#!/usr/bin/env python3
"""pr0t31n shared threat-intelligence module.

Downloads, caches, deduplicates, and queries curated IP/URL blocklists.
Findings are classified as KNOWN_MALICIOUS or SUSPECTED so consumers can
set risk accordingly (HIGH/CRITICAL vs MEDIUM).

GeoIP country lookup via DB-IP Lite MMDB (CC BY 4.0, no account needed).

Usage (lazy-import pattern — matches _auth.py / pr0t31n_schema.py):

    import sys
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_threat_intel as _ti

    db = _ti.ThreatIntelDB()          # downloads/refreshes on first use
    hit = db.lookup_ip("203.0.113.5") # -> ThreatHit | None
    geo = db.geoip("203.0.113.5")     # -> GeoResult | None
"""
from __future__ import annotations

VERSION = "1.0.0"

import csv
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Classification ────────────────────────────────────────────────────────────

KNOWN_MALICIOUS = "known_malicious"
SUSPECTED       = "suspected"

@dataclass
class ThreatHit:
    ip: str
    classification: str          # KNOWN_MALICIOUS | SUSPECTED
    sources: list[str]           # which lists matched
    tags: list[str]              # e.g. ["c2", "botnet", "dridex"]
    confidence: str              # "high" | "moderate"
    first_seen: str = ""         # ISO timestamp if available

    @property
    def risk(self) -> str:
        if self.classification == KNOWN_MALICIOUS:
            return "HIGH"
        return "MEDIUM"

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "classification": self.classification,
            "sources": self.sources,
            "tags": self.tags,
            "confidence": self.confidence,
            "risk": self.risk,
            "first_seen": self.first_seen,
        }


@dataclass
class GeoResult:
    ip: str
    country_code: str    # ISO 3166-1 alpha-2
    country_name: str
    continent: str = ""
    asn: int = 0
    as_org: str = ""

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "continent": self.continent,
            "asn": self.asn,
            "as_org": self.as_org,
        }


# ── Feed registry ────────────────────────────────────────────────────────────
# Each entry: (name, url, classification, parser_key, tags)
# parser_key selects the line-parser in _PARSERS.

_FEEDS: list[tuple[str, str, str, str, list[str]]] = [
    # ── KNOWN MALICIOUS (confirmed C2 / hijacked / compromised) ───────────
    (
        "feodo_tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        KNOWN_MALICIOUS, "comment_hash", ["c2", "botnet"],
    ),
    (
        "sslbl",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        KNOWN_MALICIOUS, "sslbl_csv", ["c2", "ssl_malware"],
    ),
    (
        "spamhaus_drop",
        "https://www.spamhaus.org/drop/drop.txt",
        KNOWN_MALICIOUS, "spamhaus_drop", ["hijacked", "spam"],
    ),
    (
        "spamhaus_edrop",
        "https://www.spamhaus.org/drop/edrop.txt",
        KNOWN_MALICIOUS, "spamhaus_drop", ["hijacked", "spam"],
    ),
    (
        "et_compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        KNOWN_MALICIOUS, "comment_hash", ["compromised"],
    ),
    (
        "et_block",
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        KNOWN_MALICIOUS, "comment_hash", ["block"],
    ),
    # urlhaus bulk download endpoint retired (410 Gone as of 2026-10)
    # ── SUSPECTED (honeypot / scan / crowdsourced) ────────────────────────
    (
        "blocklist_de",
        "https://lists.blocklist.de/lists/all.txt",
        SUSPECTED, "plain_ip", ["attack_source"],
    ),
    (
        "cins_army",
        "https://cinsscore.com/list/ci-badguys.txt",
        SUSPECTED, "plain_ip", ["poor_reputation"],
    ),
    (
        "ipsum",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        SUSPECTED, "ipsum_scored", ["aggregated"],
    ),
]

# Minimum IPsum score to include (flagged by N+ independent lists).
IPSUM_MIN_SCORE = 3


# ── Cache paths ───────────────────────────────────────────────────────────────

def _default_cache_dir() -> Path:
    d = Path(os.environ.get("PR0T31N_THREAT_CACHE",
                            "/opt/pr0t31n/shared/.threat_cache"))
    d.mkdir(parents=True, exist_ok=True)
    return d

# Max age before re-download (seconds).  Feeds refresh every run by default
# but skip re-download if the cached file is < MAX_AGE old.
MAX_CACHE_AGE = int(os.environ.get("PR0T31N_THREAT_CACHE_AGE", "3600"))


# ── Download helpers ──────────────────────────────────────────────────────────

_UA = "pr0t31n-threat-intel/1.0"

def _download(url: str, dest: Path, timeout: int = 30) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        dest.write_bytes(data)
        return True
    except Exception as exc:
        _warn(f"download failed: {url} — {exc}")
        return False


def _is_fresh(path: Path, max_age: int = MAX_CACHE_AGE) -> bool:
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < max_age


def _warn(msg: str) -> None:
    print(f"[threat-intel] WARN: {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"[threat-intel] {msg}", file=sys.stderr)


# ── Line parsers ──────────────────────────────────────────────────────────────
# Each returns a list of (ip_or_cidr: str, extra_tags: list[str]).

def _parse_comment_hash(text: str) -> list[tuple[str, list[str]]]:
    """Lines starting with # are comments; rest are bare IPs."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split()[0] if " " in line else line
        try:
            ipaddress.ip_address(ip)
            out.append((ip, []))
        except ValueError:
            pass
    return out


def _parse_plain_ip(text: str) -> list[tuple[str, list[str]]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        ip = line.split()[0].rstrip(";,")
        try:
            ipaddress.ip_address(ip)
            out.append((ip, []))
        except ValueError:
            pass
    return out


def _parse_spamhaus_drop(text: str) -> list[tuple[str, list[str]]]:
    """Spamhaus DROP format: CIDR ; SBL-ID"""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";")[0].strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
            out.append((cidr, []))
        except ValueError:
            pass
    return out


def _parse_sslbl_csv(text: str) -> list[tuple[str, list[str]]]:
    """abuse.ch SSLBL CSV: skip comment lines, extract DstIP column."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            ip_str = parts[1].strip().strip('"')
            try:
                ipaddress.ip_address(ip_str)
                out.append((ip_str, []))
            except ValueError:
                pass
    return out


def _parse_ipsum_scored(text: str) -> list[tuple[str, list[str]]]:
    """IPsum format: IP<tab>score — only include score >= IPSUM_MIN_SCORE."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            parts = line.split()
        if len(parts) < 2:
            continue
        ip_str, score_str = parts[0], parts[1]
        try:
            score = int(score_str)
        except ValueError:
            continue
        if score < IPSUM_MIN_SCORE:
            continue
        tags = [f"ipsum_score_{score}"]
        if score >= 6:
            tags.append("high_confidence")
        try:
            ipaddress.ip_address(ip_str)
            out.append((ip_str, tags))
        except ValueError:
            pass
    return out


def _parse_urlhaus_text(text: str) -> list[tuple[str, list[str]]]:
    """URLhaus text feed — one URL per line.  We extract host IPs/domains."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append((line, ["malware_url"]))
    return out


_PARSERS = {
    "comment_hash":  _parse_comment_hash,
    "plain_ip":      _parse_plain_ip,
    "spamhaus_drop": _parse_spamhaus_drop,
    "sslbl_csv":     _parse_sslbl_csv,
    "ipsum_scored":  _parse_ipsum_scored,
    "urlhaus_text":  _parse_urlhaus_text,
}


# ── GeoIP (DB-IP Lite MMDB) ──────────────────────────────────────────────────

_DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{year}-{month:02d}.mmdb.gz"

def _geoip_mmdb_path(cache_dir: Path) -> Path:
    return cache_dir / "dbip-country-lite.mmdb"


def _download_geoip(cache_dir: Path) -> Optional[Path]:
    dest = _geoip_mmdb_path(cache_dir)
    if _is_fresh(dest, max_age=86400 * 7):
        return dest
    now = datetime.now(timezone.utc)
    url = _DBIP_URL.format(year=now.year, month=now.month)
    gz_path = cache_dir / "dbip-country-lite.mmdb.gz"
    _info(f"downloading GeoIP DB from {url}")
    if not _download(url, gz_path, timeout=60):
        if dest.exists():
            _warn("GeoIP download failed — using cached copy")
            return dest
        return None
    try:
        with gzip.open(gz_path, "rb") as f_in:
            with open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        gz_path.unlink(missing_ok=True)
        _info(f"GeoIP DB ready ({dest.stat().st_size / 1024 / 1024:.1f} MB)")
        return dest
    except Exception as exc:
        _warn(f"GeoIP decompress failed: {exc}")
        return dest if dest.exists() else None


# ── Main database class ──────────────────────────────────────────────────────

class ThreatIntelDB:
    """Download, cache, deduplicate, and query threat-intel blocklists."""

    def __init__(self, cache_dir: Path | str | None = None,
                 max_cache_age: int = MAX_CACHE_AGE,
                 skip_geoip: bool = False,
                 feeds: list | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else _default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = max_cache_age
        self._feeds = feeds or _FEEDS

        # IP -> {classification, sources, tags}
        self._ip_index: dict[str, dict] = {}
        # CIDR networks (for Spamhaus DROP etc.)
        self._cidr_nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network,
                                     str, str, list[str]]] = []
        # URL index (for URLhaus)
        self._url_index: dict[str, dict] = {}

        self._geoip_reader = None
        self._geoip_fallback: dict[str, tuple[str, str]] = {}

        self._loaded = False
        self._load(skip_geoip=skip_geoip)

    # ── Public API ────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Force re-download of all feeds."""
        self._ip_index.clear()
        self._cidr_nets.clear()
        self._url_index.clear()
        self._loaded = False
        for name, *_ in self._feeds:
            cached = self.cache_dir / f"{name}.txt"
            cached.unlink(missing_ok=True)
        self._load()

    def lookup_ip(self, ip: str) -> Optional[ThreatHit]:
        """Check if an IP appears in any blocklist."""
        if not self._loaded:
            return None
        ip = ip.strip()

        # Direct IP match
        entry = self._ip_index.get(ip)
        if entry:
            return ThreatHit(
                ip=ip,
                classification=entry["classification"],
                sources=list(entry["sources"]),
                tags=list(entry["tags"]),
                confidence="high" if entry["classification"] == KNOWN_MALICIOUS else "moderate",
            )

        # CIDR match
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, classification, source, tags in self._cidr_nets:
            if addr in net:
                return ThreatHit(
                    ip=ip,
                    classification=classification,
                    sources=[source],
                    tags=list(tags),
                    confidence="high" if classification == KNOWN_MALICIOUS else "moderate",
                )

        return None

    def lookup_url(self, url: str) -> Optional[ThreatHit]:
        """Check if a URL appears in URLhaus or similar."""
        url_lower = url.lower().rstrip("/")
        entry = self._url_index.get(url_lower)
        if entry:
            return ThreatHit(
                ip=url,
                classification=entry["classification"],
                sources=list(entry["sources"]),
                tags=list(entry["tags"]),
                confidence="high",
            )
        return None

    def geoip(self, ip: str) -> Optional[GeoResult]:
        """Return country info for an IP address."""
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None

        # Try maxmind/geoip2 reader first
        if self._geoip_reader:
            try:
                resp = self._geoip_reader.country(ip)
                return GeoResult(
                    ip=ip,
                    country_code=resp.country.iso_code or "",
                    country_name=resp.country.name or "",
                    continent=resp.continent.name or "",
                )
            except Exception:
                pass

        # Fallback CSV lookup
        if self._geoip_fallback:
            entry = self._geoip_fallback.get(ip)
            if entry:
                return GeoResult(ip=ip, country_code=entry[0],
                                 country_name=entry[1])

        return None

    def stats(self) -> dict:
        """Return summary stats about loaded data."""
        known = sum(1 for v in self._ip_index.values()
                    if v["classification"] == KNOWN_MALICIOUS)
        suspected = sum(1 for v in self._ip_index.values()
                        if v["classification"] == SUSPECTED)
        return {
            "total_ips": len(self._ip_index),
            "known_malicious": known,
            "suspected": suspected,
            "cidr_ranges": len(self._cidr_nets),
            "urls": len(self._url_index),
            "geoip_available": self._geoip_reader is not None,
            "feeds_loaded": [n for n, *_ in self._feeds],
        }

    # ── Internal ──────────────────────────────────────────────────────────

    def _load(self, skip_geoip: bool = False) -> None:
        total_before = 0
        for name, url, classification, parser_key, default_tags in self._feeds:
            cached = self.cache_dir / f"{name}.txt"
            if not _is_fresh(cached, self.max_age):
                _info(f"refreshing {name}")
                _download(url, cached)
            if not cached.exists():
                _warn(f"no data for {name} — skipped")
                continue
            try:
                text = cached.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                _warn(f"read failed for {name}: {exc}")
                continue

            parser = _PARSERS.get(parser_key)
            if not parser:
                _warn(f"unknown parser {parser_key} for {name}")
                continue

            entries = parser(text)
            count = 0
            for ip_or_val, extra_tags in entries:
                tags = default_tags + extra_tags

                # URL entries
                if parser_key == "urlhaus_text":
                    key = ip_or_val.lower().rstrip("/")
                    if key not in self._url_index:
                        self._url_index[key] = {
                            "classification": classification,
                            "sources": set(), "tags": set(),
                        }
                    self._url_index[key]["sources"].add(name)
                    self._url_index[key]["tags"].update(tags)
                    if classification == KNOWN_MALICIOUS:
                        self._url_index[key]["classification"] = KNOWN_MALICIOUS
                    count += 1
                    continue

                # CIDR entries
                if "/" in ip_or_val:
                    try:
                        net = ipaddress.ip_network(ip_or_val, strict=False)
                        self._cidr_nets.append((net, classification, name, tags))
                        count += 1
                    except ValueError:
                        pass
                    continue

                # Plain IP entries — deduplicate, promote to KNOWN if any source says so
                if ip_or_val not in self._ip_index:
                    self._ip_index[ip_or_val] = {
                        "classification": classification,
                        "sources": set(), "tags": set(),
                    }
                entry = self._ip_index[ip_or_val]
                entry["sources"].add(name)
                entry["tags"].update(tags)
                if classification == KNOWN_MALICIOUS:
                    entry["classification"] = KNOWN_MALICIOUS
                count += 1

            _info(f"  {name}: {count} entries")
            total_before += count

        # Convert sets to lists for serialisation safety
        for v in self._ip_index.values():
            v["sources"] = list(v["sources"])
            v["tags"] = list(v["tags"])
        for v in self._url_index.values():
            v["sources"] = list(v["sources"])
            v["tags"] = list(v["tags"])

        _info(f"loaded {len(self._ip_index)} unique IPs, "
              f"{len(self._cidr_nets)} CIDR ranges, "
              f"{len(self._url_index)} URLs")

        if not skip_geoip:
            self._load_geoip()
        self._loaded = True

    def _load_geoip(self) -> None:
        mmdb = _download_geoip(self.cache_dir)
        if not mmdb or not mmdb.exists():
            _warn("GeoIP database not available")
            return
        try:
            import maxminddb
            self._geoip_reader = maxminddb.open_database(str(mmdb))
            _info("GeoIP ready (maxminddb reader)")
        except ImportError:
            try:
                import geoip2.database
                self._geoip_reader = geoip2.database.Reader(str(mmdb))
                _info("GeoIP ready (geoip2 reader)")
            except ImportError:
                _warn("neither maxminddb nor geoip2 installed — GeoIP disabled. "
                       "Install with: pip3 install --break-system-packages maxminddb")


# ── Convenience for one-shot scripts ──────────────────────────────────────────

_SINGLETON: Optional[ThreatIntelDB] = None

def get_db(**kwargs) -> ThreatIntelDB:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ThreatIntelDB(**kwargs)
    return _SINGLETON


def check_ip(ip: str) -> Optional[ThreatHit]:
    return get_db().lookup_ip(ip)


def check_url(url: str) -> Optional[ThreatHit]:
    return get_db().lookup_url(url)


def country(ip: str) -> Optional[GeoResult]:
    return get_db().geoip(ip)


# ── CLI for manual testing ────────────────────────────────────────────────────

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="pr0t31n threat-intel lookup")
    ap.add_argument("--ip", action="append", default=[], help="IP to check")
    ap.add_argument("--url", action="append", default=[], help="URL to check")
    ap.add_argument("--stats", action="store_true", help="Print DB stats")
    ap.add_argument("--refresh", action="store_true", help="Force re-download")
    ap.add_argument("--cache-dir", help="Override cache directory")
    args = ap.parse_args()

    kwargs = {}
    if args.cache_dir:
        kwargs["cache_dir"] = args.cache_dir

    db = ThreatIntelDB(**kwargs)
    if args.refresh:
        db.refresh()

    if args.stats:
        print(json.dumps(db.stats(), indent=2))

    for ip in args.ip:
        hit = db.lookup_ip(ip)
        geo = db.geoip(ip)
        if hit:
            print(f"  MATCH  {ip}: {hit.classification} "
                  f"[{', '.join(hit.sources)}] tags={hit.tags} risk={hit.risk}")
        else:
            print(f"  CLEAN  {ip}: not found in any blocklist")
        if geo:
            print(f"         GeoIP: {geo.country_name} ({geo.country_code})")

    for url in args.url:
        hit = db.lookup_url(url)
        if hit:
            print(f"  MATCH  {url}: {hit.classification} [{', '.join(hit.sources)}]")
        else:
            print(f"  CLEAN  {url}: not found")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
