"""
pr0t31n_intel.py — Shared "Intelligence panel" aggregator for pr0t31n Flask apps.

Generalises Vantage's Network Intelligence pattern so every manager exposes
a uniform `/api/intel/<project_id>` endpoint returning a structured intel
payload that the UI renders in a panel.

The shape is intentionally domain-agnostic:

    {
      "context":     "...",          # human-readable label ("Web App", "Wireless")
      "headline":    [               # 3-4 big-number cards
        {"label": "Active IPs", "value": 47},
        {"label": "Unique Ports", "value": 124},
        ...
      ],
      "top_lists": [                 # 1-N ranked lists for the bottom row
        {"title": "Most Common Ports", "rows": [["443", "47 hosts"], ["22", "31 hosts"], ...]},
        {"title": "Riskiest Targets",   "rows": [{"name": "10.0.0.1", "badge": "CRITICAL"}, ...]},
        ...
      ],
      "risk_counts": {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 12, "INFO": 5},
      "updated_at":  "2026-05-22T15:30:00Z",
    }

Each manager provides a tool-specific aggregator that produces this payload
by reading the producer's findings + inventory files. The shared module
provides:
  - `build_intel_envelope(...)` — wraps an aggregator's dict in the standard envelope
  - Universal aggregator helpers: counts, top-N, risk tallies
  - Renderer (renderIntelPanel(payload)) shipped as a separate JS file

Apps that already have a custom intelligence panel (Vantage's Network Intel)
can adopt this by emitting the standard envelope from their existing
aggregator; the new shared JS renderer accepts both legacy Vantage shape
and the standardised envelope.

stdlib only.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "build_intel_envelope",
    "tally_risk_counts",
    "top_n",
    "load_universal_findings",
    "load_inventory_dir",
]

_VALID_RISK = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tally_risk_counts(findings):
    """Build a {CRITICAL: n, HIGH: n, ...} counter from a finding list."""
    counts = {r: 0 for r in _VALID_RISK}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        r = str(f.get("risk") or "INFO").upper()
        if r in counts:
            counts[r] += 1
    return counts


def top_n(items, n=10, key=None):
    """Return top-N most frequent items as [(item, count), ...]."""
    if key is None:
        c = Counter(x for x in items if x is not None and x != "")
    else:
        c = Counter()
        for it in items:
            v = key(it)
            if v is None or v == "":
                continue
            c[v] += 1
    return c.most_common(n)


def load_universal_findings(run_dir):
    """Load <run_dir>/findings.json (universal v1.1) — empty list if absent."""
    p = Path(run_dir) / "findings.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def load_inventory_dir(run_dir):
    """Load all <run_dir>/inventory/*.json files into a {stem: data} map."""
    inv = {}
    d = Path(run_dir) / "inventory"
    if not d.is_dir():
        return inv
    for f in d.glob("*.json"):
        try:
            inv[f.stem] = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            pass
    return inv


def build_intel_envelope(*, context, headline, top_lists,
                         risk_counts=None, updated_at=None,
                         extras=None):
    """Wrap aggregator output in the standard envelope."""
    return {
        "context":     context,
        "headline":    list(headline or []),
        "top_lists":   list(top_lists or []),
        "risk_counts": dict(risk_counts or {}),
        "updated_at":  updated_at or _now_iso(),
        "extras":      dict(extras or {}),
    }


# ─── Per-tool aggregator templates ──────────────────────────────────────────
# These are reference aggregators that managers can call or fork.

def aggregator_network(findings, hosts, services):
    """Network Intelligence (Vantage-style).
    Builds the envelope from finding + hosts.json + services.json data."""
    rc = tally_risk_counts(findings)
    active_ips = sorted({(h.get("ip") if isinstance(h, dict) else "") for h in hosts or []} - {""})
    services = services or []
    ports    = [s.get("port") for s in services if isinstance(s, dict) and s.get("port")]
    hostnames = sorted({h.get("hostname") for h in hosts or []
                        if isinstance(h, dict) and h.get("hostname")})
    top_ports = top_n(ports)
    top_oses  = top_n(s.get("version") for s in services
                      if isinstance(s, dict) and s.get("version"))
    # Risk per host
    by_ip = Counter()
    risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    top_risk = {}
    for f in findings or []:
        ip = f.get("ip", "")
        if not ip: continue
        r = (f.get("risk") or "INFO").upper()
        if risk_rank.get(r, 0) > risk_rank.get(top_risk.get(ip, "INFO"), 0):
            top_risk[ip] = r
    riskiest = [
        {"name": ip, "badge": top_risk[ip]}
        for ip in sorted(top_risk, key=lambda i: risk_rank.get(top_risk[i], 0), reverse=True)[:10]
    ]
    return build_intel_envelope(
        context="Network",
        headline=[
            {"label": "Active IPs",   "value": len(active_ips)},
            {"label": "Unique Ports", "value": len(set(ports))},
            {"label": "Hostnames",    "value": len(hostnames)},
        ],
        top_lists=[
            {"title": "Most Common Ports", "rows": [(str(p), f"{c} hosts") for p, c in top_ports]},
            {"title": "Top Software",      "rows": [(s, f"{c}") for s, c in top_oses]},
            {"title": "Riskiest Targets",  "rows": riskiest},
        ],
        risk_counts=rc,
    )


def aggregator_api(findings, endpoints):
    """API Intelligence (Crucible/Siphon-style)."""
    rc = tally_risk_counts(findings)
    endpoints = endpoints or []
    # Use v1.1 fields when present (api_method, api_endpoint_path, is_rogue_endpoint)
    methods = [(f.get("api_method") or "GET").upper()
               for f in findings or [] if f.get("api_endpoint_path")]
    rogue   = sum(1 for f in findings or [] if f.get("is_rogue_endpoint"))
    in_spec = sum(1 for f in findings or [] if f.get("api_from_spec"))
    owasp_api_cats = [f.get("owasp_api") for f in findings or [] if f.get("owasp_api")]
    paths = [f.get("api_endpoint_path") for f in findings or [] if f.get("api_endpoint_path")]
    return build_intel_envelope(
        context="API",
        headline=[
            {"label": "Endpoints (inventory)", "value": len(endpoints)},
            {"label": "Rogue Endpoints",       "value": rogue},
            {"label": "In Spec",               "value": in_spec},
        ],
        top_lists=[
            {"title": "HTTP Methods",      "rows": [(m, str(c)) for m, c in top_n(methods)]},
            {"title": "OWASP API Top 10",  "rows": [(o, str(c)) for o, c in top_n(owasp_api_cats)]},
            {"title": "Top Endpoint Paths","rows": [(p, str(c)) for p, c in top_n(paths)]},
        ],
        risk_counts=rc,
    )


def aggregator_wireless(findings):
    """Wireless Intelligence (Spectre/Aether-style)."""
    rc = tally_risk_counts(findings)
    ssids  = [f.get("ssid")  for f in findings or [] if f.get("ssid")]
    bssids = [f.get("bssid") for f in findings or [] if f.get("bssid")]
    encs   = []
    chans  = []
    for f in findings or []:
        wd = f.get("wireless_data") or {}
        if isinstance(wd, dict):
            if wd.get("encryption"): encs.append(wd["encryption"])
            if wd.get("channel"):    chans.append(str(wd["channel"]))
    return build_intel_envelope(
        context="Wireless",
        headline=[
            {"label": "Unique SSIDs",  "value": len(set(ssids))},
            {"label": "Unique APs",    "value": len(set(bssids))},
            {"label": "Channels",      "value": len(set(chans))},
        ],
        top_lists=[
            {"title": "Top SSIDs",       "rows": [(s, str(c)) for s, c in top_n(ssids)]},
            {"title": "Encryption Mix",  "rows": [(e, str(c)) for e, c in top_n(encs)]},
            {"title": "Channels in Use", "rows": [(c, str(n)) for c, n in top_n(chans)]},
        ],
        risk_counts=rc,
    )


def aggregator_config(findings):
    """Config-Audit Intelligence (Bastion-style)."""
    rc = tally_risk_counts(findings)
    vendors   = [(f.get("vendor") or "") for f in findings or [] if f.get("vendor")]
    files     = [(f.get("config_file") or "") for f in findings or [] if f.get("config_file")]
    rule_ids  = [(f.get("audit_rule_id") or f.get("catalogue_id") or "")
                 for f in findings or [] if (f.get("audit_rule_id") or f.get("catalogue_id"))]
    accepted  = sum(1 for f in findings or [] if f.get("accepted"))
    fw_lists = []
    for f in findings or []:
        for fk in ("nist_800_53", "pci_dss_4", "iso_27001", "soc2"):
            v = f.get(fk)
            if isinstance(v, list):
                fw_lists.extend(v)
    return build_intel_envelope(
        context="Config Audit",
        headline=[
            {"label": "Vendors Detected",  "value": len(set(vendors))},
            {"label": "Config Files",      "value": len(set(files))},
            {"label": "Accepted Findings", "value": accepted},
        ],
        top_lists=[
            {"title": "Top Vendors",     "rows": [(v, str(c)) for v, c in top_n(vendors)]},
            {"title": "Top Rules Hit",   "rows": [(r, str(c)) for r, c in top_n(rule_ids)]},
            {"title": "Framework Hits",  "rows": [(c, str(n)) for c, n in top_n(fw_lists)]},
        ],
        risk_counts=rc,
    )


# ─── Self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    findings = [
        {"id": "a", "ip": "10.0.0.1", "port": 443, "risk": "HIGH",
         "api_endpoint_path": "/v1/users", "api_method": "GET", "api_from_spec": True,
         "owasp_api": "API3:2023", "is_rogue_endpoint": False},
        {"id": "b", "ip": "10.0.0.1", "port": 22,  "risk": "LOW",
         "ssid": "GuestNet", "bssid": "AA:BB:CC:00:00:01",
         "wireless_data": {"channel": 6, "encryption": "WPA2"}},
        {"id": "c", "ip": "10.0.0.2", "port": 443, "risk": "CRITICAL",
         "is_rogue_endpoint": True, "api_endpoint_path": "/v1/admin", "api_method": "POST"},
        {"id": "d", "vendor": "Cisco", "config_file": "core.cfg",
         "audit_rule_id": "PHX-001", "risk": "MEDIUM",
         "nist_800_53": ["SI-10", "SA-11"], "accepted": True},
    ]
    hosts = [{"ip": "10.0.0.1", "hostname": "web.local"},
             {"ip": "10.0.0.2", "hostname": "db.local"}]
    services = [{"ip": "10.0.0.1", "port": 443, "service": "https", "version": "nginx 1.18"},
                {"ip": "10.0.0.1", "port": 22,  "service": "ssh",   "version": "OpenSSH 8.2"},
                {"ip": "10.0.0.2", "port": 443, "service": "https", "version": "nginx 1.18"}]
    endpoints = [{"url": "https://x/v1/users", "method": "GET"},
                 {"url": "https://x/v1/admin", "method": "POST"}]

    n = aggregator_network(findings, hosts, services)
    assert n["context"] == "Network"
    assert n["headline"][0]["value"] == 2  # 2 active IPs
    assert n["risk_counts"]["CRITICAL"] == 1
    print("aggregator_network: OK")

    a = aggregator_api(findings, endpoints)
    assert a["context"] == "API"
    assert any(h["label"] == "Rogue Endpoints" and h["value"] == 1 for h in a["headline"])
    print("aggregator_api: OK")

    w = aggregator_wireless(findings)
    assert w["context"] == "Wireless"
    assert any(h["label"] == "Unique SSIDs" and h["value"] == 1 for h in w["headline"])
    print("aggregator_wireless: OK")

    c = aggregator_config(findings)
    assert c["context"] == "Config Audit"
    assert any(h["label"] == "Accepted Findings" and h["value"] == 1 for h in c["headline"])
    print("aggregator_config: OK")

    print("pr0t31n_intel: self-test PASS")
