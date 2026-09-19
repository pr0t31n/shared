#!/usr/bin/env python3
"""pr0t31n_userenum — organisation username and email enumeration.

Discovers employee names and email addresses for a target organisation via
multiple sources (Hunter.io, Dehashed, search engine dorking, LinkedIn public
pages, website team/about page scraping), detects the organisation's email
format from harvested addresses, and generates probable usernames/emails for
every discovered employee.

Works with or without API keys — API sources provide higher-quality data but
the script degrades gracefully to free methods (dorking, site scraping,
LinkedIn public pages) when no keys are available.

API key discovery order (per key):
  1. CLI arg (--hunter-key, --dehashed-key, etc.)
  2. Environment variable (HUNTER_API_KEY, DEHASHED_KEY, etc.)
  3. OSift settings file (/opt/pr0t31n/OSift/osift_settings.json)

Standalone CLI:
    python3 pr0t31n_userenum.py --domain target.com --org "Acme Corp"
    python3 pr0t31n_userenum.py --domain target.com --url https://target.com -o users.txt

Library:
    import pr0t31n_userenum as ue
    result = ue.enumerate_users("target.com", org_name="Acme Corp")
    # result.emails, result.usernames, result.employees, result.format_pattern
"""

VERSION = "1.0.0"

import json
import os
import re
import sys
import time
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser as _HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Optional deps ────────────────────────────────────────────────────────────

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup as _BS
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


# ── Settings file path ──────────────────────────────────────────────────────

_OSIFT_SETTINGS = Path("/opt/pr0t31n/OSift/osift_settings.json")

_BOGUS_DOMAINS = frozenset({
    "example.com", "exemple.com", "example.org", "example.net",
    "localhost", "sentry.io", "openssh.com", "test.com",
})

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# ── Email format patterns ────────────────────────────────────────────────────

_FORMAT_PATTERNS = [
    ("first.last",   "{first}.{last}@{domain}"),
    ("firstlast",    "{first}{last}@{domain}"),
    ("flast",        "{f}{last}@{domain}"),
    ("first_last",   "{first}_{last}@{domain}"),
    ("first",        "{first}@{domain}"),
    ("last.first",   "{last}.{first}@{domain}"),
    ("lastfirst",    "{last}{first}@{domain}"),
    ("lfirst",       "{l}{first}@{domain}"),
    ("last_first",   "{last}_{first}@{domain}"),
    ("last",         "{last}@{domain}"),
    ("firstl",       "{first}{l}@{domain}"),
    ("first-last",   "{first}-{last}@{domain}"),
]


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class Employee:
    first_name: str = ""
    last_name: str = ""
    email: str = ""
    title: str = ""
    department: str = ""
    linkedin: str = ""
    source: str = ""

    @property
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()


@dataclass
class EnumResult:
    domain: str = ""
    org_name: str = ""
    emails: Dict[str, dict] = field(default_factory=dict)
    employees: List[Employee] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    format_pattern: str = ""
    format_confidence: float = 0.0
    breach_emails: List[str] = field(default_factory=list)
    sources_used: List[str] = field(default_factory=list)

    @property
    def email_list(self) -> List[str]:
        return sorted(self.emails.keys())

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "org_name": self.org_name,
            "format_pattern": self.format_pattern,
            "format_confidence": self.format_confidence,
            "sources_used": self.sources_used,
            "email_count": len(self.emails),
            "employee_count": len(self.employees),
            "username_count": len(self.usernames),
            "breach_email_count": len(self.breach_emails),
            "emails": self.email_list,
            "usernames": self.usernames,
            "employees": [
                {"name": e.name, "email": e.email, "title": e.title,
                 "department": e.department, "source": e.source}
                for e in self.employees
            ],
            "breach_emails": self.breach_emails,
        }


# ── API key loading ──────────────────────────────────────────────────────────

def _load_osift_key(section: str, key: str) -> str:
    """Load a key from OSift settings JSON."""
    try:
        if _OSIFT_SETTINGS.exists():
            data = json.loads(_OSIFT_SETTINGS.read_text())
            return str(data.get(section, {}).get(key, "")).strip()
    except Exception:
        pass
    return ""


def _resolve_key(cli_val: str, env_var: str,
                 osift_section: str, osift_key: str) -> str:
    """Resolve an API key from CLI > env > OSift settings."""
    if cli_val:
        return cli_val.strip()
    env = os.environ.get(env_var, "").strip()
    if env:
        return env
    return _load_osift_key(osift_section, osift_key)


# ── HTTP session helper ──────────────────────────────────────────────────────

def _make_session():
    if not _HAS_REQUESTS:
        return None
    s = _requests.Session()
    s.headers["User-Agent"] = "pr0t31n-userenum/1.0 (+assessment)"
    s.verify = False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s


# ── Team page HTML parser ───────────────────────────────────────────────────

class _TeamPageParser(_HTMLParser):
    """Extract names from team/about/staff pages."""

    _SKIP_TAGS = frozenset({"script", "style", "noscript", "svg", "head"})
    _NAME_CLASSES = re.compile(
        r"name|person|team|staff|employee|member|author|bio|leadership|"
        r"executive|founder|director|profile|card",
        re.I,
    )
    _TEAM_URLS = re.compile(
        r"/(?:about|team|staff|people|leadership|our-team|company|who-we-are|"
        r"management|executives|founders|board|directory)",
        re.I,
    )

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self._base = base_url
        self._base_parsed = urllib.parse.urlparse(base_url)
        self.names: List[str] = []
        self.emails: Set[str] = set()
        self.team_links: Set[str] = set()
        self._in_name_tag = False
        self._name_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP_TAGS:
            self._skip += 1
            return
        amap = dict(attrs)
        cls = amap.get("class", "")
        if self._NAME_CLASSES.search(cls) and tag in ("h1","h2","h3","h4","h5","span","p","div","a","li"):
            self._in_name_tag = True
            self._name_depth = 0
        if self._in_name_tag:
            self._name_depth += 1
        href = amap.get("href", "")
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
            if href.startswith("mailto:"):
                email = href[7:].split("?")[0].strip().lower()
                if _EMAIL_RE.match(email):
                    self.emails.add(email)
            else:
                abs_url = urllib.parse.urljoin(self._base, href)
                p = urllib.parse.urlparse(abs_url)
                if p.netloc == self._base_parsed.netloc and self._TEAM_URLS.search(p.path):
                    self.team_links.add(urllib.parse.urlunparse(
                        (p.scheme, p.netloc, p.path, "", "", "")))
        # mailto: in href
        if href.startswith("mailto:"):
            email = href[7:].split("?")[0].strip().lower()
            if _EMAIL_RE.match(email):
                self.emails.add(email)

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
        if self._in_name_tag:
            self._name_depth -= 1
            if self._name_depth <= 0:
                self._in_name_tag = False

    def handle_data(self, data):
        if self._skip > 0:
            return
        text = data.strip()
        if not text:
            return
        # Extract emails from text
        for email in _EMAIL_RE.findall(text):
            self.emails.add(email.lower())
        # Extract names from name-classed elements
        if self._in_name_tag and 3 < len(text) < 60:
            if " " in text and not any(c.isdigit() for c in text):
                words = text.split()
                if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
                    self.names.append(text)


# ── Collectors ───────────────────────────────────────────────────────────────

def _collect_hunter(domain: str, hunter_key: str, log_fn) -> Tuple[List[dict], List[Employee]]:
    """Query Hunter.io domain search API."""
    if not hunter_key or not _HAS_REQUESTS:
        return [], []

    log_fn("[Hunter.io] Querying domain search API")
    session = _make_session()
    all_emails = []
    employees = []
    offset = 0

    while offset < 500:
        try:
            resp = session.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "limit": 100, "offset": offset,
                        "api_key": hunter_key},
                timeout=25,
            )
            if resp.status_code == 401:
                log_fn("[Hunter.io] API key rejected (401)")
                return all_emails, employees
            if resp.status_code == 429:
                log_fn("[Hunter.io] Rate limited — pausing 10s")
                time.sleep(10)
                continue
            if resp.status_code != 200:
                break
            data = resp.json().get("data", {})
            entries = data.get("emails", [])
            if not entries:
                break
            for e in entries:
                email = e.get("value", "").lower().strip()
                if not email:
                    continue
                all_emails.append({
                    "email": email,
                    "type": e.get("type", ""),
                    "confidence": e.get("confidence"),
                    "verified": (e.get("verification") or {}).get("status"),
                })
                if e.get("first_name") or e.get("last_name"):
                    employees.append(Employee(
                        first_name=e.get("first_name", ""),
                        last_name=e.get("last_name", ""),
                        email=email,
                        title=e.get("position", ""),
                        department=e.get("department", ""),
                        linkedin=e.get("linkedin", ""),
                        source="hunter_io",
                    ))
            total = data.get("meta", {}).get("results", 0) or len(entries)
            offset += 100
            if offset >= total:
                break
            time.sleep(2)
        except Exception as exc:
            log_fn(f"[Hunter.io] Error: {exc}")
            break

    log_fn(f"[Hunter.io] Found {len(all_emails)} email(s), {len(employees)} employee(s)")
    return all_emails, employees


def _collect_dehashed(domain: str, dh_user: str, dh_key: str,
                      log_fn) -> List[str]:
    """Query Dehashed API for breach emails."""
    if not dh_user or not dh_key or not _HAS_REQUESTS:
        return []

    log_fn("[Dehashed] Querying breach database")
    session = _make_session()
    session.auth = (dh_user, dh_key)
    found = []

    for field_name, value in [("domain", domain), ("email", f"@{domain}")]:
        try:
            resp = session.get(
                "https://api.dehashed.com/search",
                params={"query": f"{field_name}:{value}", "size": 100},
                timeout=20,
            )
            if resp.status_code == 200:
                for entry in (resp.json().get("entries") or []):
                    email = (entry.get("email") or "").lower().strip()
                    if email and f"@{domain}" in email:
                        found.append(email)
            elif resp.status_code == 401:
                log_fn("[Dehashed] Authentication failed (401)")
                return found
        except Exception as exc:
            log_fn(f"[Dehashed] Error: {exc}")

    found = list(set(found))
    log_fn(f"[Dehashed] Found {len(found)} breach email(s)")
    return found


def _collect_dork_emails(domain: str, log_fn) -> List[str]:
    """Harvest emails via DuckDuckGo dorking."""
    if not _HAS_REQUESTS:
        # Fall back to urllib
        return _collect_dork_emails_urllib(domain, log_fn)

    log_fn("[Dorking] Search engine email harvesting")
    session = _make_session()
    queries = [
        f'site:{domain} email OR contact',
        f'"@{domain}"',
        f'"{domain}" employees email',
        f'intext:"@{domain}" -site:{domain}',
    ]
    found: Set[str] = set()
    domain_re = re.compile(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain))

    for query in queries:
        try:
            resp = session.get("https://html.duckduckgo.com/html/",
                               params={"q": query}, timeout=15)
            if resp.status_code == 200:
                for email in domain_re.findall(resp.text):
                    found.add(email.lower())
            time.sleep(2)
        except Exception as exc:
            log_fn(f"[Dorking] Query failed: {exc}")

    log_fn(f"[Dorking] Found {len(found)} email(s)")
    return list(found)


def _collect_dork_emails_urllib(domain: str, log_fn) -> List[str]:
    """Fallback dorking via urllib when requests is unavailable."""
    log_fn("[Dorking] Search engine email harvesting (urllib)")
    queries = [
        f'site:{domain} email OR contact',
        f'"@{domain}"',
    ]
    found: Set[str] = set()
    domain_re = re.compile(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain))

    for query in queries:
        try:
            url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
            req = urllib.request.Request(url, headers={
                "User-Agent": "pr0t31n-userenum/1.0 (+assessment)"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                for email in domain_re.findall(body):
                    found.add(email.lower())
            time.sleep(2)
        except Exception as exc:
            log_fn(f"[Dorking] Query failed: {exc}")

    log_fn(f"[Dorking] Found {len(found)} email(s)")
    return list(found)


def _collect_linkedin(company: str, log_fn) -> List[Employee]:
    """Scrape LinkedIn public company page for employee names."""
    if not _HAS_REQUESTS or not _HAS_BS4 or not company:
        return []

    log_fn("[LinkedIn] Scraping public company page")
    slug = re.sub(r"[^a-z0-9-]", "", company.lower().replace(" ", "-"))
    employees = []

    try:
        session = _make_session()
        resp = session.get(f"https://www.linkedin.com/company/{slug}/",
                           timeout=10)
        if resp.status_code == 200:
            soup = _BS(resp.text, "html.parser")
            for tag in soup.find_all(
                ["h3", "h4", "span", "p", "a"],
                class_=re.compile(r"name|person|employee|member|profile", re.I),
            ):
                name = tag.get_text(strip=True)
                if 3 < len(name) < 60 and " " in name:
                    parts = name.split()
                    if all(p[0].isupper() for p in parts if p):
                        employees.append(Employee(
                            first_name=parts[0],
                            last_name=parts[-1],
                            source="linkedin_public",
                        ))
    except Exception as exc:
        log_fn(f"[LinkedIn] Error: {exc}")

    log_fn(f"[LinkedIn] Found {len(employees)} employee name(s)")
    return employees


def _collect_website_names(url: str, log_fn) -> Tuple[List[Employee], List[str]]:
    """Scrape target website for employee names and email addresses.

    Crawls the target site looking for team/about/staff pages, then extracts
    names from elements with person/team CSS classes and emails from mailto:
    links and text content.
    """
    if not url:
        return [], []

    log_fn(f"[WebScrape] Crawling {url} for team/staff pages")
    visited: Set[str] = set()
    queue = [(url.rstrip("/"), 0)]
    all_names: List[str] = []
    all_emails: Set[str] = set()
    team_pages_found = 0

    while queue and len(visited) < 30:
        cur, depth = queue.pop(0)
        if cur in visited:
            continue
        visited.add(cur)

        try:
            req = urllib.request.Request(cur, headers={
                "User-Agent": "pr0t31n-userenum/1.0 (+assessment)"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct:
                    continue
                body = resp.read(2_000_000).decode("utf-8", errors="replace")
        except Exception:
            continue

        parser = _TeamPageParser(cur)
        try:
            parser.feed(body)
        except Exception:
            pass

        all_names.extend(parser.names)
        all_emails.update(parser.emails)

        if depth < 2:
            for link in parser.team_links:
                if link not in visited:
                    queue.append((link, depth + 1))
                    team_pages_found += 1

    employees = []
    seen_names: Set[str] = set()
    for name in all_names:
        nkey = name.lower().strip()
        if nkey not in seen_names:
            seen_names.add(nkey)
            parts = name.split()
            employees.append(Employee(
                first_name=parts[0],
                last_name=parts[-1] if len(parts) > 1 else "",
                source="website",
            ))

    log_fn(f"[WebScrape] Found {len(employees)} name(s), {len(all_emails)} email(s) "
           f"({team_pages_found} team page(s) discovered)")
    return employees, list(all_emails)


# ── Format detection ─────────────────────────────────────────────────────────

def _detect_email_format(emails: Dict[str, dict], employees: List[Employee],
                         domain: str) -> Tuple[str, float]:
    """Detect the email naming pattern from harvested emails + known employees.

    Tries each format pattern against employees whose email we already know.
    The pattern with the most matches wins.
    """
    domain_emails = {e for e in emails if e.endswith(f"@{domain}")}
    if not domain_emails or not employees:
        return "", 0.0

    named = [(emp, emp.email) for emp in employees
             if emp.first_name and emp.last_name and emp.email
             and emp.email in domain_emails]
    if len(named) < 2:
        # Not enough data for reliable detection — try heuristic
        return _heuristic_format(domain_emails, domain), 0.3

    scores: Counter = Counter()
    for pattern_name, pattern_fmt in _FORMAT_PATTERNS:
        for emp, email in named:
            try:
                generated = pattern_fmt.format(
                    first=emp.first_name.lower(),
                    last=emp.last_name.lower(),
                    f=emp.first_name[0].lower() if emp.first_name else "",
                    l=emp.last_name[0].lower() if emp.last_name else "",
                    domain=domain,
                )
                if generated == email:
                    scores[pattern_name] += 1
            except (IndexError, KeyError):
                pass

    if not scores:
        return _heuristic_format(domain_emails, domain), 0.3

    best, count = scores.most_common(1)[0]
    confidence = count / len(named)
    return best, round(confidence, 2)


def _heuristic_format(emails: Set[str], domain: str) -> str:
    """Guess format from email local parts when we don't have employee names."""
    dot_count = 0
    underscore_count = 0
    short_count = 0

    for email in emails:
        local = email.split("@")[0]
        if "." in local:
            dot_count += 1
        elif "_" in local:
            underscore_count += 1
        elif len(local) <= 6:
            short_count += 1

    total = len(emails)
    if not total:
        return "first.last"

    if dot_count / total > 0.4:
        return "first.last"
    if underscore_count / total > 0.3:
        return "first_last"
    if short_count / total > 0.4:
        return "flast"
    return "first.last"


# ── Username/email generation ────────────────────────────────────────────────

def _generate_emails(employees: List[Employee], domain: str,
                     pattern: str) -> List[str]:
    """Generate probable emails for employees using the detected pattern."""
    fmt = None
    for pname, pfmt in _FORMAT_PATTERNS:
        if pname == pattern:
            fmt = pfmt
            break
    if not fmt:
        fmt = "{first}.{last}@{domain}"

    generated = []
    seen: Set[str] = set()

    for emp in employees:
        if not emp.first_name or not emp.last_name:
            continue
        try:
            email = fmt.format(
                first=emp.first_name.lower(),
                last=emp.last_name.lower(),
                f=emp.first_name[0].lower(),
                l=emp.last_name[0].lower(),
                domain=domain,
            )
            if email not in seen:
                seen.add(email)
                generated.append(email)
        except (IndexError, KeyError):
            pass

    return generated


def _generate_usernames(employees: List[Employee],
                        emails: Dict[str, dict]) -> List[str]:
    """Generate usernames from emails and employee names."""
    seen: Set[str] = set()
    usernames = []

    def _add(u: str):
        u = re.sub(r"[^a-z0-9._\-]", "", u.lower().strip())
        if 2 <= len(u) <= 64 and u not in seen:
            seen.add(u)
            usernames.append(u)

    for email in emails:
        local = email.split("@")[0]
        _add(local)
        _add(local.replace(".", "").replace("_", "").replace("-", ""))

    for emp in employees:
        if not emp.first_name:
            continue
        first = emp.first_name.lower()
        last = emp.last_name.lower() if emp.last_name else ""
        _add(first)
        if last:
            _add(f"{first}.{last}")
            _add(f"{first}{last}")
            _add(f"{first}_{last}")
            _add(f"{first[0]}{last}")
            _add(f"{last}.{first}")
            _add(f"{last}{first}")
            _add(f"{last}_{first}")
            _add(last)

    return usernames


# ── Main entry point ─────────────────────────────────────────────────────────

def enumerate_users(domain: str,
                    org_name: str = "",
                    url: str = "",
                    hunter_key: str = "",
                    dehashed_user: str = "",
                    dehashed_key: str = "",
                    log_fn=None) -> EnumResult:
    """Enumerate usernames and emails for an organisation.

    Args:
        domain:        Target domain (e.g. "acme.com").
        org_name:      Organisation name (e.g. "Acme Corp") — used for
                       LinkedIn lookup and website team page discovery.
        url:           Target website URL for team/staff page scraping.
        hunter_key:    Hunter.io API key (falls back to env/OSift settings).
        dehashed_user: Dehashed account email (falls back to env/OSift settings).
        dehashed_key:  Dehashed API key (falls back to env/OSift settings).
        log_fn:        Logging function (default: print).

    Returns:
        EnumResult with discovered emails, employees, usernames, and
        detected email format pattern.
    """
    _log = log_fn or (lambda m: print(m))
    result = EnumResult(domain=domain, org_name=org_name)

    # Resolve API keys
    hk = _resolve_key(hunter_key, "HUNTER_API_KEY",
                      "api_tier3_email_people", "hunter_key")
    du = _resolve_key(dehashed_user, "DEHASHED_USER",
                      "breach_intelligence", "dehashed_user")
    dk = _resolve_key(dehashed_key, "DEHASHED_KEY",
                      "breach_intelligence", "dehashed_key")

    _log(f"=== pr0t31n_userenum v{VERSION} — {domain} ===")
    _log(f"  API keys: Hunter.io={'YES' if hk else 'NO'}  "
         f"Dehashed={'YES' if du and dk else 'NO'}")

    # ── Stage 1: Harvest known emails ────────────────────────────────────
    _log("\n── Stage 1: Harvesting known emails ──")

    # Hunter.io (authenticated)
    if hk:
        hunter_emails, hunter_employees = _collect_hunter(domain, hk, _log)
        for he in hunter_emails:
            result.emails[he["email"]] = {
                "source": "hunter_io", "type": he.get("type"),
                "confidence": he.get("confidence"),
                "verified": he.get("verified"),
            }
        for emp in hunter_employees:
            if not any(e.first_name == emp.first_name and e.last_name == emp.last_name
                       for e in result.employees):
                result.employees.append(emp)
        result.sources_used.append("hunter_io")

    # Dehashed (authenticated)
    if du and dk:
        breach_emails = _collect_dehashed(domain, du, dk, _log)
        for be in breach_emails:
            if be not in result.emails:
                result.emails[be] = {"source": "dehashed"}
            result.breach_emails.append(be)
        result.sources_used.append("dehashed")

    # DuckDuckGo dorking (no auth needed)
    dork_emails = _collect_dork_emails(domain, _log)
    for de in dork_emails:
        if de not in result.emails:
            result.emails[de] = {"source": "dork"}
    if dork_emails:
        result.sources_used.append("dork")

    # ── Stage 2: Discover employee names ─────────────────────────────────
    _log("\n── Stage 2: Discovering employee names ──")

    # LinkedIn public page
    if org_name:
        li_employees = _collect_linkedin(org_name, _log)
        for emp in li_employees:
            if not any(e.first_name == emp.first_name and e.last_name == emp.last_name
                       for e in result.employees):
                result.employees.append(emp)
        if li_employees:
            result.sources_used.append("linkedin")

    # Website team/about page scraping
    site_url = url or f"https://{domain}"
    web_employees, web_emails = _collect_website_names(site_url, _log)
    for emp in web_employees:
        if not any(e.first_name == emp.first_name and e.last_name == emp.last_name
                   for e in result.employees):
            result.employees.append(emp)
    for we in web_emails:
        we = we.lower()
        _, edom = we.rsplit("@", 1) if "@" in we else ("", "")
        if edom in _BOGUS_DOMAINS:
            continue
        if we not in result.emails:
            result.emails[we] = {"source": "website"}
    if web_employees or web_emails:
        result.sources_used.append("website")

    # ── Stage 3: Detect email format ─────────────────────────────────────
    _log("\n── Stage 3: Detecting email format ──")

    fmt, conf = _detect_email_format(result.emails, result.employees, domain)
    result.format_pattern = fmt or "first.last"
    result.format_confidence = conf
    _log(f"  Detected format: {result.format_pattern} "
         f"(confidence: {result.format_confidence:.0%})")

    # ── Stage 4: Generate emails for all employees ───────────────────────
    _log("\n── Stage 4: Generating probable emails ──")

    generated = _generate_emails(result.employees, domain, result.format_pattern)
    new_count = 0
    for ge in generated:
        if ge not in result.emails:
            result.emails[ge] = {"source": "generated", "pattern": result.format_pattern}
            new_count += 1
    _log(f"  Generated {new_count} new email(s) from {len(result.employees)} employee(s)")

    # Also generate with all format patterns for broader coverage
    all_pattern_emails = set()
    for emp in result.employees:
        if not emp.first_name or not emp.last_name:
            continue
        for pname, pfmt in _FORMAT_PATTERNS:
            try:
                email = pfmt.format(
                    first=emp.first_name.lower(),
                    last=emp.last_name.lower(),
                    f=emp.first_name[0].lower(),
                    l=emp.last_name[0].lower(),
                    domain=domain,
                )
                all_pattern_emails.add(email)
            except (IndexError, KeyError):
                pass
    for ape in all_pattern_emails:
        if ape not in result.emails:
            result.emails[ape] = {"source": "all_patterns"}

    # ── Stage 5: Generate usernames ──────────────────────────────────────
    _log("\n── Stage 5: Generating usernames ──")

    result.usernames = _generate_usernames(result.employees, result.emails)
    _log(f"  Generated {len(result.usernames)} unique username(s)")

    # ── Summary ──────────────────────────────────────────────────────────
    _log(f"\n=== Results ===")
    _log(f"  Emails:    {len(result.emails)}")
    _log(f"  Employees: {len(result.employees)}")
    _log(f"  Usernames: {len(result.usernames)}")
    _log(f"  Breached:  {len(result.breach_emails)}")
    _log(f"  Format:    {result.format_pattern} ({result.format_confidence:.0%})")
    _log(f"  Sources:   {', '.join(result.sources_used)}")

    return result


# ── File output ──────────────────────────────────────────────────────────────

def write_results(result: EnumResult, output_dir: str = None,
                  emails_file: str = None, usernames_file: str = None,
                  json_file: str = None) -> dict:
    """Write enumeration results to files.

    Returns dict of {type: path} for files written.
    """
    written = {}

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        emails_file = emails_file or str(out / "emails.txt")
        usernames_file = usernames_file or str(out / "usernames.txt")
        json_file = json_file or str(out / "enum_results.json")

    if emails_file:
        Path(emails_file).write_text(
            "\n".join(sorted(result.emails.keys())) + "\n", encoding="utf-8")
        written["emails"] = emails_file

    if usernames_file:
        Path(usernames_file).write_text(
            "\n".join(result.usernames) + "\n", encoding="utf-8")
        written["usernames"] = usernames_file

    if json_file:
        Path(json_file).write_text(
            json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
        written["json"] = json_file

    return written


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="pr0t31n_userenum — organisation username and email enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --domain target.com --org "Acme Corp"
  %(prog)s --domain target.com --url https://target.com -o results/
  %(prog)s --domain target.com --emails-only
  %(prog)s --domain target.com --usernames-only
""")
    p.add_argument("--domain", "-d", required=True,
                   help="Target domain (e.g. acme.com)")
    p.add_argument("--org", help="Organisation name for LinkedIn/website lookup")
    p.add_argument("--url", help="Target website URL (default: https://<domain>)")
    p.add_argument("-o", "--output-dir", help="Output directory for all result files")
    p.add_argument("--emails-file", help="Output file for emails (one per line)")
    p.add_argument("--usernames-file", help="Output file for usernames (one per line)")
    p.add_argument("--json-file", help="Output file for full JSON results")
    p.add_argument("--emails-only", action="store_true",
                   help="Print only emails to stdout")
    p.add_argument("--usernames-only", action="store_true",
                   help="Print only usernames to stdout")
    p.add_argument("--hunter-key", default="",
                   help="Hunter.io API key (fallback: env HUNTER_API_KEY, OSift settings)")
    p.add_argument("--dehashed-user", default="",
                   help="Dehashed account email (fallback: env DEHASHED_USER, OSift settings)")
    p.add_argument("--dehashed-key", default="",
                   help="Dehashed API key (fallback: env DEHASHED_KEY, OSift settings)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args()

    result = enumerate_users(
        domain=args.domain,
        org_name=args.org or "",
        url=args.url or "",
        hunter_key=args.hunter_key,
        dehashed_user=args.dehashed_user,
        dehashed_key=args.dehashed_key,
    )

    if args.emails_only:
        for email in sorted(result.emails.keys()):
            print(email)
        return

    if args.usernames_only:
        for username in result.usernames:
            print(username)
        return

    # Write files if any output path specified
    if args.output_dir or args.emails_file or args.usernames_file or args.json_file:
        written = write_results(
            result,
            output_dir=args.output_dir,
            emails_file=args.emails_file,
            usernames_file=args.usernames_file,
            json_file=args.json_file,
        )
        for ftype, fpath in written.items():
            print(f"  {ftype}: {fpath}")
    else:
        # Default: write to temp dir
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", args.domain)
        out_dir = Path(tempfile.gettempdir()) / f"userenum_{safe_domain}_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        written = write_results(result, output_dir=str(out_dir))
        print(f"\n  Output: {out_dir}/")
        for ftype, fpath in written.items():
            print(f"    {ftype}: {fpath}")


if __name__ == "__main__":
    main()
