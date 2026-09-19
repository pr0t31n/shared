#!/usr/bin/env python3
"""pr0t31n_wordlist — website-scraping targeted wordlist builder.

Crawls a target website, extracts visible text, and generates a password-
candidate wordlist tailored to the organisation.  Extracted from Aether's
wireless wordlist builder and expanded for broader use: web app default
credential spraying, API auth brute force, rate-limit validation, and
service-level password attacks.

Standalone CLI:
    python3 pr0t31n_wordlist.py --url https://target.com --depth 2 -o wordlist.txt
    python3 pr0t31n_wordlist.py --url https://target.com --org "Acme Corp" --min 4

Library:
    import pr0t31n_wordlist as wl
    path = wl.build_website_wordlist("https://target.com", max_depth=2,
                                      org_name="Acme Corp", min_len=4)
"""

VERSION = "1.0.0"

import math
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime
from html.parser import HTMLParser as _HTMLParser
from itertools import permutations as _permutations
from pathlib import Path

# ── Stop words ───────────────────────────────────────────────────────────────

_STOP_WORDS: frozenset = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "in", "on", "at", "to",
    "for", "of", "with", "by", "from", "up", "about", "into", "through",
    "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "may", "might",
    "can", "this", "that", "these", "those", "it", "its", "we", "you", "he",
    "she", "they", "them", "their", "our", "your", "my", "his", "her", "all",
    "as", "so", "no", "not", "also", "than", "then", "when", "where", "who",
    "which", "what", "how", "why", "more", "most", "some", "any", "each",
    "both", "few", "other", "such", "very", "just", "new", "one", "two",
    "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    "get", "got", "use", "used", "using", "see", "make", "made", "go",
    "come", "back", "first", "last", "only", "same", "good", "much",
    "i", "me", "us", "www", "http", "https", "html", "css", "php",
    "com", "org", "net", "gov", "edu", "div", "span", "class", "page",
    "click", "here", "read", "view", "next", "prev", "previous",
    "home", "menu", "nav", "search", "close", "open", "submit",
    "login", "sign", "log", "out", "toggle", "show", "hide",
})

# ── Date helpers ─────────────────────────────────────────────────────────────

_MONTH_ABBRV = ("", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTH_NAMES = ("", "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December")
_MONTH_MAP = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7,
    "jul": 7, "august": 8, "aug": 8, "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
}

_SEASONS = {
    (12, 1, 2): ("Winter", "winter"),
    (3, 4, 5): ("Spring", "spring"),
    (6, 7, 8): ("Summer", "summer"),
    (9, 10, 11): ("Fall", "fall", "Autumn", "autumn"),
}

_PASSWORD_SUFFIXES = ("!", "@", "#", "$", "1", "123", "1!", "12!", "123!",
                      "1234", "12345", "!", "!!", "@1", "#1")

_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def _expand_date(year: int, month: int, day: int) -> set:
    """Return a set of password-style strings representing a calendar date."""
    yy = f"{year % 100:02d}"
    yyyy = f"{year:04d}"
    mm = f"{month:02d}"
    dd = f"{day:02d}"
    mn = _MONTH_ABBRV[month]
    mf = _MONTH_NAMES[month]
    return {
        f"{dd}{mm}{yy}", f"{dd}{mm}{yyyy}",
        f"{mm}{dd}{yy}", f"{mm}{dd}{yyyy}",
        f"{yyyy}{mm}{dd}", f"{yy}{mm}{dd}",
        f"{dd}-{mm}-{yy}", f"{dd}/{mm}/{yyyy}",
        f"{mm}-{dd}-{yy}", f"{mm}/{dd}/{yyyy}",
        f"{yyyy}-{mm}-{dd}",
        f"{mn}{dd}", f"{mn}{yy}", f"{mn}{yyyy}",
        f"{mn}{dd}{yy}", f"{mn}{dd}{yyyy}",
        f"{dd}{mn}", f"{dd}{mn}{yy}", f"{dd}{mn}{yyyy}",
        f"{mf}{dd}", f"{mf}{yyyy}", f"{mf}{dd}{yyyy}",
        yyyy, yy, dd, mm,
    }


def _detect_dates(text: str) -> list:
    """Find date patterns in text; return list of (year, month, day) tuples."""
    results = []
    for m in re.finditer(r'\b((?:19|20)\d{2})[-/](\d{1,2})[-/](\d{1,2})\b', text):
        try:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= mo <= 12 and 1 <= d <= 31:
                results.append((y, mo, d))
        except ValueError:
            pass
    for m in re.finditer(r'\b(\d{1,2})[-/](\d{1,2})[-/]((?:19|20)?\d{2})\b', text):
        try:
            mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if y < 100:
                y += 2000
            if 1 <= mo <= 12 and 1 <= d <= 31 and 1900 <= y <= 2050:
                results.append((y, mo, d))
        except ValueError:
            pass
    _mp = (r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?'
           r'|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)')
    for m in re.finditer(rf'\b({_mp})\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+((?:19|20)\d{{2}})\b',
                         text, re.IGNORECASE):
        mo = _MONTH_MAP.get(m.group(1).lower()[:3])
        if mo:
            try:
                results.append((int(m.group(3)), mo, int(m.group(2))))
            except ValueError:
                pass
    for m in re.finditer(rf'\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({_mp})\s+((?:19|20)\d{{2}})\b',
                         text, re.IGNORECASE):
        mo = _MONTH_MAP.get(m.group(2).lower()[:3])
        if mo:
            try:
                results.append((int(m.group(3)), mo, int(m.group(1))))
            except ValueError:
                pass
    return list({(y, mo, d) for y, mo, d in results if 1900 <= y <= 2050})


# ── HTML parser ──────────────────────────────────────────────────────────────

class _TextLinkParser(_HTMLParser):
    """Single-pass HTML parser that extracts visible text and same-domain hrefs."""
    _SKIP_TAGS: frozenset = frozenset({
        "script", "style", "noscript", "svg", "path", "head",
        "code", "pre", "iframe", "object", "embed",
    })

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._skip: int = 0
        self._base = base_url
        self._base_parsed = urllib.parse.urlparse(base_url)
        self.texts: list = []
        self.links: set = set()

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP_TAGS:
            self._skip += 1
        amap = dict(attrs)
        for attr in ("alt", "title", "placeholder", "aria-label",
                     "value", "content", "name"):
            if amap.get(attr):
                self.texts.append(amap[attr])
        href = amap.get("href", "")
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
            abs_url = urllib.parse.urljoin(self._base, href)
            p = urllib.parse.urlparse(abs_url)
            if (p.netloc == self._base_parsed.netloc
                    and p.scheme in ("http", "https")):
                self.links.add(urllib.parse.urlunparse(
                    (p.scheme, p.netloc, p.path, "", "", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data: str) -> None:
        if self._skip == 0 and data.strip():
            self.texts.append(data)


# ── Scraper ──────────────────────────────────────────────────────────────────

def scrape_site(url: str, max_depth: int = 2, max_pages: int = 80,
                user_agent: str = "pr0t31n-wordlist/1.0 (+assessment)",
                log_fn=None) -> tuple:
    """Crawl url up to max_depth levels within the same domain.

    Returns (word_counts: Counter, dates: list[tuple], raw_text: str).
    """
    _log = log_fn or (lambda m: print(m))
    visited: set = set()
    queue: list = [(url.rstrip("/"), 0)]
    all_texts: list = []

    while queue and len(visited) < max_pages:
        cur, depth = queue.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        _log(f"  [scrape] {cur} (depth {depth})")
        try:
            req = urllib.request.Request(cur, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req, timeout=12) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct:
                    continue
                body = resp.read(2_000_000).decode("utf-8", errors="replace")
        except Exception as exc:
            _log(f"  [scrape] {cur}: {exc}")
            continue

        parser = _TextLinkParser(cur)
        try:
            parser.feed(body)
        except Exception:
            pass
        all_texts.extend(parser.texts)

        if depth < max_depth:
            for link in parser.links:
                if link not in visited:
                    queue.append((link, depth + 1))

    _log(f"  [scrape] Crawled {len(visited)} page(s)")
    joined = " ".join(all_texts)

    word_counts: Counter = Counter()
    for raw in re.findall(r"[a-zA-Z][a-zA-Z0-9]{1,}", joined):
        w = raw.lower()
        if len(w) >= 3 and w not in _STOP_WORDS:
            word_counts[w] += 1

    dates = _detect_dates(joined)
    return word_counts, dates, joined


# ── Org-name mutations ───────────────────────────────────────────────────────

def _org_mutations(org_name: str) -> list:
    """Generate password candidates from an organisation name."""
    if not org_name:
        return []
    parts = re.findall(r"[a-zA-Z0-9]+", org_name)
    if not parts:
        return []

    candidates = []
    full_lower = "".join(p.lower() for p in parts)
    full_cap = "".join(p.capitalize() for p in parts)
    full_upper = "".join(p.upper() for p in parts)
    initials = "".join(p[0] for p in parts if p)
    initials_upper = initials.upper()
    initials_lower = initials.lower()

    bases = [full_lower, full_cap, full_upper]
    if len(parts) > 1:
        bases.extend([
            "-".join(p.lower() for p in parts),
            "_".join(p.lower() for p in parts),
            ".".join(p.lower() for p in parts),
            "-".join(p.capitalize() for p in parts),
        ])
    for p in parts:
        if len(p) >= 3:
            bases.extend([p.lower(), p.capitalize(), p.upper()])

    now = datetime.now()
    cur_year = now.year
    cur_month = now.month
    years = [str(y) for y in range(cur_year - 3, cur_year + 2)]
    short_years = [str(y % 100) for y in range(cur_year - 3, cur_year + 2)]

    seasons = []
    for months, names in _SEASONS.items():
        if cur_month in months or (cur_month - 1) % 12 + 1 in months:
            seasons.extend(names)
    if not seasons:
        seasons = ["Spring", "spring", "Summer", "summer",
                    "Fall", "fall", "Winter", "winter"]

    for base in bases:
        candidates.append(base)
        for sfx in _PASSWORD_SUFFIXES:
            candidates.append(base + sfx)
        for y in years:
            candidates.append(base + y)
            candidates.append(base + y + "!")
            candidates.append(base + y + "@")
        for y in short_years:
            candidates.append(base + y)
            candidates.append(base + y + "!")
        for s in seasons:
            candidates.append(base + s)
            candidates.append(s + base)
            for y in years:
                candidates.append(base + s + y)
                candidates.append(s + base + y)
                candidates.append(base + s + y + "!")

    for inits in (initials_upper, initials_lower):
        if len(inits) >= 2:
            candidates.append(inits)
            for y in years:
                candidates.append(inits + y)
                candidates.append(inits + y + "!")
            for sfx in _PASSWORD_SUFFIXES:
                candidates.append(inits + sfx)

    return candidates


# ── Leet-speak ───────────────────────────────────────────────────────────────

def _leet(word: str) -> str:
    """Simple leet-speak transform: a→4, e→3, i→1, o→0, s→5, t→7."""
    return "".join(_LEET_MAP.get(c, c) for c in word.lower())


# ── Default credential patterns ──────────────────────────────────────────────

_DEFAULT_CREDS = [
    "admin", "administrator", "Admin", "Administrator", "ADMIN",
    "password", "Password", "PASSWORD", "P@ssword", "P@ssw0rd",
    "p@ssword", "p@ssw0rd", "Passw0rd", "passw0rd",
    "root", "Root", "toor",
    "test", "Test", "test123", "Test123", "testing",
    "guest", "Guest", "default", "Default",
    "changeme", "Changeme", "Ch@ngeme", "letmein", "Letmein",
    "welcome", "Welcome", "W3lcome", "Welcome1", "welcome1",
    "qwerty", "Qwerty", "qwerty123",
    "abc123", "Abc123", "ABC123",
    "monkey", "master", "dragon", "shadow", "sunshine",
    "trustno1", "iloveyou",
    "pass", "pass123", "Pass123",
    "temp", "Temp", "temp123", "Temp123",
    "secret", "Secret",
    "user", "User", "user123",
    "demo", "Demo", "demo123",
]

_DEFAULT_COMBOS = [
    "admin:admin", "admin:password", "admin:Password1",
    "admin:changeme", "admin:123456", "admin:admin123",
    "root:root", "root:toor", "root:password",
    "test:test", "test:test123", "test:password",
    "guest:guest", "user:user", "user:password",
    "demo:demo", "operator:operator",
]


# ── Main builder ─────────────────────────────────────────────────────────────

def build_website_wordlist(url: str, max_depth: int = 2,
                           base_wordlist: str = None,
                           output: str = None,
                           org_name: str = None,
                           min_len: int = 1,
                           max_len: int = 63,
                           include_defaults: bool = True,
                           include_leet: bool = True,
                           top_words: int = 100,
                           top_combos: int = 30,
                           max_pages: int = 80,
                           log_fn=None) -> str | None:
    """Crawl a website and build a password-candidate wordlist from its content.

    Args:
        url:              Target URL to scrape.
        max_depth:        Maximum crawl depth (1-7).
        base_wordlist:    Path to an existing wordlist to merge.
        output:           Output file path (auto-generated if None).
        org_name:         Organisation name for targeted mutations.
        min_len:          Minimum candidate length (default 1 for short defaults).
        max_len:          Maximum candidate length (default 63).
        include_defaults: Include common default credential patterns.
        include_leet:     Include leet-speak mutations of high-value words.
        top_words:        How many top words to use for pairwise combos.
        top_combos:       How many top words for 3-word permutations.
        max_pages:        Max pages to crawl.
        log_fn:           Logging function (default: print).

    Returns:
        Path to the generated wordlist file, or None on failure.
    """
    _log = log_fn or (lambda m: print(m))

    if not url:
        return base_wordlist

    _log(f"Website wordlist: scraping {url} (max depth {max_depth})…")
    try:
        word_counts, dates, raw_text = scrape_site(
            url, max(1, min(7, max_depth)), max_pages, log_fn=_log)
    except Exception as exc:
        _log(f"Website scrape error: {exc}")
        return base_wordlist

    if not word_counts and not org_name:
        _log("  [scrape] No usable words extracted")
        return base_wordlist

    _log(f"  [scrape] {len(word_counts)} unique words, {len(dates)} date(s)")

    seen: set = set()
    candidates: list = []

    def _add(w: str) -> None:
        if w and w not in seen and min_len <= len(w) <= max_len:
            seen.add(w)
            candidates.append(w)

    # Rank words by frequency * sqrt(length)
    def _score(w: str) -> tuple:
        return (word_counts[w] * math.sqrt(len(w)),
                word_counts[w], len(w), w)
    word_list = sorted(word_counts.keys(), key=_score, reverse=True)

    # ── Default credentials ──────────────────────────────────────────────
    if include_defaults:
        for dc in _DEFAULT_CREDS:
            _add(dc)

    # ── Org-name mutations ───────────────────────────────────────────────
    if org_name:
        _log(f"  [org] Generating mutations for '{org_name}'")
        for om in _org_mutations(org_name):
            _add(om)

    # Also try to detect org name from the website title / most frequent
    # multi-word phrases if not supplied
    if not org_name:
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            domain_parts = host.replace("www.", "").split(".")
            if domain_parts and len(domain_parts[0]) >= 3:
                _log(f"  [org] Auto-detected domain base: {domain_parts[0]}")
                for om in _org_mutations(domain_parts[0]):
                    _add(om)
        except Exception:
            pass

    # ── Single-word mutations ────────────────────────────────────────────
    for w in word_list:
        for v in (w, w.capitalize(), w.upper()):
            _add(v)
        for sfx in _PASSWORD_SUFFIXES:
            _add(w + sfx)
            _add(w.capitalize() + sfx)

    # ── Leet-speak for top words ─────────────────────────────────────────
    if include_leet:
        for w in word_list[:top_words]:
            lw = _leet(w)
            if lw != w:
                _add(lw)
                _add(lw.capitalize() if lw[0].isalpha() else lw)
                for sfx in ("!", "1", "123"):
                    _add(lw + sfx)

    # ── Date expansions ──────────────────────────────────────────────────
    date_strs: set = set()
    for (y, mo, d) in dates:
        date_strs.update(_expand_date(y, mo, d))
    # Also add current year and surrounding years as common password suffixes
    now = datetime.now()
    for yr in range(now.year - 3, now.year + 2):
        date_strs.add(str(yr))
        date_strs.add(f"{yr % 100:02d}")
    for ds in date_strs:
        _add(ds)
        for sfx in ("!", "@", "1", "123"):
            _add(ds + sfx)

    # ── Words + dates ────────────────────────────────────────────────────
    for w in word_list[:top_words]:
        for ds in list(date_strs)[:25]:
            _add(w + ds)
            _add(w.capitalize() + ds)
            _add(ds + w)

    # ── Words + seasons (common corporate password pattern) ──────────────
    all_seasons = ["Spring", "spring", "Summer", "summer",
                   "Fall", "fall", "Autumn", "autumn",
                   "Winter", "winter"]
    for w in word_list[:30]:
        for s in all_seasons:
            _add(w + s)
            _add(w.capitalize() + s)
            _add(s + w)
            _add(s + w.capitalize())
            for yr in range(now.year - 1, now.year + 2):
                _add(w + s + str(yr))
                _add(s + str(yr))
                _add(s + str(yr) + "!")

    # ── Pairwise permutations ────────────────────────────────────────────
    cap2 = word_list[:top_words]
    seps = ("", "-", "_", ".")
    for w1, w2 in _permutations(cap2, 2):
        for sep in seps:
            _add(w1 + sep + w2)
            _add(w1.capitalize() + sep + w2.capitalize())

    # ── 3-word permutations ──────────────────────────────────────────────
    cap3 = word_list[:top_combos]
    for w1, w2, w3 in _permutations(cap3, 3):
        _add(w1 + w2 + w3)
        _add(w1.capitalize() + w2.capitalize() + w3.capitalize())
        _add(w1 + "-" + w2 + "-" + w3)

    _log(f"  Website wordlist: {len(candidates)} candidate passwords")

    # ── Write output ─────────────────────────────────────────────────────
    try:
        if output:
            path = Path(output)
        else:
            try:
                _host = urllib.parse.urlparse(url).hostname or "site"
                _host = re.sub(r"[^a-zA-Z0-9._-]", "_", _host)
            except Exception:
                _host = "site"
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fd, fpath = tempfile.mkstemp(
                prefix=f"wordlist_{_host}_{ts}_", suffix=".txt")
            os.close(fd)
            path = Path(fpath)

        with open(path, "w", encoding="utf-8") as fh:
            for w in candidates:
                fh.write(w + "\n")
            if base_wordlist and os.path.exists(base_wordlist):
                with open(base_wordlist, encoding="utf-8", errors="replace") as bf:
                    for line in bf:
                        line = line.rstrip("\n")
                        if min_len <= len(line) <= max_len and line not in seen:
                            seen.add(line)
                            fh.write(line + "\n")

        _log(f"  Website wordlist saved → {path}  ({len(seen)} total entries)")
        return str(path)
    except Exception as exc:
        _log(f"Website wordlist write failed: {exc}")
        return base_wordlist


def get_default_combos() -> list:
    """Return list of 'user:pass' default credential pairs."""
    return list(_DEFAULT_COMBOS)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="pr0t31n_wordlist — website-scraping targeted wordlist builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --url https://target.com --depth 2 -o wordlist.txt
  %(prog)s --url https://target.com --org "Acme Corp" --min 4
  %(prog)s --url https://target.com --no-defaults --no-leet --top 50
  %(prog)s --url https://target.com --base existing_wordlist.txt
""")
    parser.add_argument("--url", required=True, help="Target URL to scrape")
    parser.add_argument("--depth", type=int, default=2,
                        help="Max crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=80,
                        help="Max pages to crawl (default: 80)")
    parser.add_argument("-o", "--output", help="Output file path (auto if omitted)")
    parser.add_argument("--org", help="Organisation name for targeted mutations")
    parser.add_argument("--min", type=int, default=1, dest="min_len",
                        help="Min password length (default: 1)")
    parser.add_argument("--max", type=int, default=63, dest="max_len",
                        help="Max password length (default: 63)")
    parser.add_argument("--base", help="Base wordlist to merge")
    parser.add_argument("--top", type=int, default=100,
                        help="Top N words for pairwise combos (default: 100)")
    parser.add_argument("--top3", type=int, default=30,
                        help="Top N words for 3-word combos (default: 30)")
    parser.add_argument("--no-defaults", action="store_true",
                        help="Skip default credential patterns")
    parser.add_argument("--no-leet", action="store_true",
                        help="Skip leet-speak mutations")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    result = build_website_wordlist(
        url=args.url,
        max_depth=args.depth,
        base_wordlist=args.base,
        output=args.output,
        org_name=args.org,
        min_len=args.min_len,
        max_len=args.max_len,
        include_defaults=not args.no_defaults,
        include_leet=not args.no_leet,
        top_words=args.top,
        top_combos=args.top3,
        max_pages=args.max_pages,
    )
    if result:
        print(f"\nWordlist: {result}")
    else:
        print("\nFailed to generate wordlist", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
