"""
pr0t31n_page_sig.py — Structural HTML fingerprinting and comparison.

Provides page-structure signatures that tolerate dynamic content (CSRF tokens,
timestamps, session IDs, nonces) for:
  - Differential response analysis (injection detection through WAFs)
  - Session heartbeat / auth-state verification
  - Login-profile matching

stdlib only. No third-party imports.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

try:
    __version__ = (
        Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()
    )
except Exception:
    __version__ = "0.0.0"

# ── Dynamic content patterns ─────────────────────────────────────────────────

_CSRF_FIELD_NAMES = frozenset({
    "_token", "csrf_token", "csrftoken", "_csrf", "csrf",
    "authenticity_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "__viewstate", "__viewstategenerator",
    "__eventvalidation", "__eventtarget", "__eventargument",
    "javax.faces.viewstate", "form_build_id",
    "nonce", "wp_nonce", "_wp_nonce", "_wpnonce",
})

_TIMESTAMP_RE = re.compile(
    r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    r"|\b\d{10,13}\b"  # unix epoch seconds or millis
    r"|\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\b"
)

_SESSION_PARAM_RE = re.compile(
    r"[?&;](jsessionid|phpsessid|sid|session_id|token|sess|_s|aspsessionid)"
    r"=[^&;#\s\"']+",
    re.IGNORECASE,
)

_NONCE_ATTR_RE = re.compile(
    r'\s+nonce=["\'][^"\']*["\']',
    re.IGNORECASE,
)

_RANDOM_VALUE_RE = re.compile(
    r'value=["\'][0-9a-f]{24,}["\']',
    re.IGNORECASE,
)

_LOGIN_FIELD_NAMES = frozenset({
    "username", "user", "login", "email", "user_name", "user_login",
    "log", "usr", "userid", "user_id", "j_username", "uname",
})

_PASSWORD_FIELD_NAMES = frozenset({
    "password", "pass", "passwd", "pwd", "user_password", "user_pass",
    "j_password", "loginpassword", "secret",
})

# ── HTML structure parser ────────────────────────────────────────────────────

class _StructureParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tag_tree: list[str] = []
        self.text_chunks: list[str] = []
        self.form_fields: list[tuple[str, str]] = []
        self.link_count = 0
        self.has_login_form = False
        self._in_script = False
        self._in_style = False
        self._has_username = False
        self._has_password = False
        self._current_text = []
        self._skip_csrf_value = False

    def handle_starttag(self, tag, attrs):
        tag_l = tag.lower()
        self.tag_tree.append(tag_l)

        if tag_l in ("script", "style"):
            self._in_script = tag_l == "script"
            self._in_style = tag_l == "style"
            self._flush_text()
            return

        if tag_l == "a":
            self.link_count += 1

        if tag_l in ("input", "select", "textarea", "button"):
            attr_dict = {k.lower(): v for k, v in attrs}
            name = (attr_dict.get("name") or attr_dict.get("id") or "").lower()
            itype = (attr_dict.get("type") or "text").lower()

            # skip CSRF / viewstate hidden fields from signature
            if itype == "hidden" and name in _CSRF_FIELD_NAMES:
                return

            self.form_fields.append((name, itype))

            if name in _LOGIN_FIELD_NAMES or itype == "email":
                self._has_username = True
            if name in _PASSWORD_FIELD_NAMES or itype == "password":
                self._has_password = True

    def handle_endtag(self, tag):
        tag_l = tag.lower()
        if tag_l == "script":
            self._in_script = False
        elif tag_l == "style":
            self._in_style = False
        else:
            self._flush_text()

        if tag_l == "form" and self._has_username and self._has_password:
            self.has_login_form = True

    def handle_data(self, data):
        if self._in_script or self._in_style:
            return
        stripped = data.strip()
        if stripped:
            # strip timestamps from text content
            cleaned = _TIMESTAMP_RE.sub("", stripped).strip()
            if cleaned:
                self._current_text.append(cleaned)

    def _flush_text(self):
        if self._current_text:
            block = " ".join(self._current_text)
            if len(block) > 2:
                self.text_chunks.append(block)
            self._current_text = []

    def close(self):
        self._flush_text()
        super().close()


# ── Public API ───────────────────────────────────────────────────────────────

def page_signature(html: str) -> dict:
    if not html:
        return {
            "tag_tree": [],
            "text_blocks": [],
            "form_fields": [],
            "link_count": 0,
            "has_login_form": False,
            "page_length_bucket": 0,
        }

    parser = _StructureParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass

    text_blocks = []
    for chunk in parser.text_chunks:
        h = hashlib.md5(chunk.encode("utf-8", errors="replace")).hexdigest()[:12]
        text_blocks.append(h)

    return {
        "tag_tree": parser.tag_tree,
        "text_blocks": text_blocks,
        "form_fields": parser.form_fields,
        "link_count": parser.link_count,
        "has_login_form": parser.has_login_form,
        "page_length_bucket": (len(html) + 50) // 100 * 100,
    }


def compare_signatures(sig_a: dict, sig_b: dict) -> float:
    if not sig_a and not sig_b:
        return 1.0
    if not sig_a or not sig_b:
        return 0.0

    # tag_tree similarity (40%) — longest common subsequence ratio
    tree_a = sig_a.get("tag_tree", [])
    tree_b = sig_b.get("tag_tree", [])
    tree_sim = _lcs_ratio(tree_a, tree_b)

    # text_blocks jaccard similarity (30%)
    blocks_a = set(sig_a.get("text_blocks", []))
    blocks_b = set(sig_b.get("text_blocks", []))
    if blocks_a or blocks_b:
        text_sim = len(blocks_a & blocks_b) / len(blocks_a | blocks_b)
    else:
        text_sim = 1.0

    # form_fields match (20%) — set comparison on (name, type) tuples
    fields_a = set(tuple(f) for f in sig_a.get("form_fields", []))
    fields_b = set(tuple(f) for f in sig_b.get("form_fields", []))
    if fields_a or fields_b:
        fields_sim = len(fields_a & fields_b) / len(fields_a | fields_b)
    else:
        fields_sim = 1.0

    # page_length_bucket proximity (10%)
    len_a = sig_a.get("page_length_bucket", 0)
    len_b = sig_b.get("page_length_bucket", 0)
    max_len = max(len_a, len_b, 1)
    len_sim = 1.0 - abs(len_a - len_b) / max_len

    return tree_sim * 0.4 + text_sim * 0.3 + fields_sim * 0.2 + len_sim * 0.1


def same_page(html_a: str, html_b: str, threshold: float = 0.85) -> bool:
    return compare_signatures(page_signature(html_a), page_signature(html_b)) >= threshold


def strip_dynamic(html: str) -> str:
    if not html:
        return ""
    result = html
    result = _TIMESTAMP_RE.sub("[TS]", result)
    result = _SESSION_PARAM_RE.sub("", result)
    result = _NONCE_ATTR_RE.sub("", result)
    result = _RANDOM_VALUE_RE.sub('value="[DYN]"', result)
    # blank out CSRF hidden field values
    for name in _CSRF_FIELD_NAMES:
        result = re.sub(
            r'(<input[^>]*name=["\']' + re.escape(name) + r'["\'][^>]*value=["\'])[^"\']*(["\'])',
            r'\g<1>[CSRF]\2',
            result,
            flags=re.IGNORECASE,
        )
    return result


def differential_pair_check(
    sig_equiv_a: dict,
    sig_equiv_b: dict,
    sig_different: dict,
    threshold: float = 0.85,
) -> bool:
    equiv_score = compare_signatures(sig_equiv_a, sig_equiv_b)
    diff_a = compare_signatures(sig_equiv_a, sig_different)
    diff_b = compare_signatures(sig_equiv_b, sig_different)
    return equiv_score >= threshold and diff_a < threshold and diff_b < threshold


# ── Internal helpers ─────────────────────────────────────────────────────────

def _lcs_ratio(a: list, b: list) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    max_len = max(len(a), len(b))
    # for large pages, sample to avoid O(n^2) blowup
    if max_len > 500:
        a = a[:250] + a[-250:]
        b = b[:250] + b[-250:]
        max_len = max(len(a), len(b))
    la, lb = len(a), len(b)
    # space-optimized LCS using two rows
    prev = [0] * (lb + 1)
    for i in range(1, la + 1):
        curr = [0] * (lb + 1)
        for j in range(1, lb + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev = curr
    return prev[lb] / max_len
