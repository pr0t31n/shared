"""
pr0t31n_validators.py — Shared producer-side finding validators.

Generalises the Scattershot3 v1.13 testssl-validator pattern so any producer
(Fracture, Siphon, Gearbox, etc.) can re-test its own findings inline and
populate the v1.1 'confidence' field.

Each validator returns a (confidence, detail) tuple:
  confidence ∈ {"Certain", "Firm", "Tentative", "Cannot reproduce",
                "Not applicable"}
  detail     — short reason / extra context (may be "")

Validators available:
  validate_reflected_xss(url, param, payload=None, timeout=8)
      Re-tests a single reflected-XSS finding by sending the payload to the
      parameter and checking whether the response body reflects it intact.

  validate_bola(orig_url, alt_session_request_fn, expected_marker=None, timeout=8)
      Re-tests a BOLA / IDOR finding by replaying the request with the
      alternate user's session and confirming the response still contains
      the original user's data (marker).

  validate_open_redirect(base_url, param, payload="https://example.com/", timeout=8)
      Re-tests open-redirect findings.

  validate_clickjacking(url, timeout=5)
      Confirms missing X-Frame-Options / CSP frame-ancestors.

  validate_missing_security_header(url, header_name, timeout=5)
      Generic missing-header validator.

stdlib only (uses urllib.request). Producers may pass their own HTTP client
via the `http_get` / `http_request` callables for session/cookie reuse.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.parse
import urllib.request


def _default_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


def _default_http_get(url, headers=None, timeout=8):
    """Default GET — caller can pass a session-aware function instead."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_default_ctx()) as r:
            body = r.read()
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        return 0, {}, b""


# ─── Reflected XSS validator ────────────────────────────────────────────────
_DEFAULT_XSS_MARKER = "ss3xss12345"


def validate_reflected_xss(url, param, *, payload=None, http_get=None,
                           timeout=8):
    """
    Re-probe a reflected-XSS finding. Sends `payload` (default a benign marker
    in script tags) as the parameter value and checks the response body for
    reflection.

    Returns (confidence, detail).
    """
    http_get = http_get or _default_http_get
    marker = _DEFAULT_XSS_MARKER
    if payload is None:
        payload = f"<script>{marker}</script>"
    # Build URL with the parameter
    try:
        u = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        # Replace existing or append
        new_qs = [(k, v) for k, v in qs if k != param] + [(param, payload)]
        new_query = urllib.parse.urlencode(new_qs, doseq=True)
        test_url = urllib.parse.urlunparse((u.scheme, u.netloc, u.path,
                                             u.params, new_query, u.fragment))
    except Exception as e:
        return ("Tentative", f"validator: URL build failed: {e}")
    status, _headers, body = http_get(test_url, timeout=timeout)
    if status == 0:
        return ("Tentative", "validator: request failed")
    if status >= 500:
        return ("Tentative", f"validator: server error ({status})")
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    # Look for the full payload reflected (most reliable)
    if payload in text:
        return ("Firm",
                f"validator: payload reflected unencoded at {param} (HTTP {status})")
    # Look for just the marker — partial reflection (script tag stripped but
    # the inner text appears, still a reflection condition though lower confidence)
    if marker in text:
        return ("Tentative",
                f"validator: marker reflected (tags filtered, partial XSS) HTTP {status}")
    return ("Cannot reproduce",
            f"validator: payload not reflected (HTTP {status})")


# ─── BOLA / IDOR validator ─────────────────────────────────────────────────
def validate_bola(orig_url, alt_session_get_fn, *, expected_marker=None,
                  timeout=8):
    """
    Re-probe a BOLA/IDOR finding by sending the same URL via an alternate
    user's session. Requires the caller to pass `alt_session_get_fn(url)`
    which performs the request with the OTHER user's authentication and
    returns (status, headers, body).

    `expected_marker` — substring that, if present in the alt-session
    response body, confirms the original user's data is accessible.

    Returns (confidence, detail).
    """
    if alt_session_get_fn is None:
        return ("Tentative", "validator: alt-session function not provided")
    try:
        status, _headers, body = alt_session_get_fn(orig_url, timeout=timeout)
    except Exception as e:
        return ("Tentative", f"validator: alt-session request failed: {e}")
    if status == 0:
        return ("Tentative", "validator: alt-session request returned no status")
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    if status in (401, 403):
        return ("Cannot reproduce",
                f"validator: alt session blocked (HTTP {status}) — access control IS enforced")
    if expected_marker and expected_marker in text:
        return ("Firm",
                f"validator: alt session retrieved original user's data "
                f"(marker '{expected_marker}' present, HTTP {status})")
    if status == 200 and len(text) > 100:
        return ("Tentative",
                f"validator: alt session got HTTP 200 with body ({len(text)} bytes) "
                f"but no marker check — manually verify")
    return ("Cannot reproduce",
            f"validator: alt session response inconclusive (HTTP {status}, {len(text)} bytes)")


# ─── Open redirect validator ───────────────────────────────────────────────
def validate_open_redirect(base_url, param, *,
                           payload="https://example.com/sentinel",
                           http_get=None, timeout=5):
    """Check if a URL parameter triggers a redirect to attacker-controlled host."""
    http_get = http_get or _default_http_get
    try:
        u = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        new_qs = [(k, v) for k, v in qs if k != param] + [(param, payload)]
        new_query = urllib.parse.urlencode(new_qs, doseq=True)
        test_url = urllib.parse.urlunparse((u.scheme, u.netloc, u.path,
                                             u.params, new_query, u.fragment))
    except Exception as e:
        return ("Tentative", f"validator: URL build failed: {e}")
    # Use a custom opener that DOES NOT follow redirects
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # bail
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(test_url), timeout=timeout) as r:
            status = r.status
            headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        status = e.code
        headers = dict(e.headers or {})
    except Exception as e:
        return ("Tentative", f"validator: request failed: {e}")
    if not (300 <= status < 400):
        return ("Cannot reproduce", f"validator: no redirect on probe (HTTP {status})")
    loc = headers.get("Location", headers.get("location", ""))
    if not loc:
        return ("Cannot reproduce", "validator: 3xx without Location")
    if payload.split("://", 1)[-1].split("/", 1)[0] in loc:
        return ("Firm", f"validator: Location header redirects to attacker payload ({loc})")
    return ("Cannot reproduce", f"validator: Location points elsewhere ({loc})")


# ─── Clickjacking / missing-header validators ──────────────────────────────
def validate_clickjacking(url, *, http_get=None, timeout=5):
    """Confirms missing X-Frame-Options and absent CSP frame-ancestors."""
    http_get = http_get or _default_http_get
    status, headers, _body = http_get(url, timeout=timeout)
    if status == 0:
        return ("Tentative", "validator: request failed")
    xfo = ""
    csp = ""
    for k, v in headers.items():
        if k.lower() == "x-frame-options":
            xfo = v
        elif k.lower() == "content-security-policy":
            csp = v
    if not xfo and "frame-ancestors" not in csp.lower():
        return ("Firm", "validator: no X-Frame-Options AND no CSP frame-ancestors")
    if xfo:
        return ("Cannot reproduce", f"validator: X-Frame-Options present: {xfo}")
    return ("Cannot reproduce", "validator: CSP frame-ancestors present")


def validate_missing_security_header(url, header_name, *, http_get=None,
                                     timeout=5):
    """Generic missing-header validator."""
    http_get = http_get or _default_http_get
    status, headers, _body = http_get(url, timeout=timeout)
    if status == 0:
        return ("Tentative", "validator: request failed")
    for k in headers:
        if k.lower() == header_name.lower():
            return ("Cannot reproduce", f"validator: {header_name} present: {headers[k]}")
    return ("Firm", f"validator: {header_name} absent from response")


# ─── Self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Stub http_get for offline tests — URL-decodes to model a real reflective server
    def _stub(url, **kw):
        decoded = urllib.parse.unquote(url)
        if "xss=" in decoded and "<script>ss3xss12345</script>" in decoded:
            return (200, {}, b"...<div><script>ss3xss12345</script></div>...")
        if "xss=" in decoded and "ss3xss12345" in decoded:
            return (200, {}, b"...partial match: ss3xss12345 only...")
        if "xss=" in decoded:
            return (200, {}, b"...no reflection...")
        return (200, {"X-Frame-Options": "DENY"}, b"<html></html>")

    # XSS validator: payload reflected
    c, d = validate_reflected_xss("https://x/?xss=", "xss", http_get=_stub)
    assert c == "Firm", (c, d)
    print(f"XSS validator FIRM: {d}")

    # XSS validator: marker only (filtered)
    c, d = validate_reflected_xss("https://x/?xss=",
                                  "xss",
                                  payload="ss3xss12345",
                                  http_get=_stub)
    assert c in ("Firm", "Tentative"), (c, d)
    print(f"XSS validator MARKER-ONLY: {c} — {d}")

    # XSS validator: nothing reflected
    def _silent(url, **kw): return (200, {}, b"<html><body>nope</body></html>")
    c, d = validate_reflected_xss("https://x/?xss=", "xss", http_get=_silent)
    assert c == "Cannot reproduce"
    print(f"XSS validator CANNOT-REPRODUCE: {d}")

    # Missing security header
    def _no_hsts(url, **kw): return (200, {"X-Frame-Options": "DENY"}, b"")
    c, d = validate_missing_security_header("https://x/", "Strict-Transport-Security",
                                             http_get=_no_hsts)
    assert c == "Firm"
    print(f"missing-header validator: {d}")

    # Clickjacking — present
    c, d = validate_clickjacking("https://x/", http_get=_no_hsts)
    assert c == "Cannot reproduce"
    print(f"clickjacking PROTECTED: {d}")

    # BOLA — alt session blocked
    def _alt_blocked(url, **kw): return (403, {}, b"")
    c, d = validate_bola("https://x/api/users/123", _alt_blocked)
    assert c == "Cannot reproduce"
    print(f"BOLA blocked: {d}")

    # BOLA — alt session sees original user's data
    def _alt_leak(url, **kw): return (200, {}, b'{"email":"victim@example.com","ssn":"X"}')
    c, d = validate_bola("https://x/api/users/123", _alt_leak,
                          expected_marker="victim@example.com")
    assert c == "Firm"
    print(f"BOLA confirmed: {d}")

    print("pr0t31n_validators: self-test PASS")
