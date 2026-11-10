"""pr0t31n_auth.py — Shared authentication, TLS and security hardening for pr0t31n Flask apps.

Centralised module. Each app keeps a thin _auth.py shim that calls
configure(app_dir=...) and re-exports via ``from pr0t31n_auth import *``.

Credential files (.auth.json, .secret_key, ssl.crt, ssl.key) always land in the
configured app_dir — never in shared/.
"""
from __future__ import annotations

VERSION = "1.11.0"

import json
import os
import secrets
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ── Configurable state (set by each app's shim) ─────────────────────────────

_DIR: Optional[Path] = None
_PUBLIC: set = {"/login", "/logout", "/api/nexus-status"}
_PUBLIC_PREFIXES: tuple = ()
_SKIP_PREFIXES: tuple = ("/static/", "/socket.io/")
_REDIRECT_NEXT: Optional[str] = None   # None, "path", or "full_path"
_AUTH_FILE: Optional[Path] = None
_VALIDATE_SESSION_TOKENS: bool = False
_LOGIN_ENDPOINT: str = "login"
_CHANGE_PW_ENDPOINT: str = "change_password"

_DEFAULT_USERNAME = "admin"
_DEFAULT_PASSWORD = "t3mpPas$w0rd"


def configure(app_dir, *, public_paths=None, public_prefixes=None,
              skip_prefixes=None, redirect_next=None,
              validate_session_tokens=False,
              login_endpoint=None, change_password_endpoint=None,
              app_name=None, version_check_tools=None):
    """Call once at import time (from the app's _auth.py shim) to bind all
    file paths and auth-gate behaviour to the calling application."""
    global _DIR, _PUBLIC, _PUBLIC_PREFIXES, _SKIP_PREFIXES, _REDIRECT_NEXT
    global _AUTH_FILE, _VALIDATE_SESSION_TOKENS, _LOGIN_ENDPOINT, _CHANGE_PW_ENDPOINT
    _DIR = Path(app_dir).resolve()
    _AUTH_FILE = _DIR / ".auth.json"
    if public_paths is not None:
        _PUBLIC = set(public_paths)
    if public_prefixes is not None:
        _PUBLIC_PREFIXES = tuple(public_prefixes)
    if skip_prefixes is not None:
        _SKIP_PREFIXES = tuple(skip_prefixes)
    if redirect_next is not None:
        _REDIRECT_NEXT = redirect_next
    _VALIDATE_SESSION_TOKENS = validate_session_tokens
    if login_endpoint is not None:
        _LOGIN_ENDPOINT = login_endpoint
    if change_password_endpoint is not None:
        _CHANGE_PW_ENDPOINT = change_password_endpoint
    if app_name and version_check_tools is not None:
        try:
            from pr0t31n_version_check import check_versions_at_startup
            check_versions_at_startup(app_name, str(_DIR), tools=version_check_tools)
        except Exception:
            pass


def _ensure_configured():
    if _DIR is None:
        raise RuntimeError(
            "pr0t31n_auth.configure(app_dir) must be called before use. "
            "Each app's _auth.py shim should call it at import time."
        )


# ── Credential policy ─────────────────────────────────────────────────────────

_BLOCKED_USERNAMES: frozenset = frozenset({
    "admin", "administrator", "root", "user", "users", "guest", "test",
    "demo", "superuser", "super", "sysadmin", "operator", "manager",
    "owner", "service", "support", "helpdesk", "webmaster", "postmaster",
    "nobody", "default", "anonymous", "anon", "public", "system",
    "login", "logon", "access", "account", "info", "mail", "noreply",
})

_BLOCKED_PASSWORDS: frozenset = frozenset({
    "password", "password1", "password123", "passwords",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "abc123", "letmein", "welcome", "welcome1", "welcome123",
    "admin", "admin123", "admin1234", "administrator",
    "changeme", "change_me", "changeme1", "iloveyou",
    "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "superman", "batman", "trustno1",
    "baseball", "football", "soccer", "hockey", "hockey1",
    "pass", "pass123", "pass1234", "passw0rd",
    "test", "test123", "test1234", "testing",
    "guest", "login", "logon", "access",
    "t3mppass", _DEFAULT_PASSWORD.lower(),
})

def is_weak_username(username: str) -> Optional[str]:
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 32:
        return "Username must be 32 characters or fewer."
    if username.lower() in _BLOCKED_USERNAMES:
        return f"'{username}' is not allowed. Choose a unique username."
    return None

_MIN_PASSWORD_LENGTH = 12
_SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~\\")

def check_password_complexity(password: str) -> Optional[str]:
    if len(password) < _MIN_PASSWORD_LENGTH:
        return f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    if not any(c in _SPECIAL_CHARS for c in password):
        return "Password must contain at least one special character."
    return None

def is_weak_password(password: str, username: str = "") -> Optional[str]:
    err = check_password_complexity(password)
    if err:
        return err
    if password.lower() in _BLOCKED_PASSWORDS:
        return "That password is too common. Choose a stronger password."
    if username and password.lower() == username.lower():
        return "Password cannot be the same as the username."
    return None

# ── Persistent secret key ─────────────────────────────────────────────────────

def load_secret_key() -> str:
    _ensure_configured()
    key_file = _DIR / ".secret_key"
    if key_file.exists():
        key = key_file.read_text().strip()
        if len(key) >= 32:
            return key
    key = secrets.token_hex(32)
    key_file.write_text(key + "\n")
    key_file.chmod(0o600)
    return key

# ── Credential store ──────────────────────────────────────────────────────────

def init_auth(app_dir=None) -> None:
    if app_dir is not None:
        configure(app_dir)
    _ensure_configured()
    if not _AUTH_FILE.exists():
        _write_auth({
            "username": _DEFAULT_USERNAME,
            "password_hash": generate_password_hash(_DEFAULT_PASSWORD),
            "must_change": True,
        })

def _load_auth() -> dict:
    _ensure_configured()
    return json.loads(_AUTH_FILE.read_text())

def _write_auth(data: dict) -> None:
    _ensure_configured()
    _AUTH_FILE.write_text(json.dumps(data, indent=2))
    _AUTH_FILE.chmod(0o600)

def verify_credentials(username: str, password: str) -> bool:
    try:
        data = _load_auth()
        return (data.get("username") == username and
                check_password_hash(data.get("password_hash", ""), password))
    except Exception:
        return False

def must_change_password() -> bool:
    try:
        return bool(_load_auth().get("must_change"))
    except Exception:
        return False

def get_username() -> str:
    try:
        return _load_auth().get("username", "admin")
    except Exception:
        return "admin"

def check_current_password(password: str) -> bool:
    try:
        return check_password_hash(_load_auth().get("password_hash", ""), password)
    except Exception:
        return False

def update_password(new_password: str) -> None:
    data = _load_auth()
    data["password_hash"] = generate_password_hash(new_password)
    data["must_change"] = False
    _write_auth(data)

def update_credentials(new_username: str, new_password: str) -> None:
    _write_auth({
        "username": new_username,
        "password_hash": generate_password_hash(new_password),
        "must_change": False,
    })

# ── CSRF (server-side synchronizer token) ────────────────────────────────────

_csrf_store: dict = {}
_csrf_lock = threading.Lock()

def generate_csrf() -> str:
    token = secrets.token_hex(16)
    now = time.time()
    with _csrf_lock:
        expired = [t for t, exp in list(_csrf_store.items()) if exp < now]
        for t in expired:
            del _csrf_store[t]
        _csrf_store[token] = now + 3600
    return token

def validate_csrf(token: Optional[str]) -> bool:
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_store.pop(token, None)
    if expiry is None:
        return False
    return time.time() < expiry

# ── TLS ───────────────────────────────────────────────────────────────────────

_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!3DES"
)

def _local_ips_for_cert() -> str:
    ips: set = {"127.0.0.1"}
    try:
        if os.path.exists("/sbin/ip") or os.path.exists("/usr/sbin/ip"):
            out = subprocess.check_output(["ip", "-4", "addr"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip = line.split()[1].split("/")[0]
                    if not ip.startswith("127."):
                        ips.add(ip)
        else:
            out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    parts = line.split()
                    idx = parts.index("inet") + 1
                    ip = parts[idx]
                    if not ip.startswith("127."):
                        ips.add(ip)
    except Exception:
        pass
    return ",".join(f"IP:{ip}" for ip in sorted(ips)) + ",DNS:localhost"


def make_ssl_context() -> ssl.SSLContext:
    _ensure_configured()
    cert = _DIR / "ssl.crt"
    key  = _DIR / "ssl.key"
    if not cert.exists() or not key.exists():
        san = _local_ips_for_cert()
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-nodes", "-days", "3650",
                "-keyout", str(key), "-out", str(cert),
                "-subj", "/C=US/ST=Local/L=Local/O=pr0t31n/CN=localhost",
                "-addext", f"subjectAltName={san}",
            ],
            check=True, capture_output=True,
        )
        key.chmod(0o600)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    try:
        ctx.set_ciphers(_CIPHERS)
    except ssl.SSLError:
        pass
    return ctx

# ── Security headers ──────────────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self' wss: ws:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

def apply_security_headers(response):
    h = response.headers
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h["Content-Security-Policy"]   = _CSP
    h["X-Frame-Options"]           = "DENY"
    h["X-Content-Type-Options"]    = "nosniff"
    h["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    h["X-XSS-Protection"]          = "1; mode=block"
    h["Cache-Control"]             = "no-store, no-cache, must-revalidate, max-age=0"
    h["Pragma"]                    = "no-cache"
    h.pop("Server", None)
    h.pop("X-Powered-By", None)
    return response

# ── Request gate ──────────────────────────────────────────────────────────────

_session_tokens: dict = {}
_session_lock = threading.Lock()

def create_session_token() -> str:
    token = secrets.token_hex(24)
    with _session_lock:
        _session_tokens[token] = time.time()
    return token

def revoke_session_token(token: Optional[str]) -> None:
    if not token:
        return
    with _session_lock:
        _session_tokens.pop(token, None)

def _validate_session_token(token: Optional[str]) -> bool:
    if not token:
        return False
    with _session_lock:
        ts = _session_tokens.get(token)
    return ts is not None

def _prune_session_tokens(max_age: int = 7200) -> None:
    cutoff = time.time() - max_age
    with _session_lock:
        expired = [t for t, ts in _session_tokens.items() if ts < cutoff]
        for t in expired:
            del _session_tokens[t]


def auth_gate():
    path = request.path
    if any(path.startswith(p) for p in _SKIP_PREFIXES):
        return None
    if path in _PUBLIC:
        return None
    if _PUBLIC_PREFIXES and any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return None
    authenticated = session.get("authenticated")
    if _VALIDATE_SESSION_TOKENS and authenticated:
        if not _validate_session_token(session.get("session_token")):
            authenticated = False
            session.clear()
    if not authenticated:
        if path.startswith("/api/"):
            from flask import jsonify
            return jsonify({"error": "Session expired", "authenticated": False}), 401
        if _REDIRECT_NEXT == "path":
            return redirect(url_for(_LOGIN_ENDPOINT, next=request.path))
        elif _REDIRECT_NEXT == "full_path":
            return redirect(url_for(_LOGIN_ENDPOINT, next=request.full_path))
        return redirect(url_for(_LOGIN_ENDPOINT))
    if must_change_password() and path != "/auth/change-password":
        return redirect(url_for(_CHANGE_PW_ENDPOINT))
    if _VALIDATE_SESSION_TOKENS:
        _prune_session_tokens()
    return None
