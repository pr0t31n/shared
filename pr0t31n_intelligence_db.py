"""pr0t31n Intelligence DB — structured intelligence table management.

Operates on the same SQLite ``findings.db`` file as FindingsDB but owns
all intelligence tables (structure maps, access matrix, auth sessions,
cookies, webapp intel, network posture, hostname intel, server roles,
domain intel, OSINT tables, screenshots).

Provides both flat CRUD methods (same signatures as the ones that used to
live in FindingsDB) **and** aggregation/view methods that return the exact
JSON shapes the Crucible JS renderers expect.
"""
import json
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


try:
    VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()
except FileNotFoundError:
    VERSION = "0.0.0"

# ---------------------------------------------------------------------------
# Schema migrations — additive only, never destructive
# ---------------------------------------------------------------------------

_MIGRATIONS = [
    # structure_urls — new columns
    "ALTER TABLE structure_urls ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    "ALTER TABLE structure_urls ADD COLUMN auth_required INTEGER DEFAULT 0",
    "ALTER TABLE structure_urls ADD COLUMN auth_roles TEXT",
    "ALTER TABLE structure_urls ADD COLUMN is_rogue INTEGER DEFAULT 0",
    "ALTER TABLE structure_urls ADD COLUMN from_spec INTEGER DEFAULT 0",
    "ALTER TABLE structure_urls ADD COLUMN target_url TEXT",
    # access_matrix_entries — new columns
    "ALTER TABLE access_matrix_entries ADD COLUMN waf_detected INTEGER DEFAULT 0",
    "ALTER TABLE access_matrix_entries ADD COLUMN body_denied INTEGER DEFAULT 0",
    "ALTER TABLE access_matrix_entries ADD COLUMN response_size INTEGER",
    "ALTER TABLE access_matrix_entries ADD COLUMN size_restricted INTEGER DEFAULT 0",
    "ALTER TABLE access_matrix_entries ADD COLUMN body_class TEXT",
    "ALTER TABLE access_matrix_entries ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    "ALTER TABLE access_matrix_entries ADD COLUMN target_url TEXT",
    # auth_cookies — value column
    "ALTER TABLE auth_cookies ADD COLUMN value TEXT",
    # cookies — new columns
    "ALTER TABLE cookies ADD COLUMN value TEXT",
    "ALTER TABLE cookies ADD COLUMN role TEXT",
    # webapp_intel — new columns
    "ALTER TABLE webapp_intel ADD COLUMN waf TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN tls_enabled INTEGER",
    "ALTER TABLE webapp_intel ADD COLUMN tls_protocols TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN cert_issuer TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN cert_subject TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN cert_expiry TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN load_balancer INTEGER DEFAULT 0",
    "ALTER TABLE webapp_intel ADD COLUMN backend_ips TEXT",
    "ALTER TABLE webapp_intel ADD COLUMN frameworks TEXT DEFAULT '[]'",
    "ALTER TABLE webapp_intel ADD COLUMN programming_languages TEXT DEFAULT '[]'",
    "ALTER TABLE webapp_intel ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    # hostname_intel + server_roles — scope_id
    "ALTER TABLE hostname_intel ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    "ALTER TABLE server_roles ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    # network_posture — scope_id
    "ALTER TABLE network_posture ADD COLUMN scope_id INTEGER REFERENCES scopes(id)",
    # auth_sessions — dedup: backfill NULL roles, delete dupes, add UNIQUE index
    "UPDATE auth_sessions SET role = session_name WHERE role IS NULL OR role = ''",
    "DELETE FROM auth_sessions WHERE id NOT IN (SELECT MIN(id) FROM auth_sessions GROUP BY tool, COALESCE(role, ''))",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_sessions_tool_role ON auth_sessions(tool, role)",
]

_NEW_TABLES = """
CREATE TABLE IF NOT EXISTS network_posture_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    host_count INTEGER DEFAULT 0,
    open_hosts INTEGER DEFAULT 0,
    filtered_hosts INTEGER DEFAULT 0,
    closed_hosts INTEGER DEFAULT 0,
    segmented INTEGER DEFAULT 0,
    scope_id INTEGER REFERENCES scopes(id),
    UNIQUE(cidr, scope_id)
);

CREATE TABLE IF NOT EXISTS network_posture_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet_id INTEGER REFERENCES network_posture_subnets(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    hostname TEXT,
    posture TEXT,
    open_port_count INTEGER DEFAULT 0,
    port_open INTEGER DEFAULT 0,
    port_closed INTEGER DEFAULT 0,
    port_filtered INTEGER DEFAULT 0,
    port_scanned INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nph_subnet ON network_posture_hosts(subnet_id);
CREATE INDEX IF NOT EXISTS idx_nph_ip ON network_posture_hosts(ip);
"""


class IntelligenceDB:
    """Intelligence-table manager sharing the same SQLite DB file."""

    def __init__(self, db_path, *, timeout=30):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, timeout=timeout)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._run_migrations()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def _commit(self):
        self._conn.commit()

    # ------------------------------------------------------------------
    # Migrations
    # ------------------------------------------------------------------

    def _run_migrations(self):
        for sql in _MIGRATIONS:
            try:
                self._conn.execute(sql)
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass
        for stmt in _NEW_TABLES.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                try:
                    self._conn.execute(stmt)
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass
        try:
            self._conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            pass

    def _table_exists(self, table):
        try:
            r = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,)).fetchone()
            return r is not None
        except Exception:
            return False

    def _has_column(self, table, column):
        try:
            cols = [d[1] for d in self._conn.execute(
                f"PRAGMA table_info({table})").fetchall()]
            return column in cols
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_sort(self, col, whitelist):
        return col if col in whitelist else "id"

    def _cols(self, table):
        return [d[0] for d in self._conn.execute(
            f"SELECT * FROM {table} LIMIT 0").description]

    def _rows_to_dicts(self, table, rows):
        cols = self._cols(table)
        return [dict(zip(cols, r)) for r in rows]

    def _paginated(self, table, where, params, sort, order, page, per_page,
                   whitelist, select="*"):
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, whitelist)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM {table} {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT {select} FROM {table} {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols(table) if select == "*" else [
            d[0] for d in rows[0].keys()] if rows else []
        items = [dict(zip(cols, r)) for r in rows] if select == "*" else [
            {c: r[c] for c in cols} for r in rows]
        return {"items": items, "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    # ==================================================================
    #  Column whitelists
    # ==================================================================

    _STRUCTURE_URLS_COLS = frozenset({
        "id", "tool_run_id", "url", "method", "status_code", "content_type",
        "content_length", "redirect_url", "depth", "source", "response_time_ms",
        "created_at", "scope_id", "auth_required", "auth_roles", "is_rogue",
        "from_spec", "target_url",
    })
    _STRUCTURE_PARAMS_COLS = frozenset({
        "id", "url_id", "name", "param_type", "value", "location",
    })
    _STRUCTURE_FORMS_COLS = frozenset({
        "id", "url_id", "action", "method", "enctype", "input_count",
    })
    _STRUCTURE_HEADERS_COLS = frozenset({
        "id", "url_id", "direction", "name", "value",
    })
    _ACCESS_MATRIX_COLS = frozenset({
        "id", "tool", "endpoint_path", "method", "role", "expected_status",
        "actual_status", "result", "auth_type", "notes", "created_at",
        "waf_detected", "body_denied", "response_size", "size_restricted",
        "body_class", "scope_id", "target_url",
    })
    _AUTH_SESSIONS_COLS = frozenset({
        "id", "tool", "session_name", "auth_type", "valid", "username",
        "role", "token_preview", "expires_at", "created_at",
    })
    _AUTH_COOKIES_COLS = frozenset({
        "id", "session_id", "name", "domain", "path", "secure", "httponly",
        "samesite", "expires_at", "value",
    })
    _COOKIES_COLS = frozenset({
        "id", "name", "domain", "path", "secure", "httponly", "samesite",
        "expires_at", "scope", "tool", "url", "risk", "issues", "value", "role",
    })
    _WEBAPP_INTEL_COLS = frozenset({
        "id", "tool", "url", "ip", "port", "hostname", "server", "powered_by",
        "cms", "technologies", "cdn", "edge_security", "bi_tools",
        "web_structure", "details_json", "created_at", "waf", "tls_enabled",
        "tls_protocols", "cert_issuer", "cert_subject", "cert_expiry",
        "load_balancer", "backend_ips", "frameworks", "programming_languages",
        "scope_id",
    })
    _HOSTNAME_INTEL_COLS = frozenset({
        "id", "hostname", "ip", "environment_tag", "application_tag",
        "hardware_tag", "role_tag", "confidence", "scope_id",
    })
    _SERVER_ROLES_COLS = frozenset({
        "id", "ip", "hostname", "role", "confidence", "evidence", "scope_id",
    })
    _SCREENSHOTS_COLS = frozenset({
        "id", "tool", "url", "ip", "port", "hostname", "file_path",
        "thumbnail_path", "width", "height", "file_size", "title",
        "server", "status_code", "description", "classification",
        "scheme", "page_title", "scope", "captured_at",
    })
    _DOMAIN_INTEL_COLS = frozenset({
        "id", "domain_name", "domain_type", "netbios_name", "dns_name",
        "dns_tree", "sid", "source_ip", "source_port", "computer_name",
        "hostname", "is_dc", "source", "evidence", "created_at",
    })

    # ==================================================================
    #  CRUD — Structure URLs
    # ==================================================================

    def add_structure_url(self, url, method="GET", status_code=None,
                          content_type=None, content_length=None,
                          redirect_url=None, depth=0, source=None,
                          response_time_ms=None, tool_run_id=None,
                          scope_id=None, auth_required=0, auth_roles=None,
                          is_rogue=0, from_spec=0, target_url=None):
        ar_json = json.dumps(auth_roles) if isinstance(auth_roles, (list, tuple)) else auth_roles
        self._conn.execute(
            "INSERT INTO structure_urls (tool_run_id, url, method, status_code, "
            "content_type, content_length, redirect_url, depth, source, "
            "response_time_ms, scope_id, auth_required, auth_roles, is_rogue, "
            "from_spec, target_url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool_run_id, url, method, status_code, content_type,
             content_length, redirect_url, depth, source, response_time_ms,
             scope_id, auth_required, ar_json, is_rogue, from_spec, target_url))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_urls(self, page=1, per_page=50, status_code=None,
                             source=None, method=None, search=None,
                             tool_run_id=None, scope_id=None,
                             sort="id", order="asc", **_kw):
        where, params = [], []
        if status_code is not None:
            where.append("status_code = ?"); params.append(status_code)
        if source:
            where.append("source = ?"); params.append(source)
        if method:
            where.append("method = ?"); params.append(method)
        if tool_run_id is not None:
            where.append("tool_run_id = ?"); params.append(tool_run_id)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if search:
            where.append("url LIKE ?"); params.append(f"%{search}%")
        return self._paginated("structure_urls", where, params, sort, order,
                               page, per_page, self._STRUCTURE_URLS_COLS)

    def count_structure_urls(self, tool_run_id=None, scope_id=None):
        where, params = [], []
        if tool_run_id is not None:
            where.append("tool_run_id = ?"); params.append(tool_run_id)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM structure_urls {w}", params).fetchone()[0]

    # ==================================================================
    #  CRUD — Structure Params
    # ==================================================================

    def add_structure_param(self, url_id, name, param_type=None, value=None,
                            location=None):
        self._conn.execute(
            "INSERT INTO structure_params (url_id, name, param_type, value, "
            "location) VALUES (?, ?, ?, ?, ?)",
            (url_id, name, param_type, value, location))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_params(self, page=1, per_page=50, url_id=None,
                               param_type=None, search=None,
                               sort="id", order="asc", **_kw):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if param_type:
            where.append("param_type = ?"); params.append(param_type)
        if search:
            where.append("name LIKE ?"); params.append(f"%{search}%")
        return self._paginated("structure_params", where, params, sort, order,
                               page, per_page, self._STRUCTURE_PARAMS_COLS)

    def count_structure_params(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_params WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_params").fetchone()[0]

    # ==================================================================
    #  CRUD — Structure Forms
    # ==================================================================

    def add_structure_form(self, url_id, action=None, method="POST",
                           enctype=None, input_count=0):
        self._conn.execute(
            "INSERT INTO structure_forms (url_id, action, method, enctype, "
            "input_count) VALUES (?, ?, ?, ?, ?)",
            (url_id, action, method, enctype, input_count))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_forms(self, page=1, per_page=50, url_id=None,
                              method=None, sort="id", order="asc", **_kw):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if method:
            where.append("method = ?"); params.append(method)
        return self._paginated("structure_forms", where, params, sort, order,
                               page, per_page, self._STRUCTURE_FORMS_COLS)

    def count_structure_forms(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_forms WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_forms").fetchone()[0]

    # ==================================================================
    #  CRUD — Structure Headers
    # ==================================================================

    def add_structure_header(self, url_id, direction, name, value=None):
        self._conn.execute(
            "INSERT INTO structure_headers (url_id, direction, name, value) "
            "VALUES (?, ?, ?, ?)",
            (url_id, direction, name, value))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_headers(self, page=1, per_page=50, url_id=None,
                                direction=None, search=None,
                                sort="id", order="asc", **_kw):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if direction:
            where.append("direction = ?"); params.append(direction)
        if search:
            where.append("name LIKE ?"); params.append(f"%{search}%")
        return self._paginated("structure_headers", where, params, sort, order,
                               page, per_page, self._STRUCTURE_HEADERS_COLS)

    def count_structure_headers(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_headers WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_headers").fetchone()[0]

    # ==================================================================
    #  CRUD — Access Matrix Entries
    # ==================================================================

    def add_access_matrix_entry(self, tool, endpoint_path, role,
                                method="GET", expected_status=None,
                                actual_status=None, result=None,
                                auth_type=None, notes=None,
                                waf_detected=0, body_denied=0,
                                response_size=None, size_restricted=0,
                                body_class=None, scope_id=None,
                                target_url=None):
        self._conn.execute(
            "INSERT INTO access_matrix_entries (tool, endpoint_path, method, "
            "role, expected_status, actual_status, result, auth_type, notes, "
            "waf_detected, body_denied, response_size, size_restricted, "
            "body_class, scope_id, target_url) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool, endpoint_path, method, role, expected_status,
             actual_status, result, auth_type, notes, waf_detected,
             body_denied, response_size, size_restricted, body_class,
             scope_id, target_url))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_access_matrix_entries(self, page=1, per_page=50, tool=None,
                                    endpoint_path=None, role=None, result=None,
                                    method=None, search=None, scope_id=None,
                                    sort="id", order="asc", **_kw):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if endpoint_path:
            where.append("endpoint_path = ?"); params.append(endpoint_path)
        if role:
            where.append("role = ?"); params.append(role)
        if result:
            where.append("result = ?"); params.append(result)
        if method:
            where.append("method = ?"); params.append(method)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if search:
            where.append("endpoint_path LIKE ?"); params.append(f"%{search}%")
        return self._paginated("access_matrix_entries", where, params,
                               sort, order, page, per_page,
                               self._ACCESS_MATRIX_COLS)

    def count_access_matrix_entries(self, tool=None, role=None, scope_id=None):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if role:
            where.append("role = ?"); params.append(role)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM access_matrix_entries {w}",
            params).fetchone()[0]

    # ==================================================================
    #  CRUD — Auth Sessions
    # ==================================================================

    def add_auth_session(self, tool, session_name=None, auth_type=None,
                         valid=1, username=None, role=None,
                         token_preview=None, expires_at=None):
        role = role or session_name or ""
        self._conn.execute(
            "INSERT INTO auth_sessions (tool, session_name, auth_type, valid, "
            "username, role, token_preview, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tool, role) DO UPDATE SET "
            "session_name = COALESCE(excluded.session_name, session_name), "
            "auth_type = COALESCE(excluded.auth_type, auth_type), "
            "valid = excluded.valid, "
            "username = COALESCE(excluded.username, username), "
            "token_preview = COALESCE(excluded.token_preview, token_preview), "
            "expires_at = COALESCE(excluded.expires_at, expires_at)",
            (tool, session_name, auth_type, valid, username, role,
             token_preview, expires_at))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_auth_sessions(self, page=1, per_page=50, tool=None,
                            auth_type=None, valid=None, username=None,
                            role=None, sort="id", order="asc", **_kw):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if auth_type:
            where.append("auth_type = ?"); params.append(auth_type)
        if valid is not None:
            where.append("valid = ?"); params.append(valid)
        if username:
            where.append("username = ?"); params.append(username)
        if role:
            where.append("role = ?"); params.append(role)
        return self._paginated("auth_sessions", where, params, sort, order,
                               page, per_page, self._AUTH_SESSIONS_COLS)

    def count_auth_sessions(self, tool=None):
        if tool:
            return self._conn.execute(
                "SELECT COUNT(*) FROM auth_sessions WHERE tool = ?",
                (tool,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM auth_sessions").fetchone()[0]

    # ==================================================================
    #  CRUD — Auth Cookies
    # ==================================================================

    def add_auth_cookie(self, session_id, name, domain=None, path="/",
                        secure=0, httponly=0, samesite=None, expires_at=None,
                        value=None):
        self._conn.execute(
            "INSERT INTO auth_cookies (session_id, name, domain, path, "
            "secure, httponly, samesite, expires_at, value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, name, domain, path, secure, httponly, samesite,
             expires_at, value))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_auth_cookies(self, page=1, per_page=50, session_id=None,
                           name=None, domain=None, secure=None,
                           httponly=None, sort="id", order="asc", **_kw):
        where, params = [], []
        if session_id is not None:
            where.append("session_id = ?"); params.append(session_id)
        if name:
            where.append("name = ?"); params.append(name)
        if domain:
            where.append("domain = ?"); params.append(domain)
        if secure is not None:
            where.append("secure = ?"); params.append(secure)
        if httponly is not None:
            where.append("httponly = ?"); params.append(httponly)
        return self._paginated("auth_cookies", where, params, sort, order,
                               page, per_page, self._AUTH_COOKIES_COLS)

    def count_auth_cookies(self, session_id=None):
        if session_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM auth_cookies WHERE session_id = ?",
                (session_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM auth_cookies").fetchone()[0]

    # ==================================================================
    #  CRUD — Cookies (Fracture / Siphon)
    # ==================================================================

    def add_cookie(self, name, domain=None, path="/", secure=0, httponly=0,
                   samesite=None, expires_at=None, scope=None, tool=None,
                   url=None, risk=None, issues=None, value=None, role=None):
        cur = self._conn.execute(
            "SELECT id FROM cookies WHERE name=? AND "
            "COALESCE(domain,'')=COALESCE(?,'') AND "
            "COALESCE(path,'/')=COALESCE(?,'/') AND "
            "COALESCE(role,'')=COALESCE(?,'')",
            (name, domain, path, role))
        existing = cur.fetchone()
        if existing:
            rid = existing[0] if isinstance(existing, (tuple, list)) else existing["id"]
            self._conn.execute(
                "UPDATE cookies SET "
                "secure    = CASE WHEN ?=1 THEN 1 ELSE secure END, "
                "httponly   = CASE WHEN ?=1 THEN 1 ELSE httponly END, "
                "samesite   = COALESCE(?,samesite), "
                "expires_at = COALESCE(?,expires_at), "
                "scope      = COALESCE(?,scope), "
                "tool       = COALESCE(?,tool), "
                "url        = COALESCE(?,url), "
                "risk       = COALESCE(?,risk), "
                "issues     = COALESCE(?,issues), "
                "value      = COALESCE(?,value) "
                "WHERE id=?",
                (secure, httponly, samesite, expires_at, scope, tool,
                 url, risk, issues, value, rid))
            return rid
        else:
            self._conn.execute(
                "INSERT INTO cookies (name, domain, path, secure, httponly, "
                "samesite, expires_at, scope, tool, url, risk, issues, value, role) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, domain, path, secure, httponly, samesite, expires_at,
                 scope, tool, url, risk, issues, value, role))
            return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_cookies(self, page=1, per_page=50, tool=None, search=None,
                      scope_id=None, **_kw):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if search:
            where.append("(name LIKE ? OR domain LIKE ? OR issues LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM cookies {w}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM cookies {w} ORDER BY domain, name "
                "LIMIT ? OFFSET ?",
                params + [per_page, (page - 1) * per_page]).fetchall()
            cols = self._cols("cookies")
        except Exception:
            return {"items": [], "total": 0, "page": page, "pages": 0}
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    # ==================================================================
    #  CRUD — WebApp Intel
    # ==================================================================

    def add_webapp_intel(self, tool="fracture", url=None, ip=None, port=None,
                         hostname=None, server=None, powered_by=None,
                         cms=None, technologies=None, cdn=None,
                         edge_security=None, bi_tools=None,
                         web_structure=None, details_json=None,
                         waf=None, tls_enabled=None, tls_protocols=None,
                         cert_issuer=None, cert_subject=None,
                         cert_expiry=None, load_balancer=0,
                         backend_ips=None, frameworks=None,
                         programming_languages=None, scope_id=None):
        techs = json.dumps(technologies) if isinstance(technologies, (list, dict)) else (technologies or "[]")
        ws = json.dumps(web_structure) if isinstance(web_structure, dict) else (web_structure or "{}")
        dj = json.dumps(details_json) if isinstance(details_json, dict) else (details_json or "{}")
        fw = json.dumps(frameworks) if isinstance(frameworks, (list, dict)) else (frameworks or "[]")
        pl = json.dumps(programming_languages) if isinstance(programming_languages, (list, dict)) else (programming_languages or "[]")
        cur = self._conn.execute(
            "SELECT id FROM webapp_intel WHERE tool=? AND "
            "COALESCE(url,'')=COALESCE(?,'') AND "
            "COALESCE(ip,'')=COALESCE(?,'') AND "
            "COALESCE(port,0)=COALESCE(?,0)",
            (tool, url, ip, port))
        existing = cur.fetchone()
        if existing:
            self._conn.execute(
                "UPDATE webapp_intel SET "
                "hostname   = COALESCE(?,hostname), "
                "server     = COALESCE(?,server), "
                "powered_by = COALESCE(?,powered_by), "
                "cms        = COALESCE(?,cms), "
                "technologies = CASE WHEN ? IN ('[]','null') THEN technologies ELSE ? END, "
                "cdn          = COALESCE(?,cdn), "
                "edge_security= COALESCE(?,edge_security), "
                "bi_tools     = COALESCE(?,bi_tools), "
                "web_structure= CASE WHEN ? IN ('{}','null') THEN web_structure ELSE ? END, "
                "details_json = CASE WHEN ? IN ('{}','null') THEN details_json ELSE ? END, "
                "waf          = COALESCE(?,waf), "
                "tls_enabled  = COALESCE(?,tls_enabled), "
                "tls_protocols= COALESCE(?,tls_protocols), "
                "cert_issuer  = COALESCE(?,cert_issuer), "
                "cert_subject = COALESCE(?,cert_subject), "
                "cert_expiry  = COALESCE(?,cert_expiry), "
                "load_balancer= CASE WHEN ?=1 THEN 1 ELSE load_balancer END, "
                "backend_ips  = COALESCE(?,backend_ips), "
                "frameworks   = CASE WHEN ? IN ('[]','null') THEN frameworks ELSE ? END, "
                "programming_languages = CASE WHEN ? IN ('[]','null') THEN programming_languages ELSE ? END, "
                "scope_id     = COALESCE(?,scope_id) "
                "WHERE id=?",
                (hostname, server, powered_by, cms,
                 techs, techs, cdn, edge_security, bi_tools,
                 ws, ws, dj, dj, waf, tls_enabled, tls_protocols,
                 cert_issuer, cert_subject, cert_expiry, load_balancer,
                 backend_ips, fw, fw, pl, pl, scope_id,
                 existing[0] if isinstance(existing, (tuple, list)) else existing["id"]))
        else:
            self._conn.execute(
                "INSERT INTO webapp_intel "
                "(tool, url, ip, port, hostname, server, powered_by, cms, "
                "technologies, cdn, edge_security, bi_tools, web_structure, "
                "details_json, waf, tls_enabled, tls_protocols, cert_issuer, "
                "cert_subject, cert_expiry, load_balancer, backend_ips, "
                "frameworks, programming_languages, scope_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tool, url, ip, port, hostname, server, powered_by, cms,
                 techs, cdn, edge_security, bi_tools, ws, dj, waf,
                 tls_enabled, tls_protocols, cert_issuer, cert_subject,
                 cert_expiry, load_balancer, backend_ips, fw, pl, scope_id))

    def query_webapp_intel(self, page=1, per_page=50, category=None,
                           tool=None, ip=None, search=None,
                           scope_id=None, **_kw):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if ip:
            where.append("ip = ?"); params.append(ip)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if category:
            where.append("(server LIKE ? OR cms LIKE ? OR technologies LIKE ?)")
            params.extend([f"%{category}%"] * 3)
        if search:
            s = f"%{search}%"
            where.append("(url LIKE ? OR hostname LIKE ? OR server LIKE ? "
                         "OR cms LIKE ? OR technologies LIKE ? OR powered_by LIKE ?)")
            params.extend([s] * 6)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM webapp_intel {w}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM webapp_intel {w} ORDER BY id LIMIT ? OFFSET ?",
                params + [per_page, (page - 1) * per_page]).fetchall()
            cols = self._cols("webapp_intel")
        except Exception:
            return {"items": [], "total": 0, "page": page, "pages": 0}
        items = []
        for r in rows:
            item = dict(zip(cols, r))
            for jk in ("technologies", "web_structure", "frameworks",
                        "programming_languages"):
                if item.get(jk) and isinstance(item[jk], str):
                    try:
                        item[jk] = json.loads(item[jk])
                    except (json.JSONDecodeError, TypeError):
                        pass
            items.append(item)
        return {"items": items, "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    # ==================================================================
    #  CRUD — Network Posture (flat + subnet)
    # ==================================================================

    def add_network_posture(self, category, check_name, status, value=None,
                            risk=None, description=None, details_json=None,
                            scope_id=None):
        dj = json.dumps(details_json) if isinstance(details_json, dict) else (details_json or "{}")
        cur = self._conn.execute(
            "SELECT id FROM network_posture WHERE category=? AND check_name=? "
            "AND COALESCE(scope_id,0)=COALESCE(?,0)",
            (category, check_name, scope_id))
        existing = cur.fetchone()
        if existing:
            self._conn.execute(
                "UPDATE network_posture SET "
                "status       = ?, "
                "value        = COALESCE(?,value), "
                "risk         = COALESCE(?,risk), "
                "description  = COALESCE(?,description), "
                "details_json = CASE WHEN ? IN ('{}','null') THEN details_json ELSE ? END, "
                "scope_id     = COALESCE(?,scope_id) "
                "WHERE id=?",
                (status, value, risk, description, dj, dj, scope_id,
                 existing[0] if isinstance(existing, (tuple, list)) else existing["id"]))
        else:
            self._conn.execute(
                "INSERT INTO network_posture (category, check_name, status, value, "
                "risk, description, details_json, scope_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (category, check_name, status, value, risk, description, dj, scope_id))

    def query_network_posture(self, page=1, per_page=50, category=None,
                              search=None, scope_id=None, **_kw):
        where, params = [], []
        if category:
            where.append("category = ?"); params.append(category)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if search:
            where.append("(check_name LIKE ? OR description LIKE ?)")
            params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM network_posture {w}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM network_posture {w} ORDER BY category, check_name "
                "LIMIT ? OFFSET ?",
                params + [per_page, (page - 1) * per_page]).fetchall()
            cols = self._cols("network_posture")
        except Exception:
            return {"items": [], "total": 0, "page": page, "pages": 0}
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    def add_posture_subnet(self, cidr, host_count=0, open_hosts=0,
                           filtered_hosts=0, closed_hosts=0, segmented=0,
                           scope_id=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO network_posture_subnets "
            "(cidr, host_count, open_hosts, filtered_hosts, closed_hosts, "
            "segmented, scope_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cidr, host_count, open_hosts, filtered_hosts, closed_hosts,
             segmented, scope_id))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_posture_host(self, subnet_id, ip, hostname=None, posture=None,
                         open_port_count=0, port_open=0, port_closed=0,
                         port_filtered=0, port_scanned=0):
        self._conn.execute(
            "INSERT INTO network_posture_hosts "
            "(subnet_id, ip, hostname, posture, open_port_count, "
            "port_open, port_closed, port_filtered, port_scanned) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (subnet_id, ip, hostname, posture, open_port_count,
             port_open, port_closed, port_filtered, port_scanned))

    def bulk_insert_posture(self, subnets, scope_id=None):
        for s in subnets:
            sid = self.add_posture_subnet(
                s["cidr"], s.get("host_count", 0),
                s.get("open_hosts", 0), s.get("filtered_hosts", 0),
                s.get("closed_hosts", 0), s.get("segmented", 0), scope_id)
            for h in s.get("hosts", []):
                self.add_posture_host(
                    sid, h["ip"], h.get("hostname"), h.get("posture"),
                    h.get("open_port_count", 0), h.get("open", h.get("port_open", 0)),
                    h.get("closed", h.get("port_closed", 0)),
                    h.get("filtered", h.get("port_filtered", 0)),
                    h.get("scanned", h.get("port_scanned", 0)))
        self._commit()

    # ==================================================================
    #  CRUD — Hostname Intel
    # ==================================================================

    def add_hostname_intel(self, hostname, ip=None, environment_tag=None,
                           application_tag=None, hardware_tag=None,
                           role_tag=None, confidence=0.0, scope_id=None):
        self._conn.execute(
            "INSERT INTO hostname_intel (hostname, ip, "
            "environment_tag, application_tag, hardware_tag, role_tag, "
            "confidence, scope_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(hostname) DO UPDATE SET "
            "ip              = COALESCE(excluded.ip,              ip), "
            "environment_tag = COALESCE(excluded.environment_tag, environment_tag), "
            "application_tag = COALESCE(excluded.application_tag, application_tag), "
            "hardware_tag    = COALESCE(excluded.hardware_tag,    hardware_tag), "
            "role_tag        = COALESCE(excluded.role_tag,        role_tag), "
            "confidence      = CASE WHEN excluded.confidence > confidence "
            "                       THEN excluded.confidence ELSE confidence END, "
            "scope_id        = COALESCE(excluded.scope_id,        scope_id)",
            (hostname, ip, environment_tag, application_tag, hardware_tag,
             role_tag, confidence, scope_id))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_hostname_intel(self, page=1, per_page=50, environment_tag=None,
                             role_tag=None, search=None, scope_id=None,
                             sort="id", order="asc", **_kw):
        where, params = [], []
        if environment_tag:
            where.append("environment_tag = ?"); params.append(environment_tag)
        if role_tag:
            where.append("role_tag = ?"); params.append(role_tag)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if search:
            where.append("(hostname LIKE ? OR ip LIKE ?)")
            params.extend([f"%{search}%"] * 2)
        return self._paginated("hostname_intel", where, params, sort, order,
                               page, per_page, self._HOSTNAME_INTEL_COLS)

    def count_hostname_intel(self, environment_tag=None, scope_id=None):
        where, params = [], []
        if environment_tag:
            where.append("environment_tag = ?"); params.append(environment_tag)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM hostname_intel {w}", params).fetchone()[0]

    # ==================================================================
    #  CRUD — Server Roles
    # ==================================================================

    def add_server_role(self, ip, role, confidence=0.0, evidence=None,
                        hostname=None, scope_id=None):
        self._conn.execute(
            "INSERT INTO server_roles (ip, hostname, role, "
            "confidence, evidence, scope_id) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, role) DO UPDATE SET "
            "hostname   = COALESCE(excluded.hostname,   hostname), "
            "confidence = CASE WHEN excluded.confidence > confidence "
            "                  THEN excluded.confidence ELSE confidence END, "
            "evidence   = COALESCE(excluded.evidence,   evidence), "
            "scope_id   = COALESCE(excluded.scope_id,   scope_id)",
            (ip, hostname, role, confidence, evidence, scope_id))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_server_roles(self, page=1, per_page=50, ip=None, role=None,
                           search=None, scope_id=None,
                           sort="id", order="asc", **_kw):
        where, params = [], []
        if ip:
            where.append("ip = ?"); params.append(ip)
        if role:
            where.append("role = ?"); params.append(role)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        if search:
            where.append("(ip LIKE ? OR role LIKE ? OR evidence LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        return self._paginated("server_roles", where, params, sort, order,
                               page, per_page, self._SERVER_ROLES_COLS)

    def count_server_roles(self, ip=None, scope_id=None):
        where, params = [], []
        if ip:
            where.append("ip = ?"); params.append(ip)
        if scope_id is not None:
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM server_roles {w}", params).fetchone()[0]

    # ==================================================================
    #  CRUD — Domain Intel
    # ==================================================================

    def add_domain_intel(self, domain_name, source, domain_type="",
                         netbios_name="", dns_name="", dns_tree="",
                         sid="", source_ip="", source_port=0,
                         computer_name="", hostname="", is_dc=False,
                         evidence="", **_kw):
        self._conn.execute(
            "INSERT OR REPLACE INTO domain_intel "
            "(domain_name, domain_type, netbios_name, dns_name, dns_tree, "
            "sid, source_ip, source_port, computer_name, hostname, is_dc, "
            "source, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (domain_name, domain_type, netbios_name, dns_name, dns_tree,
             sid, source_ip, int(source_port or 0), computer_name,
             hostname, 1 if is_dc else 0, source, evidence))

    def bulk_insert_domain_intel(self, rows):
        for row in rows:
            self.add_domain_intel(**row)

    def query_domain_intel(self, page=1, per_page=50, domain_name=None,
                           source_ip=None, is_dc=None, search=None,
                           scope_id=None, sort="id", order="asc", **_kw):
        where, params = [], []
        if domain_name:
            where.append("domain_name = ?"); params.append(domain_name)
        if source_ip:
            where.append("source_ip = ?"); params.append(source_ip)
        if is_dc is not None:
            where.append("is_dc = ?"); params.append(1 if is_dc else 0)
        if search:
            where.append("(domain_name LIKE ? OR dns_name LIKE ? "
                         "OR computer_name LIKE ? OR hostname LIKE ?)")
            params.extend([f"%{search}%"] * 4)
        return self._paginated("domain_intel", where, params, sort, order,
                               page, per_page, self._DOMAIN_INTEL_COLS)

    # ==================================================================
    #  CRUD — Screenshots
    # ==================================================================

    def add_screenshot(self, tool, file_path, url=None, ip=None, port=None,
                       hostname=None, thumbnail_path=None, width=None,
                       height=None, file_size=None, title=None, server=None,
                       status_code=None, description=None,
                       classification=None, scheme=None, page_title=None,
                       scope=None, captured_at=None):
        self._conn.execute(
            "INSERT INTO screenshots (tool, file_path, url, ip, port, hostname, "
            "thumbnail_path, width, height, file_size, title, server, "
            "status_code, description, classification, scheme, page_title, "
            "scope, captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tool, file_path, url, ip, port, hostname, thumbnail_path,
             width, height, file_size, title, server, status_code,
             description, classification, scheme, page_title, scope,
             captured_at or datetime.now().isoformat()))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_screenshots(self, page=1, per_page=50, tool=None, ip=None,
                          hostname=None, search=None, scope=None,
                          sort="id", order="desc", **_kw):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if ip:
            where.append("ip = ?"); params.append(ip)
        if hostname:
            where.append("hostname = ?"); params.append(hostname)
        if scope:
            where.append("scope = ?"); params.append(scope)
        if search:
            where.append("(url LIKE ? OR hostname LIKE ? OR title LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        return self._paginated("screenshots", where, params, sort, order,
                               page, per_page, self._SCREENSHOTS_COLS)

    def count_screenshots(self, tool=None, scope=None):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if scope:
            where.append("scope = ?"); params.append(scope)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM screenshots {w}", params).fetchone()[0]

    # ==================================================================
    #  CRUD — OSINT tables (pass-through to FindingsDB for now)
    # ==================================================================

    def add_osint_domain(self, domain, registrar=None, creation_date=None,
                         expiry_date=None, nameservers=None, status=None,
                         dnssec=False, source=None):
        ns_json = json.dumps(nameservers or [])
        self._conn.execute(
            "INSERT INTO osint_domains (domain, registrar, creation_date, "
            "expiry_date, nameservers_json, status, dnssec) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(domain) DO UPDATE SET "
            "registrar     = COALESCE(excluded.registrar,     registrar), "
            "creation_date = COALESCE(excluded.creation_date, creation_date), "
            "expiry_date   = COALESCE(excluded.expiry_date,   expiry_date), "
            "nameservers_json = CASE WHEN excluded.nameservers_json IN ('[]','null',NULL) "
            "                        THEN nameservers_json ELSE excluded.nameservers_json END, "
            "status        = COALESCE(excluded.status,        status), "
            "dnssec        = CASE WHEN excluded.dnssec = 1 THEN 1 ELSE dnssec END",
            (domain, registrar, creation_date, expiry_date, ns_json, status, int(dnssec)))

    def query_osint_domains(self, page=1, per_page=50, search=None, **_kw):
        where, params = [], []
        if search:
            where.append("domain LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_domains {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_domains {w} ORDER BY domain LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_domains")
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    def bulk_insert_osint_domains(self, domains):
        ns = json.dumps
        self._conn.executemany(
            "INSERT INTO osint_domains (domain, registrar, creation_date, "
            "expiry_date, nameservers_json, status, dnssec) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(domain) DO UPDATE SET "
            "registrar     = COALESCE(excluded.registrar,     registrar), "
            "creation_date = COALESCE(excluded.creation_date, creation_date), "
            "expiry_date   = COALESCE(excluded.expiry_date,   expiry_date), "
            "nameservers_json = CASE WHEN excluded.nameservers_json IN ('[]','null',NULL) "
            "                        THEN nameservers_json ELSE excluded.nameservers_json END, "
            "status        = COALESCE(excluded.status,        status), "
            "dnssec        = CASE WHEN excluded.dnssec = 1 THEN 1 ELSE dnssec END",
            [(d.get("domain"), d.get("registrar"), d.get("creation_date"),
              d.get("expiry_date"), ns(d.get("nameservers", [])),
              d.get("status"), int(d.get("dnssec", False))) for d in domains])

    def query_osint_whois(self, page=1, per_page=50, domain_id=None,
                          registrant_org=None, **_kw):
        where, params = [], []
        if domain_id is not None:
            where.append("domain_id = ?"); params.append(domain_id)
        if registrant_org:
            where.append("registrant_org LIKE ?"); params.append(f"%{registrant_org}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_whois {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_whois {w} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_whois")
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_subdomains(self, page=1, per_page=50, search=None, **_kw):
        where, params = [], []
        if search:
            where.append("subdomain LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_subdomains {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_subdomains {w} ORDER BY subdomain LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_subdomains")
        return {"items": [{c: (r[i] if r[i] is not None else "") for i, c in enumerate(cols)} for r in rows],
                "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def _dns_union_base(self):
        parts = ["SELECT id, hostname, record_type, value, ttl, source, "
                 "first_seen FROM osint_dns_records"]
        if self._table_exists("dns_records"):
            parts.append(
                "SELECT id, hostname, rtype AS record_type, value, ttl, "
                "source, queried_at AS first_seen FROM dns_records")
        return " UNION ".join(parts)

    def query_osint_dns(self, page=1, per_page=50, record_type=None,
                        search=None, **_kw):
        base = self._dns_union_base()
        where, params = [], []
        if record_type:
            where.append("record_type = ?"); params.append(record_type)
        if search:
            where.append("(hostname LIKE ? OR value LIKE ?)")
            params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM ({base}) AS dns_all {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM ({base}) AS dns_all {w} ORDER BY hostname, record_type "
            f"LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = ["id", "hostname", "record_type", "value", "ttl", "source", "first_seen"]
        return {"items": [{c: (r[i] if r[i] is not None else "") for i, c in enumerate(cols)} for r in rows],
                "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def _cert_union_base(self):
        parts = ["SELECT id, domain, issuer, subject, serial_number, "
                 "not_before, not_after, san_json, fingerprint, key_size, "
                 "source, first_seen FROM osint_certificates"]
        if self._table_exists("certificates") and self._table_exists("ports") \
                and self._table_exists("hosts"):
            parts.append(
                "SELECT c.id, "
                "COALESCE(h.ip, '') AS domain, "
                "c.issuer, c.subject, c.serial AS serial_number, "
                "c.not_before, c.not_after, c.sans AS san_json, "
                "NULL AS fingerprint, c.key_bits AS key_size, "
                "'tls-inspection' AS source, NULL AS first_seen "
                "FROM certificates c "
                "JOIN ports p ON c.port_id = p.id "
                "JOIN hosts h ON p.host_id = h.id")
        return " UNION ALL ".join(parts)

    _CERT_COLS = ["id", "domain", "issuer", "subject", "serial_number",
                  "not_before", "not_after", "san_json", "fingerprint",
                  "key_size", "source", "first_seen"]

    def query_osint_certificates(self, page=1, per_page=50, search=None, **_kw):
        base = self._cert_union_base()
        where, params = [], []
        if search:
            where.append("(domain LIKE ? OR issuer LIKE ? OR subject LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM ({base}) AS cert_all {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM ({base}) AS cert_all {w} ORDER BY domain "
            f"LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        return {"items": [{c: (r[i] if r[i] is not None else "") for i, c in enumerate(self._CERT_COLS)} for r in rows],
                "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_emails(self, page=1, per_page=50, search=None, **_kw):
        where, params = [], []
        if search:
            where.append("(email LIKE ? OR name LIKE ?)")
            params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM osint_emails {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_emails {w} ORDER BY email LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_emails")
        return {"items": [{c: (r[i] if r[i] is not None else "") for i, c in enumerate(cols)} for r in rows],
                "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_breaches(self, page=1, per_page=50, email_id=None,
                             search=None, **_kw):
        base = ("FROM osint_breaches b "
                "LEFT JOIN osint_emails e ON b.email_id = e.id")
        where, params = [], []
        if email_id is not None:
            where.append("b.email_id = ?"); params.append(email_id)
        if search:
            where.append("(b.breach_name LIKE ? OR e.email LIKE ?)")
            params.extend([f"%{search}%"] * 2)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) {base}{w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT b.*, e.email AS email_address {base}{w} "
            f"ORDER BY b.breach_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in rows[0].keys()] if rows else []
        items = [{c: (r[c] if r[c] is not None else "") for c in cols} for r in rows] if rows else []
        return {"items": items, "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_people(self, page=1, per_page=50, search=None, **_kw):
        where, params = [], []
        if search:
            where.append("(name LIKE ? OR email LIKE ? OR company LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM osint_people {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_people {w} ORDER BY name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_people")
        return {"items": [{c: (r[i] if r[i] is not None else "") for i, c in enumerate(cols)} for r in rows],
                "total": total, "page": page,
                "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_phones(self, page=1, per_page=50, person_id=None,
                           phone_type=None, search=None, **_kw):
        where, params = [], []
        if person_id is not None:
            where.append("person_id = ?"); params.append(person_id)
        if phone_type:
            where.append("phone_type = ?"); params.append(phone_type)
        if search:
            where.append("phone LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_phones {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_phones {w} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_phones")
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_wayback_urls(self, page=1, per_page=50, domain=None,
                                 mime_type=None, status_code=None, **_kw):
        where, params = [], []
        if domain:
            where.append("domain = ?"); params.append(domain)
        if mime_type:
            where.append("mime_type LIKE ?"); params.append(f"%{mime_type}%")
        if status_code is not None:
            where.append("status_code = ?"); params.append(status_code)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_wayback_urls {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_wayback_urls {w} ORDER BY domain, timestamp LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_wayback_urls")
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    def query_osint_typosquats(self, page=1, per_page=50, domain=None,
                               fuzzer=None, registered=None, **_kw):
        where, params = [], []
        if domain:
            where.append("domain = ?"); params.append(domain)
        if fuzzer:
            where.append("fuzzer = ?"); params.append(fuzzer)
        if registered is not None:
            where.append("registered = ?"); params.append(int(registered))
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_typosquats {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_typosquats {w} ORDER BY domain, variant LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = self._cols("osint_typosquats")
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": max(1, (total + per_page - 1) // per_page)}

    # ══════════════════════════════════════════════════════════════════
    #  AGGREGATION / VIEW METHODS — return shapes JS renderers expect
    # ══════════════════════════════════════════════════════════════════

    # ------------------------------------------------------------------
    # 1. Structure Tree View
    #    Returns: {structure_map: {target: {paths: tree}}, api_map: {...}}
    # ------------------------------------------------------------------

    def query_structure_tree(self, scope_id=None):
        where, params = [], []
        if scope_id is not None and self._has_column("structure_urls", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        rows = self._conn.execute(
            f"SELECT * FROM structure_urls {w} ORDER BY url", params).fetchall()
        cols = self._cols("structure_urls")
        urls = [dict(zip(cols, r)) for r in rows]
        if not urls:
            return {"structure_map": {}, "api_map": {}}

        targets = defaultdict(list)
        for u in urls:
            tgt = u.get("target_url") or self._extract_origin(u.get("url", ""))
            targets[tgt].append(u)

        structure_map = {}
        api_map = {}

        for target, turls in targets.items():
            paths = {}
            for u in turls:
                parsed = urlparse(u.get("url", ""))
                path = parsed.path or "/"
                paths[path] = {
                    "status": u.get("status_code"),
                    "content_type": u.get("content_type"),
                    "source": u.get("source"),
                    "response_time_ms": u.get("response_time_ms"),
                    "redirect_to": u.get("redirect_url"),
                    "auth_only": bool(u.get("auth_required")),
                    "auth_users": self._parse_json_list(u.get("auth_roles")),
                    "rogue": bool(u.get("is_rogue")),
                    "from_spec": bool(u.get("from_spec")),
                }

                if u.get("is_rogue") or u.get("from_spec") or u.get("method", "GET") != "GET":
                    ep_path = parsed.path or "/"
                    if ep_path not in api_map:
                        api_map[ep_path] = {"methods": {}, "rogue": False, "from_spec": False}
                    am = api_map[ep_path]
                    method = u.get("method", "GET")
                    if method not in am["methods"]:
                        am["methods"][method] = {"status_codes": [], "auth_required": False}
                    mm = am["methods"][method]
                    if u.get("status_code"):
                        if u["status_code"] not in mm["status_codes"]:
                            mm["status_codes"].append(u["status_code"])
                        mm["max_status"] = max(mm.get("max_status", 0), u["status_code"])
                    if u.get("auth_required"):
                        mm["auth_required"] = True
                        mm["auth_users"] = self._parse_json_list(u.get("auth_roles"))
                    if u.get("is_rogue"):
                        am["rogue"] = True
                        mm["rogue"] = True
                    if u.get("from_spec"):
                        am["from_spec"] = True

            structure_map[target] = {"paths": paths}

        return {"structure_map": structure_map, "api_map": api_map}

    def _extract_origin(self, url):
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else url
        except Exception:
            return url

    def _parse_json_list(self, val):
        if not val:
            return []
        if isinstance(val, list):
            return val
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    # ------------------------------------------------------------------
    # 2. Access Matrix View
    #    Returns: {access_matrix: {target: {roles, most_privileged,
    #              privilege_counts, endpoints: [{path, access, access_meta}]}}}
    # ------------------------------------------------------------------

    def query_access_matrix_view(self, scope_id=None):
        where, params = [], []
        has_scope = self._has_column("access_matrix_entries", "scope_id")
        has_target = self._has_column("access_matrix_entries", "target_url")
        if scope_id is not None and has_scope:
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        order = "ORDER BY "
        order += "target_url, " if has_target else ""
        order += "endpoint_path, role"
        rows = self._conn.execute(
            f"SELECT * FROM access_matrix_entries {w} {order}", params).fetchall()
        cols = self._cols("access_matrix_entries")
        entries = [dict(zip(cols, r)) for r in rows]
        if not entries:
            return {"access_matrix": {}}

        targets = defaultdict(list)
        for e in entries:
            tgt = e.get("target_url") or "default"
            targets[tgt].append(e)

        matrix = {}
        for target, tent in targets.items():
            role_set = set()
            path_map = defaultdict(dict)
            meta_map = defaultdict(dict)
            for e in tent:
                r = e.get("role", "")
                p = e.get("endpoint_path", "")
                role_set.add(r)
                status = e.get("actual_status")
                if status is not None:
                    path_map[p][r] = status
                else:
                    result = e.get("result", "")
                    path_map[p][r] = True if result == "allowed" else (False if result == "denied" else result)
                meta_map[p][r] = {
                    "waf_blocked": bool(e.get("waf_detected")),
                    "body_denied": bool(e.get("body_denied")),
                    "_size_restricted": bool(e.get("size_restricted")),
                    "response_size": e.get("response_size"),
                    "body_class": e.get("body_class"),
                }

            roles = sorted(role_set)
            most_privileged = self._detect_most_privileged(roles, path_map)
            privilege_counts = {}
            for r in roles:
                cnt = sum(1 for p in path_map if isinstance(path_map[p].get(r), int) and 200 <= path_map[p][r] < 300)
                privilege_counts[r] = cnt

            endpoints = []
            for p in sorted(path_map.keys()):
                endpoints.append({
                    "path": p,
                    "access": path_map[p],
                    "access_meta": {r: meta_map[p].get(r, {}) for r in roles if r in meta_map[p]},
                })

            matrix[target] = {
                "roles": roles,
                "most_privileged": most_privileged,
                "privilege_counts": privilege_counts,
                "endpoints": endpoints,
            }

        return {"access_matrix": matrix}

    def _detect_most_privileged(self, roles, path_map):
        counts = {}
        for r in roles:
            counts[r] = sum(1 for p in path_map
                            if isinstance(path_map[p].get(r), int) and 200 <= path_map[p][r] < 300)
        if not counts:
            return None
        return max(counts, key=counts.get) if max(counts.values()) > 0 else None

    # ------------------------------------------------------------------
    # 3. Auth View
    #    Returns: {auth_status: [{role, username, status, session_name,
    #              cookies: [...], auth_headers: [...]}]}
    # ------------------------------------------------------------------

    def query_auth_view(self, scope_id=None):
        sessions = self._conn.execute(
            "SELECT * FROM auth_sessions WHERE id IN ("
            "  SELECT MIN(id) FROM auth_sessions "
            "  GROUP BY tool, COALESCE(role, session_name, '')"
            ") ORDER BY role, session_name"
        ).fetchall()
        cols_s = self._cols("auth_sessions")
        result = []
        for s in sessions:
            sd = dict(zip(cols_s, s))
            sid = sd["id"]
            cookies_rows = self._conn.execute(
                "SELECT * FROM auth_cookies WHERE session_id = ?",
                (sid,)).fetchall()
            cols_c = self._cols("auth_cookies")
            cookies = []
            for cr in cookies_rows:
                cd = dict(zip(cols_c, cr))
                cookies.append({
                    "name": cd.get("name", ""),
                    "value": cd.get("value", ""),
                    "domain": cd.get("domain", ""),
                    "path": cd.get("path", "/"),
                    "httpOnly": bool(cd.get("httponly")),
                    "secure": bool(cd.get("secure")),
                    "sameSite": cd.get("samesite", ""),
                    "expires": cd.get("expires_at", ""),
                })

            if sd.get("auth_type") == "unauthenticated":
                status = "unauthenticated"
            elif sd.get("valid"):
                status = "success"
            elif sd.get("valid") is None:
                status = ""
            else:
                status = "failed"
            auth_headers = []
            if sd.get("auth_type") in ("bearer", "basic", "apikey"):
                auth_headers.append({
                    "type": sd["auth_type"],
                    "preview": sd.get("token_preview", ""),
                })

            result.append({
                "role": sd.get("role") or sd.get("session_name", ""),
                "username": sd.get("username", ""),
                "status": status,
                "session_name": sd.get("session_name", ""),
                "cookies": cookies,
                "auth_headers": auth_headers,
            })

        return {"auth_status": result}

    # ------------------------------------------------------------------
    # 4. Cookies View
    #    Returns: {cookies: {all, site_wide, per_role, stats}}
    # ------------------------------------------------------------------

    def query_cookies_view(self, scope_id=None):
        where, params = [], []
        if scope_id is not None and self._has_column("cookies", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            rows = self._conn.execute(
                f"SELECT * FROM cookies {w} ORDER BY domain, name", params
            ).fetchall()
        except Exception:
            rows = []
        cols = self._cols("cookies")
        cookies = [dict(zip(cols, r)) for r in rows]
        if not cookies:
            return {"cookies": {"all": [], "site_wide": [], "per_role": {}, "stats": {}}}

        all_ck = []
        role_buckets = defaultdict(list)
        name_roles = defaultdict(set)
        mis_http = mis_sec = mis_ss = 0

        for c in cookies:
            ck = {
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "httpOnly": bool(c.get("httponly")),
                "secure": bool(c.get("secure")),
                "sameSite": c.get("samesite", ""),
                "expires": c.get("expires_at", ""),
                "roles": [],
            }
            if not c.get("httponly"):
                mis_http += 1
            if not c.get("secure"):
                mis_sec += 1
            if not c.get("samesite"):
                mis_ss += 1
            role = c.get("role") or ""
            if role:
                ck["roles"] = [role]
                role_buckets[role].append(ck)
            name_roles[c.get("name", "")].add(role)
            all_ck.append(ck)

        all_roles = set()
        for c in cookies:
            r = c.get("role")
            if r:
                all_roles.add(r)
        site_wide = []
        if all_roles:
            for ck in all_ck:
                if name_roles.get(ck["name"]) and name_roles[ck["name"]] >= all_roles:
                    if ck not in site_wide:
                        site_wide.append(ck)

        per_role = {}
        for role, cks in role_buckets.items():
            sw_names = {c["name"] for c in site_wide}
            per_role[role] = [c for c in cks if c["name"] not in sw_names]

        stats = {
            "total": len(all_ck),
            "site_wide": len(site_wide),
            "role_specific": sum(len(v) for v in per_role.values()),
            "missing_httponly": mis_http,
            "missing_secure": mis_sec,
            "missing_samesite": mis_ss,
        }

        return {"cookies": {"all": all_ck, "site_wide": site_wide,
                             "per_role": per_role, "stats": stats}}

    # ------------------------------------------------------------------
    # 5. WebApp Intel View
    #    Returns: {dns: {...}, infrastructure: {...}, target_profile: {...}}
    # ------------------------------------------------------------------

    def query_webapp_view(self, scope_id=None):
        where, params = [], []
        if scope_id is not None and self._has_column("webapp_intel", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            rows = self._conn.execute(
                f"SELECT * FROM webapp_intel {w} ORDER BY id", params
            ).fetchall()
        except Exception:
            rows = []
        cols = self._cols("webapp_intel")
        items = []
        for r in rows:
            item = dict(zip(cols, r))
            for jk in ("technologies", "web_structure", "frameworks",
                        "programming_languages"):
                if item.get(jk) and isinstance(item[jk], str):
                    try:
                        item[jk] = json.loads(item[jk])
                    except (json.JSONDecodeError, TypeError):
                        pass
            items.append(item)

        if not items:
            return {"dns": None, "infrastructure": {}, "target_profile": {}}

        dns = None
        infra = {}
        tp = {}
        seen_ips = set()

        for r in items:
            if r.get("hostname") or r.get("url"):
                if dns is None:
                    dns = {"hostname": "", "resolved_ips": [], "total_unique_ips": 0}
                dns["hostname"] = r.get("hostname") or ""
                if not dns["hostname"] and r.get("url"):
                    try:
                        dns["hostname"] = urlparse(r["url"]).hostname or ""
                    except Exception:
                        pass
                if r.get("ip") and r["ip"] not in seen_ips:
                    dns["resolved_ips"].append({"ip": r["ip"]})
                    seen_ips.add(r["ip"])
                dns["total_unique_ips"] = len(dns["resolved_ips"])
                if r.get("load_balancer"):
                    dns["load_balancer_detected"] = True

            if r.get("server"):
                infra["server"] = r["server"]
            if r.get("cdn"):
                infra["cdn"] = r["cdn"]
            if r.get("edge_security"):
                infra["edge_security"] = r["edge_security"]
            if r.get("waf"):
                infra["waf"] = r["waf"]
            if r.get("tls_enabled") is not None:
                infra["tls_enabled"] = bool(r["tls_enabled"])
            if r.get("tls_protocols"):
                infra["tls_protocols"] = r["tls_protocols"]
            if r.get("cert_issuer"):
                infra["cert_issuer"] = r["cert_issuer"]
            if r.get("cert_subject"):
                infra["cert_subject"] = r["cert_subject"]
            if r.get("cert_expiry"):
                infra["cert_expiry"] = r["cert_expiry"]
            if r.get("backend_ips"):
                infra["backend_ips"] = r["backend_ips"]

            if r.get("powered_by"):
                tp["server"] = r["powered_by"]
            if r.get("cms"):
                tp["cms"] = r["cms"]
            techs = r.get("technologies")
            if isinstance(techs, list) and techs:
                tp["technologies"] = techs
            frameworks = r.get("frameworks")
            if isinstance(frameworks, list) and frameworks:
                tp["frameworks"] = frameworks
            langs = r.get("programming_languages")
            if isinstance(langs, list) and langs:
                tp["programming_languages"] = langs
            if r.get("bi_tools"):
                tp["bi_tools"] = r["bi_tools"]

        return {"dns": dns, "infrastructure": infra, "target_profile": tp}

    # ------------------------------------------------------------------
    # 6. OSINT Domains View
    #    Returns: {osint_domains: [{domain, registrar, ..., whois: [...],
    #              subdomains: [...]}]}
    # ------------------------------------------------------------------

    def query_osint_domains_view(self):
        domains = self._conn.execute(
            "SELECT * FROM osint_domains ORDER BY domain").fetchall()
        cols_d = self._cols("osint_domains")
        result = []
        for d in domains:
            dd = dict(zip(cols_d, d))
            did = dd["id"]
            if dd.get("nameservers_json"):
                try:
                    dd["nameservers"] = json.loads(dd["nameservers_json"])
                except (json.JSONDecodeError, TypeError):
                    dd["nameservers"] = []
            else:
                dd["nameservers"] = []

            whois_rows = self._conn.execute(
                "SELECT * FROM osint_whois WHERE domain_id = ?", (did,)).fetchall()
            cols_w = self._cols("osint_whois")
            dd["whois"] = []
            for wr in whois_rows:
                wd = dict(zip(cols_w, wr))
                if wd.get("parsed_json"):
                    try:
                        wd["parsed"] = json.loads(wd["parsed_json"])
                    except (json.JSONDecodeError, TypeError):
                        wd["parsed"] = {}
                dd["whois"].append(wd)

            sub_rows = self._conn.execute(
                "SELECT * FROM osint_subdomains WHERE subdomain LIKE ?",
                (f"%.{dd['domain']}",)).fetchall()
            cols_s = self._cols("osint_subdomains")
            dd["subdomains"] = [dict(zip(cols_s, s)) for s in sub_rows]

            result.append(dd)

        return {"osint_domains": result}

    # ------------------------------------------------------------------
    # 7. OSINT DNS Grouped View
    #    Returns: {osint_dns: {hostname: [{type, name, value}]}}
    # ------------------------------------------------------------------

    @staticmethod
    def _dns_display_value(raw_value, record_type):
        """Extract display-friendly fields from a stored DNS value.

        Values are often stored as str(dict) from enrichment; parse
        them back and return a dict with clean per-type fields the
        renderer can format directly.
        """
        if not raw_value:
            return {"display": ""}
        v = raw_value
        if isinstance(v, str) and v.startswith("{"):
            try:
                v = json.loads(v.replace("'", '"'))
            except Exception:
                try:
                    import ast as _ast
                    v = _ast.literal_eval(v)
                except Exception:
                    return {"display": raw_value}
        if not isinstance(v, dict):
            return {"display": str(v)}
        rtype = (record_type or v.get("rtype", "")).upper()
        out = {}
        if rtype == "A" or rtype == "AAAA":
            out["display"] = v.get("address") or v.get("raw", "")
        elif rtype == "MX":
            pri = v.get("priority", "")
            exch = v.get("exchange", "")
            out["display"] = f"{exch}" if exch else v.get("raw", "")
            if pri != "":
                out["priority"] = pri
        elif rtype == "CNAME":
            out["display"] = v.get("target") or v.get("raw", "")
        elif rtype == "NS":
            out["display"] = v.get("nameserver") or v.get("raw", "")
        elif rtype == "SOA":
            out["display"] = v.get("raw", "")
            for k in ("mname", "rname", "serial", "refresh", "retry", "expire", "minimum"):
                if k in v:
                    out[k] = v[k]
        elif rtype in ("TXT", "SPF", "DMARC"):
            text = v.get("text") or v.get("raw", "")
            out["display"] = text
            txt_type = v.get("txt_type", "")
            if txt_type:
                out["txt_type"] = txt_type
            if rtype == "DMARC" or txt_type == "DMARC":
                for dk in ("dmarc_policy", "dmarc_pct", "dmarc_rua", "dmarc_ruf"):
                    if dk in v:
                        out[dk.replace("dmarc_", "")] = v[dk]
            elif rtype == "SPF" or txt_type == "SPF":
                if "spf_policy" in v:
                    out["spf_policy"] = v["spf_policy"]
        elif rtype == "SRV":
            out["display"] = v.get("target") or v.get("raw", "")
            for k in ("priority", "weight", "port"):
                if k in v:
                    out[k] = v[k]
        elif rtype == "PTR":
            out["display"] = v.get("ptrdname") or v.get("raw", "")
        else:
            out["display"] = v.get("text") or v.get("address") or v.get("raw") or str(v)
        return out

    def query_osint_dns_grouped(self):
        base = self._dns_union_base()
        rows = self._conn.execute(
            f"SELECT * FROM ({base}) AS dns_all ORDER BY hostname, record_type"
        ).fetchall()
        cols = ["id", "hostname", "record_type", "value", "ttl", "source", "first_seen"]
        grouped = defaultdict(list)
        for r in rows:
            rd = dict(zip(cols, r))
            hostname = rd.get("hostname", "unknown")
            rtype = rd.get("record_type", "")
            parsed = self._dns_display_value(rd.get("value", ""), rtype)
            entry = {
                "type": rtype,
                "name": hostname,
                "value": parsed.get("display", ""),
                "ttl": rd.get("ttl"),
            }
            extras = {k: v for k, v in parsed.items() if k != "display"}
            if extras:
                entry["details"] = extras
            grouped[hostname].append(entry)
        return {"osint_dns": dict(grouped)}

    # ------------------------------------------------------------------
    # 8. Network Posture View
    #    Returns: {subnets: [{cidr, host_count, open_hosts,
    #              filtered_hosts, closed_hosts, segmented,
    #              hosts: [{ip, hostname, posture, open, closed,
    #              filtered, scanned}]}],
    #              subnet_count, segmented_count}
    # ------------------------------------------------------------------

    def query_network_posture_view(self, scope_id=None):
        where, params = [], []
        if scope_id is not None and self._has_column("network_posture_subnets", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        try:
            subnets = self._conn.execute(
                f"SELECT * FROM network_posture_subnets {w} ORDER BY cidr",
                params).fetchall()
        except sqlite3.OperationalError:
            return {"subnets": [], "subnet_count": 0, "segmented_count": 0}
        cols_s = self._cols("network_posture_subnets")
        result = []
        seg_count = 0
        for s in subnets:
            sd = dict(zip(cols_s, s))
            sid = sd["id"]
            hosts = self._conn.execute(
                "SELECT * FROM network_posture_hosts WHERE subnet_id = ? "
                "ORDER BY ip", (sid,)).fetchall()
            cols_h = self._cols("network_posture_hosts")
            host_list = []
            for h in hosts:
                hd = dict(zip(cols_h, h))
                host_list.append({
                    "ip": hd.get("ip", ""),
                    "hostname": hd.get("hostname", ""),
                    "posture": hd.get("posture", ""),
                    "open_port_count": hd.get("open_port_count", 0),
                    "open": hd.get("port_open", 0),
                    "closed": hd.get("port_closed", 0),
                    "filtered": hd.get("port_filtered", 0),
                    "scanned": hd.get("port_scanned", 0),
                })
            if sd.get("segmented"):
                seg_count += 1
            result.append({
                "cidr": sd.get("cidr", ""),
                "host_count": sd.get("host_count", 0),
                "open_hosts": sd.get("open_hosts", 0),
                "filtered_hosts": sd.get("filtered_hosts", 0),
                "closed_hosts": sd.get("closed_hosts", 0),
                "segmented": bool(sd.get("segmented")),
                "hosts": host_list,
            })

        return {
            "subnets": result,
            "subnet_count": len(result),
            "segmented_count": seg_count,
        }

    # ------------------------------------------------------------------
    # 9. Hostname Intel View
    #    Returns: {hosts: [...], summary: {environments/applications/
    #              hardware_models depending on kind}}
    # ------------------------------------------------------------------

    def query_hostname_intel_view(self, scope_id=None, kind=None):
        where, params = [], []
        if scope_id is not None and self._has_column("hostname_intel", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        rows = self._conn.execute(
            f"SELECT * FROM hostname_intel {w} ORDER BY hostname", params
        ).fetchall()
        cols = self._cols("hostname_intel")
        hosts = [dict(zip(cols, r)) for r in rows]
        summary = self._build_hostname_summary(hosts, kind)
        return {"hosts": hosts, "summary": summary}

    def _build_hostname_summary(self, hosts, kind=None):
        envs = defaultdict(int)
        apps = defaultdict(int)
        hw = defaultdict(int)
        for h in hosts:
            e = h.get("environment_tag")
            a = h.get("application_tag")
            hw_tag = h.get("hardware_tag")
            if e:
                envs[e] += 1
            if a:
                apps[a] += 1
            if hw_tag:
                hw[hw_tag] += 1
        result = {}
        if kind in (None, "env"):
            result["environments"] = dict(envs)
        if kind in (None, "apps"):
            result["applications"] = dict(apps)
        if kind in (None, "hw"):
            result["hardware_models"] = dict(hw)
        return result

    # ------------------------------------------------------------------
    # 10. Server Roles View
    #     Returns: {roles: [...], summary: {role_counts: {...}}}
    # ------------------------------------------------------------------

    def query_server_roles_view(self, scope_id=None):
        where, params = [], []
        if scope_id is not None and self._has_column("server_roles", "scope_id"):
            where.append("scope_id = ?"); params.append(scope_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        rows = self._conn.execute(
            f"SELECT * FROM server_roles {w} ORDER BY role, ip", params
        ).fetchall()
        cols = self._cols("server_roles")
        roles = [dict(zip(cols, r)) for r in rows]
        role_counts = defaultdict(int)
        for r in roles:
            role_counts[r.get("role", "")] += 1
        return {"roles": roles, "summary": {"role_counts": dict(role_counts)}}
