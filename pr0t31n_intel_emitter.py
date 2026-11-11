"""Shared helper for writing intelligence data to DB and emitting tokens.

Every pr0t31n tool writes to its own findings.db FIRST, then JSON as a
secondary copy, and emits __CRUCIBLE_INTEL__ tokens when managed for
real-time Crucible UI updates.

Usage:
    try:
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_intel_emitter as _ie
    except ImportError:
        _ie = None

    # Initialize with a FindingsDB handle (required for DB writes)
    if _ie:
        _ie.init_db(fdb_handle)

    # Single item — writes to DB first, then emits token if managed
    if _ie:
        _ie.emit_intel("software", {"software": "Apache", "version": "2.4.51",
                                     "ip": "10.0.0.1", "port": 80})

    # Bulk items
    if _ie:
        _ie.emit_intel("dns_record", rows, bulk=True)
"""

import json
import os
import inspect

_CRUCIBLE_MANAGED = os.environ.get("CRUCIBLE_MANAGED") == "1"

_PREFIX = "__CRUCIBLE_INTEL__:"

_db = None


_DB_METHOD_MAP = {
    "software":       ("bulk_insert_network_software", "bulk_insert_network_software"),
    "server_role":    ("add_server_role",              None),
    "hostname_intel": ("add_hostname_intel",           None),
    "certificate":    ("add_certificate",              None),
    "dns_record":     ("add_dns_record",               None),
    "host":           ("ensure_host",                  None),
    "port":           ("add_port",                     None),
    "service":        ("add_service",                  None),
    "email":          ("add_email",                    None),
    "subdomain":      ("add_subdomain",                None),
    "endpoint":       ("add_endpoint",                 None),
    "screenshot":     ("add_screenshot",               None),
    "network_posture":   ("add_network_posture",       "bulk_insert_network_posture"),
    "cookie":            ("add_cookie",                "bulk_insert_cookies"),
    "webapp_intel":      ("add_webapp_intel",          "bulk_insert_webapp_intel"),
    "api_inventory":     ("add_api_inventory",         "bulk_insert_api_inventory"),
    "firewall_config":   ("add_firewall_config",       "bulk_insert_firewall_config"),
    "endpoint_overview": ("add_endpoint_overview",     "bulk_insert_endpoint_overview"),
    "endpoint_network":  ("add_endpoint_network",      "bulk_insert_endpoint_network"),
    "endpoint_disk":     ("add_endpoint_disk",         "bulk_insert_endpoint_disk"),
    "endpoint_hardware": ("add_endpoint_hardware",     "bulk_insert_endpoint_hardware"),
    "wireless_network":  ("add_wireless_network",      None),
    "osint_domain":      ("add_osint_domain",          "bulk_insert_osint_domains"),
    "osint_whois":       ("add_osint_whois",           "bulk_insert_osint_whois"),
    "osint_phone":       ("add_osint_phone",           "bulk_insert_osint_phones"),
    "osint_wayback":     ("add_osint_wayback_url",     "bulk_insert_osint_wayback_urls"),
    "osint_typosquat":   ("add_osint_typosquat",       "bulk_insert_osint_typosquats"),
    "osint_breach":      ("add_osint_breach",          "bulk_insert_osint_breaches"),
    "osint_person":      ("add_osint_person",          "bulk_insert_osint_people"),
    "firewall_rule":     ("add_firewall_rule",         "bulk_insert_firewall_rules"),
    "firewall_zone":     ("add_firewall_zone",         "bulk_insert_firewall_zones"),
    "firewall_compliance": ("add_firewall_compliance", "bulk_insert_firewall_compliance"),
    "cloud_resource":    ("add_cloud_resource",        "bulk_insert_cloud_resources"),
    "cloud_iam_policy":  ("add_cloud_iam_policy",      "bulk_insert_cloud_iam_policies"),
    "cloud_iam_role":    ("add_cloud_iam_role",        "bulk_insert_cloud_iam_roles"),
    "cloud_service":     ("add_cloud_service",         "bulk_insert_cloud_services"),
    "traffic_conversation": ("add_traffic_conversation", "bulk_insert_traffic_conversations"),
    "traffic_summary":   ("add_traffic_summary",       "bulk_insert_traffic_summary"),
    "db_schema":         ("add_db_schema",             "bulk_insert_db_schemas"),
    "db_table":          ("add_db_table",              "bulk_insert_db_tables"),
    "db_column":         ("add_db_column",             "bulk_insert_db_columns"),
    "db_privilege":      ("add_db_privilege",           "bulk_insert_db_privileges"),
}


def init_db(db_handle):
    """Set the FindingsDB handle for direct DB writes.

    Call this once after creating a FindingsDB instance. The emitter
    will then write all intelligence data to DB first, regardless of
    whether the tool is running under Crucible management.
    """
    global _db
    _db = db_handle


def _safe_call(method, row):
    """Call a DB method with a dict, filtering to accepted params."""
    try:
        sig = inspect.signature(method)
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            method(**row)
        else:
            accepted = {k: v for k, v in row.items()
                        if k in params and k != "self"}
            method(**accepted)
    except Exception:
        pass


def _write_to_db(intel_type, data, bulk):
    """Write intelligence data to the local FindingsDB."""
    if not _db:
        return
    mapping = _DB_METHOD_MAP.get(intel_type)
    if not mapping:
        return
    single_name, bulk_name = mapping
    rows = data if bulk else [data]

    if bulk and bulk_name and hasattr(_db, bulk_name):
        try:
            getattr(_db, bulk_name)(rows)
            return
        except Exception:
            pass

    if single_name and hasattr(_db, single_name):
        method = getattr(_db, single_name)
        for row in rows:
            if isinstance(row, dict):
                _safe_call(method, row)


def emit_intel(intel_type: str, data, *, bulk: bool = False) -> bool:
    """Write intelligence data to DB first, then emit token if managed.

    Args:
        intel_type: Subtype string (e.g. "software", "dns_record").
        data: A dict (single) or list of dicts (bulk).
        bulk: If True, data must be a list.

    Returns:
        True if data was processed, False if skipped (no data).
    """
    if data is None:
        return False
    if bulk and not isinstance(data, list):
        return False
    if not bulk and not isinstance(data, dict):
        return False

    _write_to_db(intel_type, data, bulk)

    if _CRUCIBLE_MANAGED:
        payload = {"type": intel_type, "data": data}
        if bulk:
            payload["bulk"] = True
        try:
            line = json.dumps(payload, ensure_ascii=False, default=str)
            print(f"{_PREFIX}{line}", flush=True)
        except Exception:
            pass

    return True


def emit_intel_single(intel_type: str, **kwargs) -> bool:
    """Convenience: emit a single intel item from keyword args."""
    return emit_intel(intel_type, kwargs)


def is_managed() -> bool:
    """Return True if running under Crucible management."""
    return _CRUCIBLE_MANAGED
