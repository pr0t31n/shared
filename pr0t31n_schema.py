"""
pr0t31n_schema.py — Universal output schema (v1.0) for all pr0t31n tools.

See /Users/pr0t31n/pr0t31n_universal_directory_structure.docx for the full
specification. This module is the single source of truth for:

  - schema version constant
  - tool name registry
  - required + optional field lists for meta.json / findings.json / summary.json
  - constructors that build correctly-shaped dicts
  - validators that report schema violations
  - atomic writers (meta / summary / findings append)
  - dual-write helper (writes new + legacy filenames during migration)
  - run-directory path builder (clients_base aware)
  - run-dir-relative output_file helper

Distribution: VENDORED. Each tool copies this file into its own repo
(matching the existing _auth.py pattern). The canonical copy lives at
/opt/pr0t31n/shared/pr0t31n_schema.py — copy it into your tool and import
locally. Bug fixes propagate to every tool's vendored copy.

stdlib only. No third-party imports.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


# ───────────────────────────────────────────────────────────────────────────
# Schema version & constants
# ───────────────────────────────────────────────────────────────────────────
SCHEMA_VERSION = "1.4"

RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
RISK_RANK   = {r: i for i, r in enumerate(("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))}

TOOL_NAMES = (
    "scattershot3", "fracture", "siphon", "gearbox", "aether",
    "auger", "osift", "bastion", "authprobe", "pain",
    "aether_b", "aether_z", "aether_u", "forge", "quill", "isotope",
    "trawler", "nessus",
)

TOOL_DIR_NAMES = {
    "ss3": "scattershot", "scattershot3": "scattershot",
    "osift": "osift", "trawler": "trawler",
    "fracture": "fracture", "siphon": "siphon", "auger": "auger",
    "aether": "aether", "aether_b": "aether_b",
    "aether_z": "aether_z", "aether_u": "aether_u",
    "bastion": "bastion", "forge": "forge", "quill": "quill",
    "isotope": "isotope", "nessus": "nessus",
    "gearbox": "gearbox", "authprobe": "authprobe", "pain": "pain",
}

SCOPE_KEYS = (
    "external", "internal", "webapp", "api", "osint", "database",
    "pcap", "wifi", "bluetooth", "zigbee", "uwb",
    "firewall", "cloud", "mobile", "file",
)

SCOPE_DISPLAY_NAMES = {
    "external": "External", "internal": "Internal",
    "webapp": "Web Application", "api": "API",
    "osint": "OSINT", "database": "Database",
    "pcap": "PCAP Analysis",
    "wifi": "Wi-Fi (802.11)", "bluetooth": "Bluetooth (802.15.1)",
    "zigbee": "Zigbee (802.15.4)", "uwb": "Ultra-Wideband (UWB) (802.15.4z)",
    "firewall": "Firewall Config Analysis",
    "cloud": "Cloud Infrastructure",
    "mobile": "Mobile Application", "file": "File Analysis",
}

SCOPE_TOOL_DEFAULTS = {
    "external": ["ss3"],
    "internal": ["ss3"],
    "webapp":   ["fracture"],
    "api":      ["siphon"],
    "osint":    ["osift"],
    "database": ["auger"],
    "pcap":     ["trawler"],
    "wifi":     ["aether"],
    "bluetooth": ["aether_b"],
    "zigbee":   ["aether_z"],
    "uwb":      ["aether_u"],
    "firewall": ["bastion"],
    "cloud":    ["forge"],
    "mobile":   ["quill"],
    "file":     ["isotope"],
}

TOOL_NATIVE_SCOPES = {
    "ss3": "external", "fracture": "webapp", "siphon": "api",
    "osift": "osint", "trawler": "pcap", "auger": "database",
    "aether": "wifi", "aether_b": "bluetooth",
    "aether_z": "zigbee", "aether_u": "uwb",
    "bastion": "firewall", "forge": "cloud",
    "quill": "mobile", "isotope": "file",
}

META_REQUIRED_FIELDS = (
    "tool", "version", "schema_version", "client_short", "client_name",
    "engagement_name", "target", "scan_start", "hostname",
)
META_OPTIONAL_FIELDS = ("scopes", "operator", "notes")

FINDING_REQUIRED_FIELDS = (
    "id", "tool", "title", "datetime", "ip", "port", "risk",
    "command", "description", "sources", "affected", "remediation",
    "exploitdb", "metasploit", "exploit_details",
)
FINDING_OPTIONAL_FIELDS = (
    "hostname", "scope", "phase", "catalogue_id", "output",
    "output_file", "cves", "service", "owasp", "owasp_url", "nist",
    # v1.2 addition — impact narrative (description is REQUIRED, see required list)
    "impact",
    # ── v1.1 additions — producer-knowable + catalogue-enrichable ─────────
    # CVSS (producer-known by Aether/Gearbox/Bastion; also catalogue-driven)
    "cvss_score", "cvss_vector",
    # CWE list
    "cwe",
    # External scanner mappings (Nessus/Qualys interop)
    "nessus_plugin_id", "nessus_plugin_name", "qualys_qid", "plugin_output",
    # Compliance frameworks as lists (universal v1.0 had only scalar 'nist')
    "nist_800_53", "nist_800_171", "nist_csf2",
    "pci_dss_4", "iso_27001", "iso_27002",
    "soc2", "hitrust", "gdpr",
    # Threat intelligence
    "mitre_attack", "kev",
    # Exploit refs as lists (distinct from bool exploitdb/metasploit flags)
    "searchsploit_terms", "metasploit_modules",
    # Granular remediation
    "remediation_effort", "remediation_component", "remediation_category",
    # OWASP split — owasp_api is distinct from owasp (web/general)
    "owasp_api",
    # Tool-specific producer-known fields
    "ssid", "bssid", "wireless_data",
    "subdevice", "interface", "instance", "classification",
    "api_endpoint_path", "api_method", "api_from_spec", "is_rogue_endpoint",
    # Workflow state
    "accepted", "confidence",
    # Catalogue lineage
    "aliases", "source_tools", "cve_examples",
)

SUMMARY_REQUIRED_FIELDS = (
    "tool", "version", "scan_start", "scan_end", "duration_seconds",
    "hostname", "target", "success", "total_findings", "risk_counts",
)

REQUIRED_RUN_FILES = (
    "meta.json", "findings.json", "summary.json",
    "scan.log", "scan.log.json", "errors.log",
)


# ───────────────────────────────────────────────────────────────────────────
# Path helpers
# ───────────────────────────────────────────────────────────────────────────
def clients_base() -> Path:
    """Platform-aware clients root. Override with PR0T31N_CLIENTS_BASE env."""
    env = os.environ.get("PR0T31N_CLIENTS_BASE")
    if env:
        return Path(env)
    if sys.platform.startswith("linux"):
        return Path("/clients")
    if sys.platform == "darwin":
        return Path("/Users/Shared/clients")
    if sys.platform.startswith("win"):
        return Path(r"C:\clients")
    return Path.home() / "clients"


def universal_run_dir(client_short: str, tool: str,
                      year: "int | str | None" = None,
                      ts: "str | None" = None,
                      base: "Path | None" = None) -> Path:
    """
    Build the canonical run-directory path:
      <base>/<client_short>/<year>/<tool>/<client_short>_<YYYYMMDD_HHMMSS>/
    """
    if base is None:
        base = clients_base()
    if year is None:
        year = datetime.now().year
    if ts is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(base) / client_short / str(year) / tool / f"{client_short}_{ts}"


def to_relative_output_file(abs_path: "str | Path", run_dir: "str | Path") -> str:
    """Convert an absolute evidence file path to run-dir-relative for finding['output_file'].
    Already-relative paths without '..' are returned unchanged."""
    s = str(abs_path).strip()
    if not s:
        return ""
    if not Path(s).is_absolute():
        if ".." not in s:
            return s.replace(os.sep, "/")
    abs_p = Path(abs_path).resolve()
    rd    = Path(run_dir).resolve()
    try:
        return str(abs_p.relative_to(rd)).replace(os.sep, "/")
    except ValueError:
        return s.replace(os.sep, "/")


# ───────────────────────────────────────────────────────────────────────────
# Engagement directory helpers (v2.0 layout)
# ───────────────────────────────────────────────────────────────────────────
def engagement_dir(client_short: str, year: "int | str",
                   engagement_id: str,
                   base: "Path | None" = None) -> Path:
    """Build engagement root: <base>/<client>/<year>/<engagement_id>/"""
    if base is None:
        base = clients_base()
    return Path(base) / client_short / str(year) / engagement_id


def scope_tool_dir(eng_dir: "str | Path", scope: str, tool: str) -> Path:
    """Build tool output dir under a scope: <eng>/<scope>/<tool_dirname>/"""
    tool_dirname = TOOL_DIR_NAMES.get(tool, tool)
    return Path(eng_dir) / scope / tool_dirname


def create_engagement(client_short: str, year: "int | str",
                      ts: "str | None" = None,
                      base: "Path | None" = None) -> "tuple[Path, str]":
    """Create engagement root directory. Returns (path, engagement_id)."""
    if ts is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    eid = f"{client_short}_{ts}"
    eng = engagement_dir(client_short, str(year), eid, base=base)
    eng.mkdir(parents=True, exist_ok=True)
    return eng, eid


def write_engagement_json(eng_dir: "str | Path", data: dict) -> None:
    """Write engagement.json at the engagement root."""
    atomic_write_json(Path(eng_dir) / "engagement.json", data)


def make_engagement_json(*, engagement_id: str, client_name: str,
                         client_short: str, engagement_name: str,
                         year: str, active_scopes: list,
                         scope_tools: dict, tools: list,
                         **kwargs) -> dict:
    """Build a valid engagement.json dict."""
    eng = {
        "schema_version": "2.0",
        "engagement_id":  engagement_id,
        "created_at":     now_iso(),
        "updated_at":     now_iso(),
        "client": {
            "name":  client_name,
            "short": client_short,
        },
        "engagement": {
            "name": engagement_name,
            "year": str(year),
        },
        "active_scopes": list(active_scopes),
        "scope_tools":   dict(scope_tools),
        "tools":         list(tools),
    }
    for k in ("client_industry", "client_contact"):
        if kwargs.get(k):
            eng["client"][k.replace("client_", "")] = kwargs[k]
    for k in ("type", "start_date", "end_date", "authorization"):
        if kwargs.get(k):
            eng["engagement"][k] = kwargs[k]
    for k in ("consultant", "poc", "scope_definition", "tool_settings",
              "management_app", "management_app_version"):
        if kwargs.get(k):
            eng[k] = kwargs[k]
    return eng


def create_scope_dir(eng_dir: "str | Path", scope: str,
                     targets: "list | None" = None) -> Path:
    """Create scope directory with scope_meta.json. Returns the scope path."""
    sd = Path(eng_dir) / scope
    sd.mkdir(parents=True, exist_ok=True)
    meta = {
        "schema_version": "2.0",
        "scope_key":      scope,
        "scope_display":  SCOPE_DISPLAY_NAMES.get(scope, scope),
        "created_at":     now_iso(),
        "updated_at":     now_iso(),
        "targets":        list(targets or []),
        "tools":          {},
        "finding_count":  0,
        "risk_summary":   {r: 0 for r in RISK_LEVELS},
    }
    atomic_write_json(sd / "scope_meta.json", meta)
    return sd


def create_scope_tool_dir(eng_dir: "str | Path", scope: str, tool: str,
                          native: bool = True,
                          source_tool: "str | None" = None,
                          source_finding: "str | None" = None,
                          override_targets: "list | None" = None) -> Path:
    """Create tool directory under a scope and init run files. Returns the path."""
    td = scope_tool_dir(eng_dir, scope, tool)
    init_run_dir(td)
    sm_path = Path(eng_dir) / scope / "scope_meta.json"
    if sm_path.exists():
        try:
            sm = json.loads(sm_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            sm = {}
        tools = sm.get("tools", {})
        entry = {"native": native, "status": "queued"}
        if not native:
            if source_tool:
                entry["source_tool"] = source_tool
            if source_finding:
                entry["source_finding"] = source_finding
            if override_targets:
                entry["override_targets"] = list(override_targets)
        tools[tool] = entry
        sm["tools"] = tools
        sm["updated_at"] = now_iso()
        atomic_write_json(sm_path, sm)
    return td


def detect_layout(path: "str | Path") -> str:
    """Detect directory layout version. Returns '2.0', '1.x', or 'unknown'."""
    p = Path(path)
    if (p / "engagement.json").exists():
        return "2.0"
    if (p / "meta.json").exists():
        return "1.x"
    return "unknown"


# ───────────────────────────────────────────────────────────────────────────
# Time helpers
# ───────────────────────────────────────────────────────────────────────────
def now_iso(utc: bool = False) -> str:
    """ISO 8601 timestamp. UTC ends in Z; local has no offset."""
    if utc:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def make_finding_id() -> str:
    return str(uuid.uuid4())


# ───────────────────────────────────────────────────────────────────────────
# Builders
# ───────────────────────────────────────────────────────────────────────────
def make_meta(*, tool: str, version: str,
              client_short: str, client_name: str, engagement_name: str,
              target: str,
              scan_start: "str | None" = None,
              hostname: "str | None" = None,
              scopes: "list | None" = None,
              operator: str = "",
              notes: str = "",
              scope: "str | None" = None,
              scope_override: bool = False,
              source_tool: str = "",
              engagement_id: str = "") -> dict:
    """Build a valid meta.json dict."""
    m = {
        "tool":            tool,
        "version":         version,
        "schema_version":  SCHEMA_VERSION,
        "client_short":    client_short,
        "client_name":     client_name,
        "engagement_name": engagement_name,
        "target":          target,
        "scopes":          list(scopes) if scopes else [],
        "scan_start":      scan_start or now_iso(utc=True),
        "hostname":        hostname or socket.gethostname(),
        "operator":        operator,
        "notes":           notes,
    }
    if scope:
        m["scope"] = scope
    if scope_override:
        m["scope_override"] = True
        if source_tool:
            m["source_tool"] = source_tool
    if engagement_id:
        m["engagement_id"] = engagement_id
    return m


def make_finding(*, tool: str, title: str, ip: str, port: int,
                 risk: str, command: str, description: str,
                 remediation: str, sources: str, affected: str,
                 datetime_str: "str | None" = None,
                 hostname: str = "", scope: "str | None" = None,
                 phase: str = "", catalogue_id: str = "",
                 output: str = "", output_file: str = "",
                 cves: str = "", service: str = "",
                 owasp: str = "", owasp_url: str = "", nist: str = "",
                 exploitdb: bool = False, metasploit: bool = False,
                 exploit_details: "list | None" = None,
                 # ── v1.1 optional enrichment fields ──────────────────────
                 cvss_score: "float | None" = None, cvss_vector: str = "",
                 cwe: "list | None" = None,
                 nessus_plugin_id: "int | None" = None,
                 nessus_plugin_name: str = "",
                 qualys_qid: "int | None" = None,
                 plugin_output: str = "",
                 nist_800_53: "list | None" = None,
                 nist_800_171: "list | None" = None,
                 nist_csf2: "list | None" = None,
                 pci_dss_4: "list | None" = None,
                 iso_27001: "list | None" = None,
                 iso_27002: "list | None" = None,
                 soc2: "list | None" = None,
                 hitrust: "list | None" = None,
                 gdpr: "list | None" = None,
                 mitre_attack: "list | None" = None,
                 kev: bool = False,
                 searchsploit_terms: "list | None" = None,
                 metasploit_modules: "list | None" = None,
                 remediation_effort: str = "",
                 remediation_component: str = "",
                 remediation_category: str = "",
                 owasp_api: str = "",
                 ssid: str = "", bssid: str = "",
                 wireless_data: "dict | None" = None,
                 subdevice: str = "", interface: str = "",
                 instance: str = "", classification: str = "",
                 api_endpoint_path: str = "", api_method: str = "",
                 api_from_spec: bool = False, is_rogue_endpoint: bool = False,
                 accepted: bool = False, confidence: str = "",
                 aliases: "list | None" = None,
                 source_tools: "list | None" = None,
                 cve_examples: "list | None" = None,
                 # v1.2 addition — impact narrative (one paragraph; attacker
                 # capability + business consequence). Distinct from description
                 # which says what the finding IS.
                 impact: str = "",
                 **_extra) -> dict:
    """Build a valid universal-schema finding dict (id + datetime auto-filled).

    Required keyword args populate the v1.0 baseline. v1.1 optional kwargs
    accept producer-known enrichment (CVSS, CWE, framework lists, MITRE,
    tool-specific wireless/api/db fields). Any unknown kwargs in **_extra
    are silently discarded — callers that need custom fields should add
    them via dict update on the returned object.
    """
    return {
        # ── v1.0 baseline ────────────────────────────────────────────────
        "id":              make_finding_id(),
        "tool":            tool,
        "title":           title,
        "datetime":        datetime_str or now_iso(),
        "ip":              ip,
        "port":            int(port) if port is not None else 0,
        "hostname":        hostname,
        "risk":            (risk or "INFO").upper(),
        "scope":           scope,
        "phase":           phase,
        "catalogue_id":    catalogue_id,
        "command":         command,
        "description":     description,
        "output":          output,
        "output_file":     output_file,
        "cves":            cves,
        "sources":         sources,
        "service":         service,
        "affected":        affected,
        "owasp":           owasp,
        "owasp_url":       owasp_url,
        "nist":            nist,
        "remediation":     remediation,
        "exploitdb":       bool(exploitdb),
        "metasploit":      bool(metasploit),
        "exploit_details": list(exploit_details or []),
        # ── v1.1 enrichment ──────────────────────────────────────────────
        "cvss_score":            cvss_score,
        "cvss_vector":           cvss_vector,
        "cwe":                   list(cwe or []),
        "nessus_plugin_id":      nessus_plugin_id,
        "nessus_plugin_name":    nessus_plugin_name,
        "qualys_qid":            qualys_qid,
        "plugin_output":         plugin_output,
        "nist_800_53":           list(nist_800_53 or []),
        "nist_800_171":          list(nist_800_171 or []),
        "nist_csf2":             list(nist_csf2 or []),
        "pci_dss_4":             list(pci_dss_4 or []),
        "iso_27001":             list(iso_27001 or []),
        "iso_27002":             list(iso_27002 or []),
        "soc2":                  list(soc2 or []),
        "hitrust":               list(hitrust or []),
        "gdpr":                  list(gdpr or []),
        "mitre_attack":          list(mitre_attack or []),
        "kev":                   bool(kev),
        "searchsploit_terms":    list(searchsploit_terms or []),
        "metasploit_modules":    list(metasploit_modules or []),
        "remediation_effort":    remediation_effort,
        "remediation_component": remediation_component,
        "remediation_category":  remediation_category,
        "owasp_api":             owasp_api,
        "ssid":                  ssid,
        "bssid":                 bssid,
        "wireless_data":         dict(wireless_data or {}),
        "subdevice":             subdevice,
        "interface":             interface,
        "instance":              instance,
        "classification":        classification,
        "api_endpoint_path":     api_endpoint_path,
        "api_method":            api_method,
        "api_from_spec":         bool(api_from_spec),
        "is_rogue_endpoint":     bool(is_rogue_endpoint),
        "accepted":              bool(accepted),
        "confidence":            confidence,
        "aliases":               list(aliases or []),
        "source_tools":          list(source_tools or []),
        "cve_examples":          list(cve_examples or []),
        "impact":                impact,
    }


def augment_finding(finding: dict, *, tool: str,
                    scope: "str | None" = None,
                    phase: str = "",
                    catalogue_id: str = "",
                    run_dir: "str | Path | None" = None) -> dict:
    """
    Ensure a finding dict carries universal-required fields. Mutates and
    returns the input dict. Existing values are NEVER overwritten — only
    missing/empty keys get filled in. Designed to be cheap and idempotent
    so tools can call it on every finding without breaking re-runs.

    Adds (if missing):
      id            — UUID4 string
      tool          — provided 'tool' argument
      scope         — provided 'scope' argument (may be None)
      phase         — provided 'phase' argument
      catalogue_id  — provided 'catalogue_id' argument
      datetime      — now_iso() if absent

    Also normalises common type coercions:
      risk → uppercase
      exploitdb, metasploit → bool
      exploit_details → list (if it was None or wrong type)
    """
    if not isinstance(finding, dict):
        return finding
    finding.setdefault("id", make_finding_id())
    if not finding.get("id"):
        finding["id"] = make_finding_id()
    finding.setdefault("tool", tool)
    if not finding.get("tool"):
        finding["tool"] = tool
    finding.setdefault("scope", scope)
    finding.setdefault("phase", phase or "")
    finding.setdefault("catalogue_id", catalogue_id or "")
    finding.setdefault("datetime", now_iso())
    if finding.get("risk"):
        finding["risk"] = str(finding["risk"]).upper()
    finding["exploitdb"]  = bool(finding.get("exploitdb", False))
    finding["metasploit"] = bool(finding.get("metasploit", False))
    if not isinstance(finding.get("exploit_details"), list):
        finding["exploit_details"] = []
    # ── v1.1: coerce optional list-type fields to lists if present-but-wrong-type ──
    # NOTE: do NOT setdefault these — empty defaults would bloat every finding.
    # Only fix the type when the field exists with a wrong type.
    for _list_field in ("cwe", "nist_800_53", "nist_800_171", "nist_csf2",
                        "pci_dss_4", "iso_27001", "iso_27002",
                        "soc2", "hitrust", "gdpr",
                        "mitre_attack", "searchsploit_terms", "metasploit_modules",
                        "aliases", "source_tools", "cve_examples"):
        if _list_field in finding and not isinstance(finding[_list_field], list):
            finding[_list_field] = []
    # v1.1: coerce bool fields if present-but-wrong-type
    for _bool_field in ("kev", "api_from_spec", "is_rogue_endpoint", "accepted"):
        if _bool_field in finding:
            finding[_bool_field] = bool(finding[_bool_field])
    # v1.1: coerce wireless_data to dict
    if "wireless_data" in finding and not isinstance(finding["wireless_data"], dict):
        finding["wireless_data"] = {}
    # 2026-06-12: cross-cutting #157 — when a run_dir is supplied,
    # rewrite output_file as run-dir-relative.  Re-running on already
    # relative paths is safe because to_relative_output_file() returns
    # the input unchanged when it doesn't reside under run_dir.
    if run_dir and finding.get("output_file"):
        try:
            finding["output_file"] = to_relative_output_file(
                finding["output_file"], run_dir)
        except Exception:
            pass
    return finding


def augment_findings_file(path: "str | Path", *, tool: str,
                          scope: "str | None" = None,
                          phase: str = "",
                          run_dir: "str | Path | None" = None) -> int:
    """
    Load <path> (a findings.json array), call augment_finding() on each entry,
    atomic-write the result back. Idempotent: re-runs are no-ops because
    augment_finding only fills MISSING/empty fields. Returns the count of
    findings augmented. Used by tools at scan completion to backfill
    universal-required fields on findings emitted by legacy code paths.

    2026-06-12 — when `run_dir` is provided, output_file paths are
    rewritten to run-dir-relative form via to_relative_output_file().
    When omitted, defaults to the parent directory of <path> (since
    findings.json conventionally lives at <run_dir>/findings.json).
    """
    p = Path(path)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0
    if not isinstance(data, list):
        return 0
    effective_run_dir = run_dir if run_dir is not None else p.parent
    for entry in data:
        augment_finding(entry, tool=tool, scope=scope, phase=phase,
                          run_dir=effective_run_dir)
    atomic_write_json(p, data)
    return len(data)


def write_universal_findings(run_dir: "str | Path", findings: list, *,
                             tool: str, scope: "str | None" = None,
                             phase: str = "") -> int:
    """
    Build a universal-schema findings.json at <run_dir>/findings.json from a
    list of dicts. Each entry is passed through augment_finding(), so callers
    can pass legacy-shape dicts and get a compliant universal output.

    2026-06-12 — output_file paths in each finding are rewritten to be
    run-dir-relative via to_relative_output_file() (cross-cutting #157).

    Returns the count of findings written.
    """
    out = []
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        out.append(augment_finding(dict(f), tool=tool, scope=scope, phase=phase,
                                      run_dir=run_dir))
    atomic_write_json(Path(run_dir) / "findings.json", out)
    return len(out)


def make_summary(*, tool: str, version: str,
                 scan_start: str, scan_end: str,
                 target: str, success: bool,
                 hostname: "str | None" = None,
                 phases_run: "list | None" = None,
                 total_findings: int = 0,
                 risk_counts: "dict | None" = None,
                 errors: "list | None" = None) -> dict:
    """Build a valid summary.json dict."""
    try:
        start_dt = datetime.fromisoformat(scan_start.rstrip("Z"))
        end_dt   = datetime.fromisoformat(scan_end.rstrip("Z"))
        duration = max(0, int((end_dt - start_dt).total_seconds()))
    except Exception:
        duration = 0
    return {
        "tool":             tool,
        "version":          version,
        "scan_start":       scan_start,
        "scan_end":         scan_end,
        "duration_seconds": duration,
        "hostname":         hostname or socket.gethostname(),
        "target":           target,
        "success":          bool(success),
        "phases_run":       list(phases_run or []),
        "total_findings":   int(total_findings),
        "risk_counts":      dict(risk_counts or {r: 0 for r in RISK_LEVELS}),
        "errors":           list(errors or []),
    }


# ───────────────────────────────────────────────────────────────────────────
# Validators (return a list of error strings; empty list = valid)
# ───────────────────────────────────────────────────────────────────────────
def validate_meta(meta: dict) -> list:
    errs = []
    if not isinstance(meta, dict):
        return ["meta is not a dict"]
    for f in META_REQUIRED_FIELDS:
        if f not in meta:
            errs.append(f"meta: missing required field '{f}'")
        elif meta[f] in (None, "") and f != "target":
            errs.append(f"meta: required field '{f}' is empty")
    if meta.get("tool") and meta["tool"] not in TOOL_NAMES:
        errs.append(f"meta: unknown tool '{meta['tool']}' (allowed: {TOOL_NAMES})")
    if meta.get("schema_version") and meta["schema_version"] != SCHEMA_VERSION:
        errs.append(f"meta: schema_version mismatch (got {meta['schema_version']}, expected {SCHEMA_VERSION})")
    return errs


def validate_finding(finding: dict) -> list:
    errs = []
    if not isinstance(finding, dict):
        return ["finding is not a dict"]
    for f in FINDING_REQUIRED_FIELDS:
        if f not in finding:
            errs.append(f"finding: missing required field '{f}'")
    risk = finding.get("risk", "")
    if risk and risk not in RISK_LEVELS:
        errs.append(f"finding: invalid risk '{risk}' (allowed: {RISK_LEVELS})")
    if not (finding.get("description") or "").strip():
        errs.append("finding: 'description' must not be empty")
    if not (finding.get("remediation") or "").strip():
        errs.append("finding: 'remediation' must not be empty")
    out = finding.get("output_file", "")
    if out:
        p = PurePosixPath(out.replace("\\", "/"))
        if p.is_absolute() or ".." in p.parts:
            errs.append(f"finding: 'output_file' must be relative and within run dir (got '{out}')")
    return errs


def validate_summary(summary: dict) -> list:
    errs = []
    if not isinstance(summary, dict):
        return ["summary is not a dict"]
    for f in SUMMARY_REQUIRED_FIELDS:
        if f not in summary:
            errs.append(f"summary: missing required field '{f}'")
    rc = summary.get("risk_counts", {})
    if not isinstance(rc, dict):
        errs.append("summary: 'risk_counts' must be a dict")
    return errs


def validate_run_dir(run_dir: "str | Path") -> dict:
    """
    Return a structured report of schema compliance issues for a run directory.
    Useful for self-checks during scan completion and for Prometheus diagnostics.
    """
    rd = Path(run_dir)
    report = {
        "run_dir":              str(rd),
        "exists":               rd.is_dir(),
        "missing_required":     [],
        "meta_errors":          [],
        "finding_errors":       {},
        "summary_errors":       [],
        "non_relative_outputs": [],
    }
    if not report["exists"]:
        return report
    for fn in REQUIRED_RUN_FILES:
        if not (rd / fn).exists():
            report["missing_required"].append(fn)
    # meta
    try:
        meta = json.loads((rd / "meta.json").read_text(encoding="utf-8"))
        report["meta_errors"] = validate_meta(meta)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        report["meta_errors"] = [f"meta.json read error: {e}"]
    # findings
    try:
        findings = json.loads((rd / "findings.json").read_text(encoding="utf-8"))
        if not isinstance(findings, list):
            report["finding_errors"]["_file"] = ["findings.json is not a JSON array"]
        else:
            for i, f in enumerate(findings):
                errs = validate_finding(f)
                if errs:
                    report["finding_errors"][f.get("id") or f"idx_{i}"] = errs
                out = (f or {}).get("output_file", "")
                if out:
                    cand = (rd / out).resolve()
                    try:
                        cand.relative_to(rd.resolve())
                    except ValueError:
                        report["non_relative_outputs"].append(out)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        report["finding_errors"]["_file"] = [f"findings.json read error: {e}"]
    # summary
    try:
        summary = json.loads((rd / "summary.json").read_text(encoding="utf-8"))
        report["summary_errors"] = validate_summary(summary)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        report["summary_errors"] = [f"summary.json read error: {e}"]
    return report


# ───────────────────────────────────────────────────────────────────────────
# Atomic writers (thread-safe)
# ───────────────────────────────────────────────────────────────────────────
_write_lock = threading.Lock()


def atomic_write_json(path: "str | Path", obj, indent: int = 2) -> None:
    """Atomic write: tmpfile + rename. Parent dirs created. Lock held."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with _write_lock:
        tmp.write_text(json.dumps(obj, indent=indent, default=str), encoding="utf-8")
        tmp.replace(p)


def write_meta(run_dir: "str | Path", meta: dict,
               legacy_filename: "str | None" = "project_meta.json") -> None:
    """
    Write meta.json. During the dual-write migration window, also writes the
    legacy_filename (default 'project_meta.json') so existing consumers
    (Crucible reading project_meta.json) continue working.
    """
    rd = Path(run_dir)
    atomic_write_json(rd / "meta.json", meta)
    if legacy_filename:
        atomic_write_json(rd / legacy_filename, meta)


def write_summary(run_dir: "str | Path", summary: dict) -> None:
    atomic_write_json(Path(run_dir) / "summary.json", summary)


def append_finding(run_dir: "str | Path", finding: dict,
                   scope: "str | None" = None,
                   legacy_paths: "list | None" = None) -> None:
    """
    Append a finding to <run_dir>/findings.json and (if scope given) to
    <run_dir>/scopes/<scope>/findings.json. legacy_paths is a list of extra
    paths to mirror-append during dual-write (e.g. tool-specific legacy
    locations like <run_dir>/int/findings.json).
    """
    rd = Path(run_dir)
    _append_to_findings_array(rd / "findings.json", finding)
    if scope:
        _append_to_findings_array(rd / "scopes" / scope / "findings.json", finding)
    for lp in (legacy_paths or []):
        _append_to_findings_array(Path(lp), finding)


def _append_to_findings_array(path: "str | Path", finding: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        try:
            current = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(current, list):
                current = []
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            current = []
        current.append(finding)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(current, indent=2, default=str), encoding="utf-8")
        tmp.replace(p)


def init_run_dir(run_dir: "str | Path") -> None:
    """Create run directory and empty required files so consumers don't crash mid-scan."""
    rd = Path(run_dir)
    rd.mkdir(parents=True, exist_ok=True)
    if not (rd / "findings.json").exists():
        atomic_write_json(rd / "findings.json", [])
    for fn in ("scan.log", "errors.log"):
        f = rd / fn
        if not f.exists():
            f.touch()
    if not (rd / "scan.log.json").exists():
        atomic_write_json(rd / "scan.log.json", [])


# ───────────────────────────────────────────────────────────────────────────
# Self-test (run: python3 pr0t31n_schema.py)
# ───────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    print(f"pr0t31n_schema v{SCHEMA_VERSION} — self-test")

    with tempfile.TemporaryDirectory() as td:
        rd = Path(td) / "acme_20260522_120000"
        init_run_dir(rd)

        meta = make_meta(
            tool="scattershot3", version="1.10.1",
            client_short="acme", client_name="ACME Corporation",
            engagement_name="ACME External Pentest 2026",
            target="10.0.0.0/24",
        )
        assert not validate_meta(meta), validate_meta(meta)
        write_meta(rd, meta)

        f = make_finding(
            tool="scattershot3",
            title="SSL/TLS Vulnerability: LUCKY13",
            ip="10.0.0.50", port=443, risk="LOW",
            command="testssl --jsonfile out.json 10.0.0.50:443",
            description="LUCKY13 timing side-channel in CBC-mode ciphers.",
            remediation="Disable CBC cipher suites; prefer TLS 1.3.",
            sources="testssl", affected="10.0.0.50:443",
            cves="CVE-2013-0169", service="https", scope="int",
            output_file="evidence/int/hosts/10.0.0.50/testssl.json",
        )
        assert not validate_finding(f), validate_finding(f)
        append_finding(rd, f, scope="int")

        summary = make_summary(
            tool="scattershot3", version="1.10.1",
            scan_start=meta["scan_start"], scan_end=now_iso(utc=True),
            target=meta["target"], success=True,
            total_findings=1,
            risk_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0},
        )
        write_summary(rd, summary)

        report = validate_run_dir(rd)
        print("validate_run_dir:", json.dumps(report, indent=2))
        assert not report["meta_errors"], report
        assert not report["finding_errors"], report
        assert not report["summary_errors"], report

    # ── engagement directory v2.0 test ──
    with tempfile.TemporaryDirectory() as td:
        eng, eid = create_engagement("acme", "2026", base=Path(td))
        assert eng.exists(), f"engagement dir not created: {eng}"
        assert eid.startswith("acme_"), f"bad engagement_id: {eid}"

        ej = make_engagement_json(
            engagement_id=eid, client_name="ACME Corporation",
            client_short="acme", engagement_name="ACME Q3 Pentest",
            year="2026", active_scopes=["external", "webapp"],
            scope_tools={"external": ["ss3"], "webapp": ["fracture"]},
            tools=["ss3", "fracture"],
        )
        write_engagement_json(eng, ej)
        assert (eng / "engagement.json").exists()

        sd = create_scope_dir(eng, "external", targets=["220.1.2.0/24"])
        assert (sd / "scope_meta.json").exists()

        td_ss3 = create_scope_tool_dir(eng, "external", "ss3")
        assert (td_ss3 / "findings.json").exists()
        write_meta(td_ss3, make_meta(
            tool="scattershot3", version="1.18.0",
            client_short="acme", client_name="ACME Corporation",
            engagement_name="Q3 Pentest", target="220.1.2.0/24",
            scope="external", engagement_id=eid,
        ))

        td_fr = create_scope_tool_dir(eng, "external", "fracture",
                                      native=False, source_tool="ss3",
                                      source_finding="SS-042",
                                      override_targets=["https://220.1.2.56"])
        sm = json.loads((eng / "external" / "scope_meta.json").read_text())
        assert sm["tools"]["fracture"]["native"] is False
        assert sm["tools"]["fracture"]["source_tool"] == "ss3"

        assert detect_layout(eng) == "2.0"
        assert detect_layout(td_ss3) == "1.x"

        stdir = scope_tool_dir(eng, "external", "ss3")
        assert str(stdir).endswith("external/scattershot")
        print("engagement v2.0 layout: OK")

    print("OK")
