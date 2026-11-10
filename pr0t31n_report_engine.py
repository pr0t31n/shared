#!/usr/bin/env python3
"""pr0t31n_report_engine — Universal report templating engine for the pr0t31n toolkit.

Renders user-supplied report templates (DOCX, ODT, LaTeX, Markdown, reST,
AsciiDoc, HTML) by replacing placeholders with engagement data while
preserving all existing styles, fonts, and formatting.

Comparable to PlexTrac / Ghostwriter / Dradis report automation — uses
Jinja2 syntax as the industry-standard placeholder language.

Usage
-----
    from pr0t31n_report_engine import render_report, build_context

    ctx = build_context(project_dir, project_meta)
    render_report("template.docx", "output.docx", ctx)

Distribution: lives at /opt/pr0t31n/shared/pr0t31n_report_engine.py.
Called from Crucible and any future management app.

Dependencies:
    Required:  jinja2 (>=3.1)
    DOCX:      docxtpl (preferred) OR python-docx (>=1.0, fallback)
    ODT:       stdlib only (zipfile + xml.etree)
    Text:      jinja2 only
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import sys
import uuid
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    from jinja2 import Environment, BaseLoader, StrictUndefined, Undefined
    from jinja2 import TemplateSyntaxError
    _HAS_JINJA2 = True
except ImportError:
    _HAS_JINJA2 = False

try:
    from docxtpl import DocxTemplate, InlineImage, RichText, Listing
    from docx.shared import Inches, Pt, Mm
    _HAS_DOCXTPL = True
except ImportError:
    _HAS_DOCXTPL = False
    try:
        from docx import Document as _DocxDocument
        from docx.shared import Inches, Pt, Mm
        from docx.oxml.ns import qn as _qn
        from docx.oxml import OxmlElement as _OxmlElement
        _HAS_PYTHON_DOCX = True
    except ImportError:
        _HAS_PYTHON_DOCX = False

log = logging.getLogger("pr0t31n.report_engine")

ENGINE_VERSION = "1.0.0"

# ═══════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════

SUPPORTED_FORMATS = {
    ".docx": "docx",
    ".odt":  "odt",
    ".tex":  "latex",
    ".latex": "latex",
    ".md":   "markdown",
    ".markdown": "markdown",
    ".rst":  "rst",
    ".rest": "rst",
    ".adoc": "asciidoc",
    ".asciidoc": "asciidoc",
    ".html": "html",
    ".htm":  "html",
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
RISK_COLORS = {
    "CRITICAL": "#7b2d8b",
    "HIGH":     "#dc3545",
    "MEDIUM":   "#fd7e14",
    "LOW":      "#ffc107",
    "INFO":     "#17a2b8",
}
RISK_BG_COLORS = {
    "CRITICAL": "#f3e5f5",
    "HIGH":     "#fce4ec",
    "MEDIUM":   "#fff3e0",
    "LOW":      "#fffde7",
    "INFO":     "#e0f7fa",
}

# ═══════════════════════════════════════════════════════════════════════════
#  Placeholder Schema — the complete mapping of all reportable data
# ═══════════════════════════════════════════════════════════════════════════

PLACEHOLDER_SCHEMA = {
    "engagement": {
        "name":            "Engagement name",
        "id":              "Engagement ID (client_short_YYYYMMDD_HHMMSS)",
        "client_name":     "Client organization full name",
        "client_short":    "Client short code",
        "year":            "Engagement year",
        "start_date":      "Test start date",
        "end_date":        "Test end date",
        "created":         "Engagement creation timestamp",
        "scope":           "Primary scope type (external/internal/multi)",
        "active_scopes":   "List of active scope keys",
        "consultant": {
            "name":  "Lead consultant name",
            "title": "Consultant title/role",
            "email": "Consultant email",
        },
        "client_poc": {
            "name":  "Client point of contact name",
            "phone": "Client POC phone number",
            "email": "Client POC email",
        },
        "scope_definition": "Scope definition text (CIDRs, domains, URLs)",
        "tools":           "List of tool IDs used",
        "oos_handling":    "Out-of-scope handling mode",
    },
    "report": {
        "date":            "Report generation date (auto-filled)",
        "title":           "Report title (user-provided or auto-generated)",
        "version":         "Report version string",
        "classification":  "Document classification level",
        "prepared_by":     "Report author name",
        "prepared_for":    "Client name (alias of engagement.client_name)",
        "engine_version":  "Report engine version",
    },
    "stats": {
        "total_findings":    "Total finding count",
        "critical_count":    "CRITICAL finding count",
        "high_count":        "HIGH finding count",
        "medium_count":      "MEDIUM finding count",
        "low_count":         "LOW finding count",
        "info_count":        "INFO finding count",
        "total_hosts":       "Unique host count",
        "total_ports":       "Unique port count across all hosts",
        "total_cves":        "Unique CVE count",
        "kev_count":         "CISA KEV finding count",
        "tools_active":      "Number of distinct tools used",
        "fp_count":          "False positive count",
        "accepted_count":    "Accepted finding count",
        "total_action_items": "Total action item count",
        "pending_actions":   "Pending action item count",
        "completed_actions": "Completed action item count",
        "scope_count":       "Number of active scopes",
        "category_count":    "Number of distinct finding categories",
    },
    "findings[]": {
        "id":                    "UUID finding identifier",
        "title":                 "Finding title",
        "risk":                  "Risk level (CRITICAL/HIGH/MEDIUM/LOW/INFO)",
        "description":           "Finding description",
        "impact":                "Impact narrative (attacker capability + business consequence)",
        "remediation":           "Remediation guidance",
        "ip":                    "Target IP address",
        "port":                  "Target port number",
        "hostname":              "Target hostname",
        "service":               "Service name on port",
        "tool":                  "Originating tool name",
        "scope":                 "Scope key (external/internal/etc.)",
        "phase":                 "Scan phase",
        "datetime":              "Finding discovery timestamp",
        "command":               "Command that discovered the finding",
        "output":                "Abbreviated command output",
        "output_file":           "Path to full output evidence file",
        "cves":                  "Comma-separated CVE IDs",
        "cwe":                   "List of CWE IDs",
        "cvss_score":            "CVSS v3 base score (float)",
        "cvss_vector":           "CVSS v3 vector string",
        "owasp":                 "OWASP Web Top 10 category",
        "owasp_api":             "OWASP API Top 10 category",
        "nist":                  "NIST reference (legacy scalar)",
        "category":              "Finding category name",
        "catalogue_id":          "Catalogue entry ID",
        "confidence":            "Confidence level (Certain/Firm/Tentative)",
        "sources":               "Source tool(s) that reported the finding",
        "affected":              "Affected locations (newline-separated)",
        "exploitdb":             "ExploitDB reference exists (bool)",
        "metasploit":            "Metasploit module exists (bool)",
        "kev":                   "CISA Known Exploited Vulnerability (bool)",
        "exploit_details":       "List of exploit detail dicts",
        "nessus_plugin_id":      "Nessus plugin ID",
        "nessus_plugin_name":    "Nessus plugin name",
        "qualys_qid":            "Qualys QID",
        "plugin_output":         "External scanner plugin output",
        "remediation_effort":    "Remediation effort (Easy/Moderate/Significant/Major)",
        "remediation_component": "Remediation component",
        "remediation_category":  "Remediation category",
        "mitre_attack":          "List of MITRE ATT&CK technique dicts",
        "searchsploit_terms":    "List of searchsploit search terms",
        "metasploit_modules":    "List of Metasploit module paths",
        "accepted":              "Finding accepted by tester (bool)",
        "notes":                 "List of finding notes",
        # Compliance framework lists
        "nist_800_53":           "NIST SP 800-53 controls",
        "nist_800_171":          "NIST SP 800-171 controls",
        "nist_csf2":             "NIST CSF 2.0 subcategories",
        "pci_dss_4":             "PCI DSS v4.0 requirements",
        "iso_27001":             "ISO 27001 controls",
        "iso_27002":             "ISO 27002 controls",
        "soc2":                  "SOC 2 criteria",
        "hitrust":               "HITRUST controls",
        "gdpr":                  "GDPR articles",
        # Tool-specific
        "ssid":                  "Wireless SSID (Aether)",
        "bssid":                 "Wireless BSSID (Aether)",
        "wireless_data":         "Wireless metadata dict (Aether)",
        "subdevice":             "Subdevice identifier (Gearbox)",
        "interface":             "Interface name (Gearbox)",
        "instance":              "Instance identifier (Gearbox)",
        "classification":        "Device classification (Gearbox)",
        "api_endpoint_path":     "API endpoint path (Siphon)",
        "api_method":            "HTTP method (Siphon)",
        "api_from_spec":         "Endpoint from API spec (Siphon, bool)",
        "is_rogue_endpoint":     "Rogue/undocumented endpoint (Siphon, bool)",
        # Catalogue lineage
        "aliases":               "Alternative finding titles",
        "source_tools":          "Tools that contributed to this finding",
        "cve_examples":          "Example CVEs for this finding type",
        # Derived (added by context builder)
        "risk_color":            "Hex color for risk level",
        "risk_bg_color":         "Background hex color for risk level",
        "finding_number":        "Sequential finding number (1-based)",
        "cve_list":              "CVEs as a Python list",
        "cwe_list":              "CWEs as a Python list",
        "affected_list":         "Affected locations as a Python list",
        "mitre_techniques":      "MITRE techniques as formatted strings",
        "compliance_frameworks": "Dict of framework→controls for this finding",
    },
    "findings_critical[]": "Findings filtered to CRITICAL risk only",
    "findings_high[]":     "Findings filtered to HIGH risk only",
    "findings_medium[]":   "Findings filtered to MEDIUM risk only",
    "findings_low[]":      "Findings filtered to LOW risk only",
    "findings_info[]":     "Findings filtered to INFO risk only",
    "findings_kev[]":      "Findings with CISA KEV flag",
    "findings_by_host{}":  "Findings grouped by IP → list",
    "findings_by_tool{}":  "Findings grouped by tool → list",
    "findings_by_category{}": "Findings grouped by category → list",
    "findings_by_scope{}": "Findings grouped by scope → list",
    "findings_by_risk{}":  "Findings grouped by risk → list",
    "actions[]": {
        "id":               "Action item ID",
        "title":            "Action item title/description",
        "target":           "Target IP/URL",
        "recommended_tool": "Recommended tool for follow-up",
        "command":          "Suggested command",
        "status":           "Status (pending/running/completed/skipped)",
        "priority":         "Priority (CRITICAL/HIGH/MEDIUM/LOW)",
        "category":         "Action category",
        "approval_tier":    "Approval tier (auto/confirm)",
        "in_scope":         "Whether target is in scope (bool)",
        "created":          "Creation timestamp",
        "finding_id":       "Associated finding ID (from metadata)",
        "action_number":    "Sequential action number (1-based)",
    },
    "actions_pending[]":   "Action items with status=pending",
    "actions_completed[]": "Action items with status=completed",
    "hosts[]": {
        "ip":              "Host IP address",
        "hostname":        "Primary hostname",
        "ports":           "List of port dicts with findings",
        "tools":           "List of tool names that found issues",
        "cves":            "List of CVEs found on this host",
        "max_risk":        "Highest risk level on this host",
        "total_findings":  "Finding count for this host",
        "host_number":     "Sequential host number (1-based)",
    },
    "scopes[]": {
        "key":           "Scope key (external/internal/etc.)",
        "display_name":  "Scope display name",
        "tools":         "Tools assigned to this scope",
        "finding_count": "Findings in this scope",
        "risk_summary":  "Risk count dict for this scope",
    },
    "false_positives[]": "List of false positive findings (same fields as findings[])",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Jinja2 Custom Filters
# ═══════════════════════════════════════════════════════════════════════════

def _filter_risk_color(risk):
    """Return hex color for a risk level."""
    return RISK_COLORS.get(str(risk).upper(), "#6c757d")

def _filter_risk_bg_color(risk):
    """Return background hex color for a risk level."""
    return RISK_BG_COLORS.get(str(risk).upper(), "#f8f9fa")

def _filter_date_format(value, fmt="%B %d, %Y"):
    """Format an ISO date string."""
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.strftime(fmt)
    for parse_fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                      "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value)[:19], parse_fmt).strftime(fmt)
        except (ValueError, TypeError):
            continue
    return str(value)

def _filter_cve_list(cves):
    """Split comma-separated CVE string into a list."""
    if isinstance(cves, list):
        return cves
    if not cves:
        return []
    return [c.strip() for c in str(cves).split(",") if c.strip()]

def _filter_cwe_list(cwes):
    """Normalize CWE field to a list."""
    if isinstance(cwes, list):
        return cwes
    if not cwes:
        return []
    return [c.strip() for c in str(cwes).split(",") if c.strip()]

def _filter_affected_list(affected):
    """Split newline-separated affected string into a list."""
    if isinstance(affected, list):
        return affected
    if not affected:
        return []
    return [a.strip() for a in str(affected).split("\n") if a.strip()]

def _filter_count_by_risk(findings):
    """Count findings by risk level."""
    counts = {r: 0 for r in RISK_ORDER}
    for f in (findings or []):
        r = str(f.get("risk", "INFO")).upper()
        counts[r] = counts.get(r, 0) + 1
    return counts

def _filter_mitre_format(mitre_list):
    """Format MITRE ATT&CK list for display."""
    if not mitre_list:
        return ""
    parts = []
    for m in mitre_list:
        if isinstance(m, dict):
            tid = m.get("technique", "")
            name = m.get("name", "")
            tactic = m.get("tactic", "")
            parts.append(f"{tid} - {name} ({tactic})" if name else tid)
        else:
            parts.append(str(m))
    return "; ".join(parts)

def _filter_compliance_join(items, sep=", "):
    """Join a compliance list (list[str]) into a string."""
    if not items:
        return ""
    if isinstance(items, str):
        return items
    return sep.join(str(i) for i in items)

def _filter_ordinal(n):
    """Convert integer to ordinal string (1st, 2nd, 3rd, etc.)."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    s = ("th", "st", "nd", "rd") + ("th",) * 6
    if n % 100 in (11, 12, 13):
        return f"{n}th"
    return f"{n}{s[n % 10]}"

def _filter_nl2br(text):
    """Convert newlines to <br> tags (HTML format)."""
    if not text:
        return ""
    return str(text).replace("\n", "<br>")

def _filter_risk_sort(findings):
    """Sort findings by risk severity (CRITICAL first)."""
    return sorted(findings or [],
                  key=lambda f: RISK_ORDER.get(
                      str(f.get("risk", "INFO")).upper(), 5))

def _filter_unique_cves(findings):
    """Extract unique CVEs from a list of findings."""
    seen = set()
    for f in (findings or []):
        for cve in _filter_cve_list(f.get("cves", "")):
            seen.add(cve)
    return sorted(seen)

def _filter_group_by(items, key):
    """Group a list of dicts by a key, returning {value: [items]}."""
    groups = {}
    for item in (items or []):
        val = item.get(key, "") or ""
        groups.setdefault(val, []).append(item)
    return groups

CUSTOM_FILTERS = {
    "risk_color":      _filter_risk_color,
    "risk_bg_color":   _filter_risk_bg_color,
    "date_format":     _filter_date_format,
    "cve_list":        _filter_cve_list,
    "cwe_list":        _filter_cwe_list,
    "affected_list":   _filter_affected_list,
    "count_by_risk":   _filter_count_by_risk,
    "mitre_format":    _filter_mitre_format,
    "compliance_join": _filter_compliance_join,
    "ordinal":         _filter_ordinal,
    "nl2br":           _filter_nl2br,
    "risk_sort":       _filter_risk_sort,
    "unique_cves":     _filter_unique_cves,
    "group_by":        _filter_group_by,
}


# ═══════════════════════════════════════════════════════════════════════════
#  ReportContext — build the full data context from engagement data
# ═══════════════════════════════════════════════════════════════════════════

class ReportContext:
    """Builds the Jinja2 template context from engagement data sources.

    Pulls from:
      - project meta (crucible_meta.json / engagement.json)
      - findings (findings.db or findings.json)
      - action items (action_items.json)
      - false positives (falsePositives.json)
      - host correlation (derived from findings)
      - scope information
    """

    def __init__(self, project_dir, project_meta=None, findings=None,
                 action_items=None, false_positives=None,
                 report_overrides=None):
        self.project_dir = Path(project_dir) if project_dir else None
        self.project_meta = project_meta or {}
        self._findings_raw = findings
        self._actions_raw = action_items
        self._fps_raw = false_positives
        self._report_overrides = report_overrides or {}

    def build(self) -> dict:
        """Build and return the complete template context dict."""
        findings = self._load_findings()
        actions = self._load_action_items()
        fps = self._load_false_positives()

        findings = self._enrich_findings(findings)
        actions = self._enrich_actions(actions)

        ctx = {}
        ctx["engagement"] = self._build_engagement()
        ctx["report"] = self._build_report()
        ctx["stats"] = self._build_stats(findings, actions, fps)
        ctx["findings"] = findings
        ctx["actions"] = actions
        ctx["false_positives"] = fps
        ctx["hosts"] = self._build_hosts(findings)
        ctx["scopes"] = self._build_scopes(findings)

        ctx["findings_critical"] = [f for f in findings
                                     if f.get("risk") == "CRITICAL"]
        ctx["findings_high"] = [f for f in findings
                                 if f.get("risk") == "HIGH"]
        ctx["findings_medium"] = [f for f in findings
                                   if f.get("risk") == "MEDIUM"]
        ctx["findings_low"] = [f for f in findings
                                if f.get("risk") == "LOW"]
        ctx["findings_info"] = [f for f in findings
                                 if f.get("risk") == "INFO"]
        ctx["findings_kev"] = [f for f in findings if f.get("kev")]

        ctx["findings_by_host"] = _filter_group_by(findings, "ip")
        ctx["findings_by_tool"] = _filter_group_by(findings, "tool")
        ctx["findings_by_category"] = _filter_group_by(findings, "category")
        ctx["findings_by_scope"] = _filter_group_by(findings, "scope")
        ctx["findings_by_risk"] = _filter_group_by(findings, "risk")

        ctx["actions_pending"] = [a for a in actions
                                   if a.get("status") == "pending"]
        ctx["actions_completed"] = [a for a in actions
                                     if a.get("status") == "completed"]
        return ctx

    # ── Data loading ────────────────────────────────────────────

    def _load_findings(self):
        if self._findings_raw is not None:
            return list(self._findings_raw)
        if not self.project_dir:
            return []
        db_path = self.project_dir / "findings.db"
        if db_path.exists():
            try:
                if "/opt/pr0t31n/shared" not in sys.path:
                    sys.path.insert(0, "/opt/pr0t31n/shared")
                import pr0t31n_findings_db as _fdb
                db = _fdb.FindingsDB(str(db_path), readonly=True)
                result = db.query_findings(page=1, per_page=500000)
                db.close()
                findings = result.get("findings", [])
                if findings:
                    return findings
            except Exception:
                log.debug("DB load failed, falling back to JSON")
        json_path = self.project_dir / "findings.json"
        if json_path.exists():
            try:
                with open(json_path) as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    return data.get("findings", [])
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _load_action_items(self):
        if self._actions_raw is not None:
            return list(self._actions_raw)
        if not self.project_dir:
            return []
        ai_path = self.project_dir / "action_items.json"
        if ai_path.exists():
            try:
                with open(ai_path) as fh:
                    data = json.load(fh)
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _load_false_positives(self):
        if self._fps_raw is not None:
            return list(self._fps_raw)
        if not self.project_dir:
            return []
        for fn in ("falsePositives.json", "false_positives.json"):
            fp_path = self.project_dir / fn
            if fp_path.exists():
                try:
                    with open(fp_path) as fh:
                        data = json.load(fh)
                    return data if isinstance(data, list) else []
                except (json.JSONDecodeError, OSError):
                    pass
        return []

    # ── Enrichment ──────────────────────────────────────────────

    def _enrich_findings(self, findings):
        enriched = []
        for i, f in enumerate(findings, 1):
            f = dict(f)
            risk = str(f.get("risk", "INFO")).upper()
            f["risk"] = risk
            f["risk_color"] = RISK_COLORS.get(risk, "#6c757d")
            f["risk_bg_color"] = RISK_BG_COLORS.get(risk, "#f8f9fa")
            f["finding_number"] = i
            f["cve_list"] = _filter_cve_list(f.get("cves", ""))
            f["cwe_list"] = _filter_cwe_list(f.get("cwe", []))
            f["affected_list"] = _filter_affected_list(f.get("affected", ""))
            mitre = f.get("mitre_attack", [])
            f["mitre_techniques"] = _filter_mitre_format(mitre) if mitre else ""

            compliance = {}
            for fw in ("nist_800_53", "nist_800_171", "nist_csf2",
                       "pci_dss_4", "iso_27001", "iso_27002",
                       "soc2", "hitrust", "gdpr"):
                val = f.get(fw, [])
                if val:
                    compliance[fw] = val
            f["compliance_frameworks"] = compliance

            for key in ("description", "impact", "remediation", "output",
                        "command", "hostname", "service", "tool", "scope",
                        "phase", "category", "sources", "affected"):
                f.setdefault(key, "")
            for key in ("exploitdb", "metasploit", "kev", "accepted"):
                f.setdefault(key, False)
            f.setdefault("port", 0)
            f.setdefault("notes", [])
            f.setdefault("exploit_details", [])
            enriched.append(f)
        enriched.sort(key=lambda f: RISK_ORDER.get(f.get("risk", "INFO"), 5))
        return enriched

    def _enrich_actions(self, actions):
        enriched = []
        for i, a in enumerate(actions, 1):
            a = dict(a)
            a["action_number"] = i
            meta = a.get("metadata") or {}
            a["finding_id"] = meta.get("finding_id", "")
            for key in ("title", "target", "recommended_tool", "command",
                        "status", "priority", "category", "approval_tier",
                        "created"):
                a.setdefault(key, "")
            a.setdefault("in_scope", True)
            enriched.append(a)
        return enriched

    # ── Context section builders ────────────────────────────────

    def _build_engagement(self):
        m = self.project_meta
        consultant = m.get("consultant") or {}
        if isinstance(consultant, str):
            consultant = {"name": consultant}
        client_poc = m.get("client_poc") or {}
        if isinstance(client_poc, str):
            client_poc = {"name": client_poc}

        scope_def = m.get("scope_definition") or {}
        if isinstance(scope_def, dict):
            parts = []
            for scope_key, entries in scope_def.items():
                if isinstance(entries, list):
                    parts.extend(entries)
                elif isinstance(entries, str):
                    parts.append(entries)
            scope_def_text = "\n".join(parts)
        else:
            scope_def_text = str(scope_def)

        return {
            "name":         m.get("name", ""),
            "id":           m.get("engagement_id", ""),
            "client_name":  m.get("client_name", ""),
            "client_short": m.get("client_short", ""),
            "year":         m.get("year", ""),
            "start_date":   m.get("start_date", ""),
            "end_date":     m.get("end_date", ""),
            "created":      m.get("created", ""),
            "scope":        m.get("scope", ""),
            "active_scopes": m.get("active_scopes", []),
            "consultant": {
                "name":  consultant.get("name", ""),
                "title": consultant.get("title", ""),
                "email": consultant.get("email", ""),
            },
            "client_poc": {
                "name":  client_poc.get("name", ""),
                "phone": client_poc.get("phone", ""),
                "email": client_poc.get("email", ""),
            },
            "scope_definition": scope_def_text,
            "tools":        m.get("tools", []),
            "oos_handling": m.get("oos_handling", "explicit"),
        }

    def _build_report(self):
        now = datetime.now()
        r = {
            "date":           now.strftime("%B %d, %Y"),
            "date_iso":       now.strftime("%Y-%m-%d"),
            "title":          "",
            "version":        "1.0",
            "classification": "",
            "prepared_by":    "",
            "prepared_for":   self.project_meta.get("client_name", ""),
            "engine_version": ENGINE_VERSION,
        }
        r.update(self._report_overrides)
        return r

    def _build_stats(self, findings, actions, fps):
        risk_counts = {r: 0 for r in RISK_ORDER}
        hosts = set()
        ports = set()
        cves = set()
        tools = set()
        categories = set()
        kev_count = 0
        accepted = 0

        for f in findings:
            r = str(f.get("risk", "INFO")).upper()
            risk_counts[r] = risk_counts.get(r, 0) + 1
            ip = f.get("ip", "")
            if ip:
                hosts.add(ip)
                port = f.get("port", 0)
                if port:
                    ports.add((ip, port))
            for cve in _filter_cve_list(f.get("cves", "")):
                cves.add(cve)
            t = f.get("tool", "")
            if t:
                tools.add(t)
            cat = f.get("category", "")
            if cat:
                categories.add(cat)
            if f.get("kev"):
                kev_count += 1
            if f.get("accepted"):
                accepted += 1

        pending = sum(1 for a in actions if a.get("status") == "pending")
        completed = sum(1 for a in actions if a.get("status") == "completed")

        return {
            "total_findings":     len(findings),
            "critical_count":     risk_counts.get("CRITICAL", 0),
            "high_count":         risk_counts.get("HIGH", 0),
            "medium_count":       risk_counts.get("MEDIUM", 0),
            "low_count":          risk_counts.get("LOW", 0),
            "info_count":         risk_counts.get("INFO", 0),
            "total_hosts":        len(hosts),
            "total_ports":        len(ports),
            "total_cves":         len(cves),
            "kev_count":          kev_count,
            "tools_active":       len(tools),
            "fp_count":           len(fps),
            "accepted_count":     accepted,
            "total_action_items": len(actions),
            "pending_actions":    pending,
            "completed_actions":  completed,
            "scope_count":        len(self.project_meta.get("active_scopes", [])),
            "category_count":     len(categories),
        }

    def _build_hosts(self, findings):
        hosts = {}
        for f in findings:
            ip = f.get("ip", "")
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = {
                    "ip": ip,
                    "hostname": f.get("hostname", ""),
                    "ports": set(),
                    "tools": set(),
                    "cves": set(),
                    "max_risk": "INFO",
                    "total_findings": 0,
                }
            h = hosts[ip]
            h["total_findings"] += 1
            port = f.get("port", 0)
            if port:
                h["ports"].add(port)
            t = f.get("tool", "")
            if t:
                h["tools"].add(t)
            for cve in _filter_cve_list(f.get("cves", "")):
                h["cves"].add(cve)
            r = str(f.get("risk", "INFO")).upper()
            if RISK_ORDER.get(r, 5) < RISK_ORDER.get(h["max_risk"], 5):
                h["max_risk"] = r
            if f.get("hostname") and not h["hostname"]:
                h["hostname"] = f["hostname"]

        result = []
        for i, (ip, h) in enumerate(
                sorted(hosts.items(),
                       key=lambda x: RISK_ORDER.get(x[1]["max_risk"], 5)), 1):
            h["ports"] = sorted(h["ports"])
            h["tools"] = sorted(h["tools"])
            h["cves"] = sorted(h["cves"])
            h["host_number"] = i
            result.append(h)
        return result

    def _build_scopes(self, findings):
        try:
            if "/opt/pr0t31n/shared" not in sys.path:
                sys.path.insert(0, "/opt/pr0t31n/shared")
            from pr0t31n_schema import SCOPE_DISPLAY_NAMES
        except ImportError:
            SCOPE_DISPLAY_NAMES = {}

        active = self.project_meta.get("active_scopes", [])
        scope_tools = self.project_meta.get("scope_tools", {})
        scope_findings = {}
        for f in findings:
            s = f.get("scope", "")
            if s:
                scope_findings.setdefault(s, []).append(f)

        result = []
        for sk in active:
            sf = scope_findings.get(sk, [])
            rc = {r: 0 for r in RISK_ORDER}
            for f in sf:
                r = str(f.get("risk", "INFO")).upper()
                rc[r] = rc.get(r, 0) + 1
            result.append({
                "key":           sk,
                "display_name":  SCOPE_DISPLAY_NAMES.get(sk, sk),
                "tools":         scope_tools.get(sk, []),
                "finding_count": len(sf),
                "risk_summary":  rc,
            })
        return result


def build_context(project_dir, project_meta=None, findings=None,
                  action_items=None, false_positives=None,
                  report_overrides=None) -> dict:
    """Build a complete template context from engagement data.

    This is the main entry point for context building. Pass whatever
    data you have — the builder will load the rest from disk.
    """
    return ReportContext(
        project_dir, project_meta, findings, action_items,
        false_positives, report_overrides
    ).build()


# ═══════════════════════════════════════════════════════════════════════════
#  Format Detection
# ═══════════════════════════════════════════════════════════════════════════

def detect_format(path) -> str:
    """Detect template format from file extension. Returns format key or raises."""
    ext = Path(path).suffix.lower()
    fmt = SUPPORTED_FORMATS.get(ext)
    if not fmt:
        raise ValueError(
            f"Unsupported template format '{ext}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}")
    return fmt


# ═══════════════════════════════════════════════════════════════════════════
#  Base Engine
# ═══════════════════════════════════════════════════════════════════════════

class BaseEngine:
    """Base class for format-specific template engines."""

    def render(self, template_path, output_path, context):
        raise NotImplementedError

    def _make_jinja_env(self, **kwargs):
        """Create a Jinja2 Environment with custom filters."""
        if not _HAS_JINJA2:
            raise ImportError("jinja2 is required for report templating")
        env = Environment(**kwargs)
        env.filters.update(CUSTOM_FILTERS)
        return env


# ═══════════════════════════════════════════════════════════════════════════
#  DOCX Engine — docxtpl (primary) or python-docx (fallback)
# ═══════════════════════════════════════════════════════════════════════════

class DocxEngine(BaseEngine):
    """DOCX template engine.

    Primary: docxtpl (Jinja2-native DOCX rendering, handles run-splitting,
    style preservation, loops, conditionals, images, tables).

    Fallback: python-docx with manual run-merging (when docxtpl is not
    installed).
    """

    def render(self, template_path, output_path, context):
        if _HAS_DOCXTPL:
            return self._render_docxtpl(template_path, output_path, context)
        if _HAS_PYTHON_DOCX:
            return self._render_python_docx(template_path, output_path, context)
        raise ImportError(
            "DOCX rendering requires 'docxtpl' (preferred) or "
            "'python-docx'. Install with: pip3 install docxtpl")

    # ── docxtpl primary path ───────────────────────────────────

    def _render_docxtpl(self, template_path, output_path, context):
        """Render using docxtpl — the gold standard for DOCX templates.

        docxtpl handles:
        - Run-splitting (Word splits {{placeholder}} across XML runs)
        - Style preservation across all placeholders
        - Jinja2 loops and conditionals natively in DOCX
        - Table row duplication for loop content
        - Inline images with {{image}} tags
        - RichText for HTML→DOCX conversion
        - Subdocument inclusion
        """
        tpl = DocxTemplate(str(template_path))
        jinja_env = tpl.get_jinja_env()
        jinja_env.filters.update(CUSTOM_FILTERS)
        tpl.render(context, jinja_env)
        tpl.save(str(output_path))
        log.info("DOCX rendered via docxtpl: %s → %s",
                 template_path, output_path)

    # ── python-docx fallback path ──────────────────────────────

    _PLACEHOLDER_RE = re.compile(
        r'\{\{[\s]*[\w.|\s\'"()\[\],]+[\s]*\}\}'
        r'|'
        r'\{%[\s]*.*?[\s]*%\}'
        r'|'
        r'\{#[\s]*.*?[\s]*#\}'
    )

    def _render_python_docx(self, template_path, output_path, context):
        """Fallback: render using python-docx with manual run-merging.

        This handles the run-splitting problem by merging adjacent runs
        that form a complete Jinja2 placeholder before doing replacement.
        Loops and conditionals are NOT supported in this fallback —
        only simple variable substitution.
        """
        doc = _DocxDocument(str(template_path))
        env = self._make_jinja_env(undefined=Undefined)

        for para in doc.paragraphs:
            self._process_paragraph(para, context, env)
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        self._process_paragraph(para, context, env)
        for section in doc.sections:
            for part in (section.header, section.footer,
                         section.first_page_header, section.first_page_footer,
                         section.even_page_header, section.even_page_footer):
                if part is not None:
                    for para in part.paragraphs:
                        self._process_paragraph(para, context, env)

        doc.save(str(output_path))
        log.info("DOCX rendered via python-docx fallback: %s → %s",
                 template_path, output_path)

    def _process_paragraph(self, para, context, env):
        """Merge runs that form placeholders, then render via Jinja2."""
        full_text = "".join(r.text for r in para.runs)
        if "{{" not in full_text and "{%" not in full_text:
            return

        merged = self._merge_runs_for_placeholders(para.runs)
        for run_group in merged:
            if len(run_group) == 1:
                run = run_group[0]
                if "{{" in run.text or "{%" in run.text:
                    try:
                        tmpl = env.from_string(run.text)
                        run.text = tmpl.render(context)
                    except Exception:
                        pass
            else:
                combined = "".join(r.text for r in run_group)
                if "{{" in combined or "{%" in combined:
                    try:
                        tmpl = env.from_string(combined)
                        rendered = tmpl.render(context)
                    except Exception:
                        rendered = combined
                    run_group[0].text = rendered
                    for r in run_group[1:]:
                        r.text = ""

    @staticmethod
    def _merge_runs_for_placeholders(runs):
        """Group runs that together form Jinja2 placeholders.

        Word/LibreOffice splits text like {{finding.title}} across
        multiple XML runs due to spell-check marks, formatting changes,
        or revision tracking. This method identifies runs that need to
        be merged to reconstruct complete placeholders.
        """
        if not runs:
            return []

        groups = []
        current_group = []
        brace_depth = 0
        in_placeholder = False

        for run in runs:
            text = run.text or ""
            if not in_placeholder:
                start = -1
                for j, ch in enumerate(text):
                    if ch == '{' and j + 1 < len(text) and text[j + 1] in ('{', '%', '#'):
                        start = j
                        break
                    if j > 0 and text[j - 1] == '{' and ch in ('{', '%', '#'):
                        start = j - 1
                        break

                if start >= 0:
                    if current_group:
                        groups.append(current_group)
                    current_group = [run]
                    in_placeholder = True
                    for ch in text[start:]:
                        if ch == '{':
                            brace_depth += 1
                        elif ch == '}':
                            brace_depth -= 1
                            if brace_depth <= 0:
                                in_placeholder = False
                                brace_depth = 0
                                break
                else:
                    if current_group:
                        groups.append(current_group)
                    current_group = [run]
            else:
                current_group.append(run)
                for ch in text:
                    if ch == '{':
                        brace_depth += 1
                    elif ch == '}':
                        brace_depth -= 1
                        if brace_depth <= 0:
                            in_placeholder = False
                            brace_depth = 0
                            break

                if not in_placeholder:
                    groups.append(current_group)
                    current_group = []

        if current_group:
            groups.append(current_group)

        return groups


# ═══════════════════════════════════════════════════════════════════════════
#  ODT Engine — stdlib zipfile + XML
# ═══════════════════════════════════════════════════════════════════════════

class OdtEngine(BaseEngine):
    """ODT template engine using stdlib only.

    ODT files are ZIP archives containing XML. Unlike DOCX, ODT does NOT
    have the run-splitting problem — styles are expressed as element
    attributes, so placeholder text stays contiguous.

    Supports: variable substitution, loops, conditionals via Jinja2.
    """

    _NS = {
        "text":   "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
        "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
        "style":  "urn:oasis:names:tc:opendocument:xmlns:style:1.0",
        "fo":     "urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0",
        "draw":   "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",
        "table":  "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
    }

    def render(self, template_path, output_path, context):
        for prefix, uri in self._NS.items():
            ET.register_namespace(prefix, uri)

        buf = BytesIO()
        with zipfile.ZipFile(str(template_path), 'r') as zin:
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename == "content.xml":
                        data = self._process_xml(data, context)
                    elif item.filename == "styles.xml":
                        data = self._process_xml(data, context)
                    zout.writestr(item, data)

        Path(output_path).write_bytes(buf.getvalue())
        log.info("ODT rendered: %s → %s", template_path, output_path)

    def _process_xml(self, xml_bytes, context):
        """Process an ODT XML file, replacing Jinja2 placeholders."""
        tree = ET.fromstring(xml_bytes)
        self._walk_and_replace(tree, context)
        return ET.tostring(tree, encoding="unicode", xml_declaration=True).encode("utf-8")

    def _walk_and_replace(self, element, context):
        """Walk XML tree and replace Jinja2 placeholders in text nodes."""
        env = self._make_jinja_env(undefined=Undefined)
        self._replace_text_in_element(element, context, env)
        for child in element:
            self._walk_and_replace(child, context)

    def _replace_text_in_element(self, elem, context, env):
        if elem.text and ("{{" in elem.text or "{%" in elem.text):
            try:
                tmpl = env.from_string(elem.text)
                elem.text = tmpl.render(context)
            except Exception:
                pass
        if elem.tail and ("{{" in elem.tail or "{%" in elem.tail):
            try:
                tmpl = env.from_string(elem.tail)
                elem.tail = tmpl.render(context)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Text Engine — Jinja2 for Markdown, LaTeX, reST, AsciiDoc, HTML
# ═══════════════════════════════════════════════════════════════════════════

class TextEngine(BaseEngine):
    """Text-based template engine using Jinja2.

    Supports: Markdown, LaTeX, reStructuredText, AsciiDoc, HTML.

    LaTeX uses custom delimiters to avoid conflict with TeX braces:
        \\VAR{variable}     instead of {{ variable }}
        \\BLOCK{statement}  instead of {% statement %}
        \\#{comment}        instead of {# comment #}
    """

    _LATEX_CONFIG = {
        "block_start_string":    "\\BLOCK{",
        "block_end_string":      "}",
        "variable_start_string": "\\VAR{",
        "variable_end_string":   "}",
        "comment_start_string":  "\\#{",
        "comment_end_string":    "}",
    }

    def render(self, template_path, output_path, context, fmt=None):
        template_path = Path(template_path)
        if fmt is None:
            fmt = detect_format(template_path)

        template_text = template_path.read_text(encoding="utf-8")

        if fmt == "latex":
            env = self._make_jinja_env(
                loader=BaseLoader(),
                **self._LATEX_CONFIG
            )
        else:
            env = self._make_jinja_env(loader=BaseLoader())

        tmpl = env.from_string(template_text)
        rendered = tmpl.render(context)

        Path(output_path).write_text(rendered, encoding="utf-8")
        log.info("%s rendered: %s → %s", fmt.upper(), template_path, output_path)


# ═══════════════════════════════════════════════════════════════════════════
#  Engine Registry
# ═══════════════════════════════════════════════════════════════════════════

_ENGINES = {
    "docx":     DocxEngine,
    "odt":      OdtEngine,
    "latex":    TextEngine,
    "markdown": TextEngine,
    "rst":      TextEngine,
    "asciidoc": TextEngine,
    "html":     TextEngine,
}


def get_engine(fmt) -> BaseEngine:
    """Get the appropriate engine for a format."""
    cls = _ENGINES.get(fmt)
    if not cls:
        raise ValueError(f"No engine for format '{fmt}'")
    return cls()


# ═══════════════════════════════════════════════════════════════════════════
#  Main API
# ═══════════════════════════════════════════════════════════════════════════

def render_report(template_path, output_path, context,
                  fmt=None) -> str:
    """Render a report template with engagement data.

    Args:
        template_path: Path to the template file.
        output_path:   Path for the rendered output.
        context:       Template context dict (from build_context()).
        fmt:           Force format (auto-detected from extension if None).

    Returns:
        The output path as a string.
    """
    template_path = Path(template_path)
    output_path = Path(output_path)

    if fmt is None:
        fmt = detect_format(template_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    engine = get_engine(fmt)
    if isinstance(engine, TextEngine):
        engine.render(template_path, output_path, context, fmt=fmt)
    else:
        engine.render(template_path, output_path, context)

    return str(output_path)


def get_placeholder_schema() -> dict:
    """Return the full placeholder schema for documentation/UI display."""
    return copy.deepcopy(PLACEHOLDER_SCHEMA)


def get_placeholder_list(flat=True) -> list:
    """Return a flat list of all placeholder paths for autocomplete/docs.

    Each entry is a dict with keys: path, description, type, loop.
    """
    result = []

    def _walk(schema, prefix="", loop=False):
        for key, val in schema.items():
            clean_key = key.rstrip("[]{}").rstrip()
            is_loop = key.endswith("[]") or key.endswith("{}")
            path = f"{prefix}.{clean_key}" if prefix else clean_key

            if isinstance(val, dict):
                _walk(val, path, loop=is_loop or loop)
            elif isinstance(val, str):
                var_syntax = "{{ " + path + " }}"
                if is_loop:
                    var_syntax = "{% for item in " + path + " %}"
                result.append({
                    "path": path,
                    "syntax": var_syntax,
                    "description": val,
                    "loop": is_loop or loop,
                })

    _walk(PLACEHOLDER_SCHEMA)
    return result


def validate_template(template_path, fmt=None) -> dict:
    """Validate a template file and return a report of placeholders found.

    Returns:
        {
            "valid": bool,
            "format": str,
            "placeholders_found": [str],
            "unknown_placeholders": [str],
            "errors": [str],
        }
    """
    template_path = Path(template_path)
    if not template_path.exists():
        return {"valid": False, "format": None,
                "placeholders_found": [], "unknown_placeholders": [],
                "errors": [f"File not found: {template_path}"]}

    if fmt is None:
        try:
            fmt = detect_format(template_path)
        except ValueError as e:
            return {"valid": False, "format": None,
                    "placeholders_found": [], "unknown_placeholders": [],
                    "errors": [str(e)]}

    errors = []
    found = set()

    try:
        if fmt == "docx":
            found = _extract_docx_placeholders(template_path)
        elif fmt == "odt":
            found = _extract_odt_placeholders(template_path)
        else:
            found = _extract_text_placeholders(template_path, fmt)
    except Exception as e:
        errors.append(f"Failed to parse template: {e}")

    known_paths = {p["path"] for p in get_placeholder_list()}
    unknown = set()
    for ph in found:
        clean = ph.strip().strip("{}% ")
        parts = clean.split("|")[0].strip()
        parts = parts.split(".")
        root = parts[0] if parts else ""
        _KNOWN_ROOTS = {
            "engagement", "report", "stats", "findings",
            "actions", "hosts", "scopes", "false_positives",
            "findings_critical", "findings_high",
            "findings_medium", "findings_low", "findings_info",
            "findings_kev", "findings_by_host",
            "findings_by_tool", "findings_by_category",
            "findings_by_scope", "findings_by_risk",
            "actions_pending", "actions_completed",
            "finding", "action", "host", "scope", "fp",
            "item", "loop", "range", "true", "false", "none",
        }
        _JINJA_KEYWORDS = {
            "for", "endfor", "if", "endif", "else", "elif",
            "set", "block", "endblock", "macro", "endmacro",
            "call", "endcall", "filter", "endfilter",
            "extends", "include", "import", "from",
            "with", "endwith", "autoescape", "endautoescape",
        }
        if root not in _KNOWN_ROOTS and root not in _JINJA_KEYWORDS:
            is_loop_var = False
            for kw in ("for ", "if ", "else", "endif", "endfor",
                        "set ", "block", "macro"):
                if clean.startswith(kw):
                    is_loop_var = True
                    break
            if not is_loop_var:
                unknown.add(ph)

    return {
        "valid": len(errors) == 0,
        "format": fmt,
        "placeholders_found": sorted(found),
        "unknown_placeholders": sorted(unknown),
        "errors": errors,
    }


# ── Placeholder extraction helpers ────────────────────────────

_JINJA_VAR_RE = re.compile(r'\{\{[\s]*([\w.|\s\'"()\[\],]+?)[\s]*\}\}')
_JINJA_TAG_RE = re.compile(r'\{%[\s]*(.*?)[\s]*%\}')
_LATEX_VAR_RE = re.compile(r'\\VAR\{([\w.|\s\'"()\[\],]+?)\}')
_LATEX_TAG_RE = re.compile(r'\\BLOCK\{(.*?)\}')


def _extract_docx_placeholders(path):
    """Extract Jinja2 placeholders from a DOCX file."""
    found = set()
    if _HAS_DOCXTPL:
        tpl = DocxTemplate(str(path))
        for var in tpl.get_undeclared_template_variables():
            found.add(var)
        return found
    if _HAS_PYTHON_DOCX:
        doc = _DocxDocument(str(path))
        for para in doc.paragraphs:
            text = "".join(r.text for r in para.runs)
            for m in _JINJA_VAR_RE.finditer(text):
                found.add(m.group(1).strip())
            for m in _JINJA_TAG_RE.finditer(text):
                found.add(m.group(1).strip())
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        text = "".join(r.text for r in para.runs)
                        for m in _JINJA_VAR_RE.finditer(text):
                            found.add(m.group(1).strip())
                        for m in _JINJA_TAG_RE.finditer(text):
                            found.add(m.group(1).strip())
    return found


def _extract_odt_placeholders(path):
    """Extract Jinja2 placeholders from an ODT file."""
    found = set()
    with zipfile.ZipFile(str(path), 'r') as z:
        for fn in ("content.xml", "styles.xml"):
            if fn in z.namelist():
                data = z.read(fn).decode("utf-8")
                for m in _JINJA_VAR_RE.finditer(data):
                    found.add(m.group(1).strip())
                for m in _JINJA_TAG_RE.finditer(data):
                    found.add(m.group(1).strip())
    return found


def _extract_text_placeholders(path, fmt):
    """Extract Jinja2 placeholders from a text-based template."""
    text = Path(path).read_text(encoding="utf-8")
    found = set()
    if fmt == "latex":
        for m in _LATEX_VAR_RE.finditer(text):
            found.add(m.group(1).strip())
        for m in _LATEX_TAG_RE.finditer(text):
            found.add(m.group(1).strip())
    else:
        for m in _JINJA_VAR_RE.finditer(text):
            found.add(m.group(1).strip())
        for m in _JINJA_TAG_RE.finditer(text):
            found.add(m.group(1).strip())
    return found


# ═══════════════════════════════════════════════════════════════════════════
#  CLI — standalone usage for testing
# ═══════════════════════════════════════════════════════════════════════════

def _cli():
    """CLI entry point for testing and validation."""
    import argparse
    parser = argparse.ArgumentParser(
        description="pr0t31n Report Engine — render report templates")
    sub = parser.add_subparsers(dest="cmd")

    # render
    rp = sub.add_parser("render", help="Render a template")
    rp.add_argument("template", help="Template file path")
    rp.add_argument("output", help="Output file path")
    rp.add_argument("--project-dir", help="Engagement project directory")
    rp.add_argument("--context-json", help="JSON file with context overrides")

    # validate
    vp = sub.add_parser("validate", help="Validate a template")
    vp.add_argument("template", help="Template file path")

    # schema
    sub.add_parser("schema", help="Print the placeholder schema")
    sub.add_parser("placeholders", help="Print flat placeholder list")

    args = parser.parse_args()

    if args.cmd == "schema":
        print(json.dumps(PLACEHOLDER_SCHEMA, indent=2))

    elif args.cmd == "placeholders":
        for p in get_placeholder_list():
            loop_tag = " [LOOP]" if p["loop"] else ""
            print(f"  {p['syntax']:<50} {p['description']}{loop_tag}")

    elif args.cmd == "validate":
        result = validate_template(args.template)
        print(json.dumps(result, indent=2))

    elif args.cmd == "render":
        ctx_overrides = {}
        if args.context_json:
            with open(args.context_json) as f:
                ctx_overrides = json.load(f)
        ctx = build_context(
            args.project_dir,
            report_overrides=ctx_overrides.get("report", {}),
        )
        ctx.update({k: v for k, v in ctx_overrides.items() if k != "report"})
        out = render_report(args.template, args.output, ctx)
        print(f"Rendered: {out}")

    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
