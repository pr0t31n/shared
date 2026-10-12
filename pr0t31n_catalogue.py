#!/usr/bin/env python3
"""
pr0t31n_catalogue.py — Findings-catalogue tooling for the pr0t31n toolkit.

Subcommands:
    extract      Pull every emitted finding title from a producer's source
    validate     Check a catalogue against the canonical v1.1 layout
    report       Produce gap report (titles-in-code vs catalogue entries) per tool
    merge        Merge per-tool catalogues into Arbiter's master, deduplicated
    scaffold     Generate skeleton catalogue entries for missing titles
                 (output JSON ready for human + web-research enrichment)

Usage:
    pr0t31n_catalogue.py report
    pr0t31n_catalogue.py extract /opt/pr0t31n/Fracture/fracture.py
    pr0t31n_catalogue.py validate /opt/pr0t31n/Arbiter/findings_catalogue.json
    pr0t31n_catalogue.py merge --output /tmp/master.json
    pr0t31n_catalogue.py scaffold --tool Auger --output /tmp/auger_skeleton.json

Canonical layout (Arbiter master v1.6.0+ — 31 fields per entry):
  id, title, aliases, source_tools, risk, cwe, cve_examples,
  cvss_v3_base, cvss_vector, nessus_plugin_ids, qualys_qids,
  owasp_web, owasp_api, nist_csf2, nist_800_53, nist_800_171,
  pci_dss_4, iso_27001, iso_27002, soc2, hitrust, gdpr,
  mitre_attack, searchsploit_terms, metasploit_modules, kev,
  remediation_brief, remediation_component, remediation_category,
  remediation_effort, validation_tools
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# ─── Canonical layout (Arbiter findings_catalogue.json — v1.7.0 = 33 fields) ──
# v1.7.0 added: description (what the finding is) + impact (why it matters)
CANONICAL_FIELDS = [
    "id", "title", "aliases", "source_tools", "risk", "cwe", "cve_examples",
    "cvss_v3_base", "cvss_vector", "nessus_plugin_ids", "qualys_qids",
    "owasp_web", "owasp_api", "nist_csf2", "nist_800_53", "nist_800_171",
    "pci_dss_4", "iso_27001", "iso_27002", "soc2", "hitrust", "gdpr",
    "mitre_attack", "searchsploit_terms", "metasploit_modules", "kev",
    "remediation_brief", "remediation_component", "remediation_category",
    "remediation_effort", "validation_tools",
    # v1.7.0 additions
    "description", "impact",
    # v1.8.0 additions — endpoint security frameworks
    "cis_benchmark", "disa_stig", "ms_security_baseline",
]

REQUIRED_FIELDS = {"id", "title", "risk", "description", "impact", "remediation_brief"}
LIST_FIELDS = {
    "aliases", "source_tools", "cwe", "cve_examples", "nessus_plugin_ids",
    "qualys_qids", "nist_csf2", "nist_800_53", "nist_800_171", "pci_dss_4",
    "iso_27001", "iso_27002", "soc2", "hitrust", "gdpr", "mitre_attack",
    "searchsploit_terms", "metasploit_modules", "validation_tools",
    "cis_benchmark", "disa_stig", "ms_security_baseline",
}
BOOL_FIELDS = {"kev"}
FLOAT_FIELDS = {"cvss_v3_base"}

VALID_RISK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# ─── Tool registry ──────────────────────────────────────────────────────────
TOOLS = {
    "Scattershot3": "/opt/pr0t31n/Scattershot3/scattershot3.py",
    "Fracture":     "/opt/pr0t31n/Fracture/fracture.py",
    "Siphon":       "/opt/pr0t31n/Siphon/siphon.py",
    "Auger":        "/opt/pr0t31n/Auger/auger.py",
    "Gearbox":      "/opt/pr0t31n/Gearbox/gearbox.py",
    "Aether":       "/opt/pr0t31n/Aether/aether.py",
    "Aether-B":     "/opt/pr0t31n/Aether-B/aether_b.py",
    "Aether-U":     "/opt/pr0t31n/Aether-U/aether_u.py",
    "Aether-Z":     "/opt/pr0t31n/Aether-Z/aether_z.py",
    "OSift":        "/opt/pr0t31n/OSift/osift.py",
    "AuthProbe":    "/opt/pr0t31n/AuthProbe/authprobe.py",
    "pAIn":         "/opt/pr0t31n/pAIn/pain.py",
    "Bastion":      "/opt/pr0t31n/Bastion/app.py",
    "Anvil":        "/opt/pr0t31n/Anvil/anvil.py",
    "Drift":        "/opt/pr0t31n/Drift/drift.py",
    "Forge":        "/opt/pr0t31n/Forge/forge.py",
    "Isotope":      "/opt/pr0t31n/Isotope/isotope.py",
    "Phalanx":      "/opt/pr0t31n/Phalanx/app.py",
    "Pivot":        "/opt/pr0t31n/Pivot/pivot/agent/main.py",
    "Quill":        "/opt/pr0t31n/Quill/quill.py",
    "Trawler":      "/opt/pr0t31n/Trawler/trawler.py",
    "Vault":        "/opt/pr0t31n/Vault/vault.py",
    "Dredge":       "/opt/pr0t31n/Dredge/dredge.py",
}

CATALOGUE_PATHS = {
    "Aether":       "/opt/pr0t31n/Aether/findings_catalogue.json",
    "Aether-B":     "/opt/pr0t31n/Aether-B/findings_catalogue.json",
    "Aether-U":     "/opt/pr0t31n/Aether-U/findings_catalogue.json",
    "Aether-Z":     "/opt/pr0t31n/Aether-Z/findings_catalogue.json",
    "Anvil":        "/opt/pr0t31n/Anvil/findings_catalogue.json",
    "Auger":        "/opt/pr0t31n/Auger/findings_catalogue.json",
    "AuthProbe":    "/opt/pr0t31n/AuthProbe/findings_catalogue.json",
    "Bastion":      "/opt/pr0t31n/Bastion/findings_catalogue.json",
    "Dredge":       "/opt/pr0t31n/Dredge/findings_catalogue.json",
    "Drift":        "/opt/pr0t31n/Drift/findings_catalogue.json",
    "Forge":        "/opt/pr0t31n/Forge/findings_catalogue.json",
    "Fracture":     "/opt/pr0t31n/Fracture/findings_catalogue.json",
    "Gearbox":      "/opt/pr0t31n/Gearbox/findings_catalogue.json",
    "Isotope":      "/opt/pr0t31n/Isotope/findings_catalogue.json",
    "OSift":        "/opt/pr0t31n/OSift/findings_catalogue.json",
    "pAIn":         "/opt/pr0t31n/pAIn/findings_catalogue.json",
    "Phalanx":      "/opt/pr0t31n/Phalanx/findings_catalogue.json",
    "Pivot":        "/opt/pr0t31n/Pivot/findings_catalogue.json",
    "Quill":        "/opt/pr0t31n/Quill/findings_catalogue.json",
    "Scattershot3": "/opt/pr0t31n/Scattershot3/findings_catalogue.json",
    "Siphon":       "/opt/pr0t31n/Siphon/findings_catalogue.json",
    "Trawler":      "/opt/pr0t31n/Trawler/findings_catalogue.json",
    "Vault":        "/opt/pr0t31n/Vault/findings_catalogue.json",
}

ARBITER_MASTER = "/opt/pr0t31n/shared/master_findings_catalogue.json"


# ─── Title extraction ──────────────────────────────────────────────────────
_TITLE_PATTERNS = [
    # title="..." / title='...' / title=f"..." (kwarg form)
    re.compile(r'''title\s*=\s*[fr]?(['"])([^'"\n]{3,250})\1'''),
    # "title": "..." (dict-literal form — used by some tools' add_finding callers)
    re.compile(r'''['"]title['"]\s*:\s*[fr]?(['"])([^'"\n]{3,250})\1'''),
]


def extract_titles(source_file: str) -> "list[dict]":
    """Extract all distinct finding titles from a Python source file.
    Returns list of {title, file, line, is_template}."""
    src = Path(source_file).read_text(encoding="utf-8", errors="replace")
    found: dict = {}
    for pat in _TITLE_PATTERNS:
        for m in pat.finditer(src):
            title = m.group(2).strip()
            if not title or title.startswith("{") or len(title) < 4:
                continue
            # Compute line number from offset
            line = src[:m.start()].count("\n") + 1
            is_tmpl = "{" in title and "}" in title
            key = title
            if key not in found:
                found[key] = {
                    "title":       title,
                    "file":        source_file,
                    "line":        line,
                    "is_template": is_tmpl,
                }
    return sorted(found.values(), key=lambda r: (not r["is_template"], r["title"].lower()))


# ─── Validation ────────────────────────────────────────────────────────────
def validate_entry(entry: dict, idx: int = 0) -> "list[str]":
    """Validate a single catalogue entry against the canonical layout."""
    if not isinstance(entry, dict):
        return [f"entry {idx}: not a dict"]
    errs = []
    # Required
    for f in REQUIRED_FIELDS:
        if f not in entry or entry[f] in (None, ""):
            errs.append(f"entry {idx} ({entry.get('id', '?')}): missing required '{f}'")
    # Risk
    r = entry.get("risk", "")
    if r and r not in VALID_RISK:
        errs.append(f"entry {idx} ({entry.get('id', '?')}): invalid risk '{r}'")
    # Type coercion checks
    for lf in LIST_FIELDS:
        if lf in entry and not isinstance(entry[lf], list):
            errs.append(f"entry {idx} ({entry.get('id', '?')}): field '{lf}' must be list, got {type(entry[lf]).__name__}")
    for bf in BOOL_FIELDS:
        if bf in entry and not isinstance(entry[bf], bool):
            errs.append(f"entry {idx} ({entry.get('id', '?')}): field '{bf}' must be bool")
    for ff in FLOAT_FIELDS:
        if ff in entry and not isinstance(entry[ff], (int, float, type(None))):
            errs.append(f"entry {idx} ({entry.get('id', '?')}): field '{ff}' must be number or null")
    # Unknown fields (warning, not error — extras tolerated)
    return errs


def validate_catalogue(path: str) -> dict:
    """Validate an entire catalogue file. Returns summary dict."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        return {"path": path, "ok": False, "error": f"cannot parse: {e}", "entries": 0, "errors": []}
    findings = data if isinstance(data, list) else data.get("findings", [])
    errors = []
    for i, entry in enumerate(findings):
        errors.extend(validate_entry(entry, i))
    # Missing-field counts across entries
    missing = defaultdict(int)
    for entry in findings:
        if isinstance(entry, dict):
            for f in CANONICAL_FIELDS:
                if f not in entry:
                    missing[f] += 1
    return {
        "path":             path,
        "ok":               len(errors) == 0,
        "entries":          len(findings),
        "errors":           errors[:20],
        "errors_truncated": len(errors) > 20,
        "missing_field_counts": dict(missing),
        "field_coverage": {f: len(findings) - missing[f] for f in CANONICAL_FIELDS},
    }


# ─── Merger ────────────────────────────────────────────────────────────────
def _normalise_to_canonical(entry: dict, source_tool: str) -> dict:
    """Lift a per-tool entry to canonical shape — fills missing fields with
    sensible defaults, maps tool-specific keys onto canonical ones."""
    out = {f: ([] if f in LIST_FIELDS else (False if f in BOOL_FIELDS else
                (None if f in FLOAT_FIELDS else "")))
           for f in CANONICAL_FIELDS}
    if not isinstance(entry, dict):
        return out
    # Direct passthroughs
    for f in CANONICAL_FIELDS:
        if f in entry and entry[f] not in (None, "", []):
            out[f] = entry[f]
    # Field aliasing — handle per-tool variants
    if "severity" in entry and not out.get("risk"):
        out["risk"] = str(entry["severity"]).upper()
    if "cvss_score" in entry and not out.get("cvss_v3_base"):
        try:
            out["cvss_v3_base"] = float(entry["cvss_score"])
        except (TypeError, ValueError):
            pass
    if "cves" in entry and not out.get("cve_examples"):
        v = entry["cves"]
        if isinstance(v, list):
            out["cve_examples"] = v
        elif isinstance(v, str):
            out["cve_examples"] = [c.strip() for c in v.split(",") if c.strip()]
    if "owasp" in entry and not out.get("owasp_web"):
        out["owasp_web"] = entry["owasp"]
    if "references" in entry and not out.get("validation_tools"):
        # 'references' is the closest analog
        v = entry["references"]
        if isinstance(v, list):
            out["validation_tools"] = v
    if "remediation" in entry and not out.get("remediation_brief"):
        out["remediation_brief"] = entry["remediation"]
    # v1.7.0 aliases — many existing per-tool catalogues use 'description' already
    if "description" in entry and not out.get("description"):
        out["description"] = entry["description"]
    # 'impact' is a fresh field; if not present, leave blank for enrichment
    if "impact" in entry and not out.get("impact"):
        out["impact"] = entry["impact"]
    # Normalise risk to uppercase
    if out.get("risk"):
        out["risk"] = str(out["risk"]).upper()
    # Always tag source_tool
    st = out.get("source_tools") or []
    if isinstance(st, str):
        st = [st]
    if source_tool and source_tool not in st:
        st.append(source_tool)
    out["source_tools"] = st
    return out


def merge_catalogues(include_master: bool = True) -> dict:
    """Merge per-tool catalogues + Arbiter master, deduplicated by title-lowercase.
    Returns a dict with 'findings' + 'sources' (which tools contributed each)."""
    merged: dict = {}
    sources_by_title = defaultdict(set)

    if include_master:
        try:
            mdata = json.loads(Path(ARBITER_MASTER).read_text(encoding="utf-8"))
            for entry in mdata.get("findings", []):
                if not isinstance(entry, dict):
                    continue
                key = (entry.get("title") or "").strip().lower()
                if not key:
                    continue
                merged[key] = _normalise_to_canonical(entry, "arbiter_master")
                sources_by_title[key].add("arbiter_master")
        except Exception as e:
            print(f"WARNING: could not read Arbiter master: {e}", file=sys.stderr)

    for tool, path in CATALOGUE_PATHS.items():
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"WARNING: skipping {tool}: {e}", file=sys.stderr)
            continue
        findings = data if isinstance(data, list) else (data.get("findings") or data.get("entries") or [])
        for entry in findings:
            if not isinstance(entry, dict):
                continue
            key = (entry.get("title") or "").strip().lower()
            if not key:
                continue
            if key in merged:
                # Merge: union source_tools + aliases + cve_examples
                existing = merged[key]
                new = _normalise_to_canonical(entry, tool.lower())
                # Union list-type fields — handle hashable (str/int) and dict (mitre_attack) entries
                for lf in LIST_FIELDS:
                    existing_list = existing.get(lf) or []
                    seen = set()
                    seen_dict_keys = []  # for dict items: store comparable repr
                    for v in existing_list:
                        if isinstance(v, dict):
                            k = json.dumps(v, sort_keys=True)
                            seen_dict_keys.append(k)
                        else:
                            seen.add(v)
                    for v in (new.get(lf) or []):
                        if isinstance(v, dict):
                            k = json.dumps(v, sort_keys=True)
                            if k not in seen_dict_keys:
                                existing_list.append(v)
                                seen_dict_keys.append(k)
                        elif v not in seen:
                            existing_list.append(v)
                            seen.add(v)
                    existing[lf] = existing_list
                # Take stronger risk if missing
                if not existing.get("risk") and new.get("risk"):
                    existing["risk"] = new["risk"]
                # Take cvss if missing
                if existing.get("cvss_v3_base") is None and new.get("cvss_v3_base") is not None:
                    existing["cvss_v3_base"] = new["cvss_v3_base"]
                sources_by_title[key].add(tool.lower())
            else:
                merged[key] = _normalise_to_canonical(entry, tool.lower())
                sources_by_title[key].add(tool.lower())

    findings_out = sorted(merged.values(), key=lambda e: e.get("id", "") or e.get("title", ""))
    return {
        "version":       "merged-1.0",
        "generated":     "(use --output)",
        "source_tools":  sorted({s for src in sources_by_title.values() for s in src}),
        "findings":      findings_out,
        "_summary": {
            "total_entries":      len(findings_out),
            "from_master_only":   sum(1 for k, s in sources_by_title.items() if s == {"arbiter_master"}),
            "from_tools_only":    sum(1 for k, s in sources_by_title.items() if "arbiter_master" not in s),
            "in_master_and_tool": sum(1 for k, s in sources_by_title.items() if "arbiter_master" in s and len(s) > 1),
        },
    }


# ─── Report ────────────────────────────────────────────────────────────────
def report() -> None:
    """Per-tool gap report — titles in code vs catalogue entries."""
    print(f"{'Tool':<15} {'Code titles':>11} {'Catalogue':>10} {'Gap':>6} {'Catalogue path'}")
    print("-" * 95)
    for tool, src in TOOLS.items():
        if not Path(src).exists():
            print(f"{tool:<15} {'-':>11} {'-':>10} {'-':>6} (source missing)")
            continue
        code_titles = extract_titles(src)
        n_code = len(code_titles)
        cat_path = CATALOGUE_PATHS.get(tool, "")
        if cat_path and Path(cat_path).exists():
            try:
                data = json.loads(Path(cat_path).read_text(encoding="utf-8"))
                findings = data if isinstance(data, list) else (data.get("findings") or data.get("entries") or [])
                n_cat = len(findings)
            except Exception:
                n_cat = 0
        else:
            n_cat = 0
        gap = n_code - n_cat
        gap_str = f"+{gap}" if gap > 0 else str(gap)
        cat_display = cat_path or "(none)"
        print(f"{tool:<15} {n_code:>11} {n_cat:>10} {gap_str:>6} {cat_display}")
    print()
    # Arbiter master
    try:
        mdata = json.loads(Path(ARBITER_MASTER).read_text(encoding="utf-8"))
        print(f"Arbiter master: {len(mdata.get('findings', []))} entries · v{mdata.get('version', '?')}")
    except Exception as e:
        print(f"Arbiter master: ERROR {e}")


# ─── Scaffold ──────────────────────────────────────────────────────────────
def scaffold(tool: str, out_path: str) -> None:
    """Generate skeleton catalogue entries for every title not yet catalogued."""
    if tool not in TOOLS:
        print(f"ERROR: unknown tool '{tool}'. Known: {list(TOOLS)}", file=sys.stderr)
        sys.exit(2)
    src = TOOLS[tool]
    code_titles = extract_titles(src)
    code_set = {t["title"].strip().lower() for t in code_titles}
    cat_titles = set()
    cat_path = CATALOGUE_PATHS.get(tool, "")
    if cat_path and Path(cat_path).exists():
        try:
            data = json.loads(Path(cat_path).read_text(encoding="utf-8"))
            findings = data if isinstance(data, list) else (data.get("findings") or data.get("entries") or [])
            for e in findings:
                if isinstance(e, dict) and e.get("title"):
                    cat_titles.add(e["title"].strip().lower())
        except Exception:
            pass
    missing = [t for t in code_titles if t["title"].strip().lower() not in cat_titles]
    skeleton_entries = []
    next_id_num = 1
    tool_prefix = {"Scattershot3": "SS", "Fracture": "FR", "Siphon": "SI",
                   "Auger": "AU", "Gearbox": "GB", "Aether": "AE",
                   "OSift": "OS", "AuthProbe": "AP", "pAIn": "PI",
                   "Bastion": "BA", "Dredge": "DR"}.get(tool, tool[:2].upper())
    for t in missing:
        entry = {f: ([] if f in LIST_FIELDS else (False if f in BOOL_FIELDS else
                     (None if f in FLOAT_FIELDS else "")))
                 for f in CANONICAL_FIELDS}
        entry["id"]            = f"{tool_prefix}-{next_id_num:03d}"
        entry["title"]         = t["title"]
        entry["source_tools"]  = [tool.lower()]
        entry["risk"]          = ""  # FILL IN
        entry["remediation_brief"] = ""  # FILL IN
        entry["_scaffold_from"] = f"{Path(src).name}:{t['line']}"
        entry["_template"]      = t["is_template"]
        skeleton_entries.append(entry)
        next_id_num += 1
    out = {
        "tool":          tool,
        "version":       "scaffold-1.0",
        "missing_count": len(missing),
        "findings":      skeleton_entries,
    }
    Path(out_path).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Scaffolded {len(missing)} entries for {tool} → {out_path}")
    print(f"  Fill in: risk, remediation_brief, cwe, cve_examples, cvss_v3_base,")
    print(f"           cvss_vector, framework lists, mitre_attack")


# ─── Schema upgrade ────────────────────────────────────────────────────────
def upgrade_catalogue(path: str, output: str, source_tool: str = "") -> dict:
    """
    Upgrade an existing per-tool catalogue to the canonical 31-field shape.
    Preserves all existing data; adds missing canonical fields with empty
    defaults; normalises field aliasing (severity→risk, cves→cve_examples,
    cvss_score→cvss_v3_base, owasp→owasp_web, remediation→remediation_brief).
    Returns summary.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = data if isinstance(data, list) else data.get("findings", [])
    upgraded = []
    fields_added = defaultdict(int)
    for entry in findings:
        before_keys = set(entry.keys()) if isinstance(entry, dict) else set()
        normalised = _normalise_to_canonical(entry, source_tool)
        # Record which fields are NEW (added by upgrade)
        for f in CANONICAL_FIELDS:
            if f not in before_keys:
                fields_added[f] += 1
        # Preserve unknown extension fields from the original
        if isinstance(entry, dict):
            for k, v in entry.items():
                if k not in CANONICAL_FIELDS and not k.startswith("_"):
                    normalised[f"_x_{k}"] = v
        upgraded.append(normalised)
    out_doc = {
        "version":     "1.6.0",
        "generated":   "(upgraded — preserve enrichment via web research)",
        "tool":        source_tool or "unknown",
        "findings":    upgraded,
    }
    Path(output).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    return {
        "input":         path,
        "output":        output,
        "entries":       len(upgraded),
        "fields_added":  dict(fields_added),
    }


def scaffold_missing(tool: str, output: str) -> dict:
    """
    Generate skeleton entries ONLY for code-emitted titles that are missing
    from the existing catalogue. Each skeleton is canonical-shape with empty
    enrichment fields, ready for web-research filling.
    """
    if tool not in TOOLS:
        raise ValueError(f"unknown tool '{tool}'")
    src = TOOLS[tool]
    code_titles = extract_titles(src)
    cat_path = CATALOGUE_PATHS.get(tool, "")
    cat_titles_lower = set()
    next_id_num = 1
    tool_prefix = {"Scattershot3": "SS", "Fracture": "FR", "Siphon": "SI",
                   "Auger": "AU", "Gearbox": "GB", "Aether": "AE",
                   "OSift": "OS", "AuthProbe": "AP", "pAIn": "PI",
                   "Bastion": "BA", "Dredge": "DR"}.get(tool, tool[:2].upper())
    if cat_path and Path(cat_path).exists():
        try:
            data = json.loads(Path(cat_path).read_text(encoding="utf-8"))
            findings = data if isinstance(data, list) else (data.get("findings") or data.get("entries") or [])
            existing_ids = []
            for e in findings:
                if isinstance(e, dict):
                    if e.get("title"):
                        cat_titles_lower.add(e["title"].strip().lower())
                    if e.get("id", "").startswith(f"{tool_prefix}-"):
                        try:
                            existing_ids.append(int(e["id"].split("-", 1)[1]))
                        except (ValueError, IndexError):
                            pass
            if existing_ids:
                next_id_num = max(existing_ids) + 1
        except Exception:
            pass
    missing = [t for t in code_titles
               if t["title"].strip().lower() not in cat_titles_lower]
    skeleton_entries = []
    for t in missing:
        entry = {f: ([] if f in LIST_FIELDS else (False if f in BOOL_FIELDS else
                     (None if f in FLOAT_FIELDS else "")))
                 for f in CANONICAL_FIELDS}
        entry["id"]            = f"{tool_prefix}-{next_id_num:03d}"
        entry["title"]         = t["title"]
        entry["source_tools"]  = [tool.lower()]
        # Risk-from-context heuristics — leave as "" for human enrichment
        entry["risk"]          = ""
        entry["remediation_brief"] = ""
        entry["_scaffold_from"] = f"{Path(src).name}:{t['line']}"
        entry["_template"]      = t["is_template"]
        skeleton_entries.append(entry)
        next_id_num += 1
    out_doc = {
        "version":       "scaffold-1.0",
        "tool":          tool,
        "missing_count": len(missing),
        "total_code":    len(code_titles),
        "in_catalogue":  len(cat_titles_lower),
        "findings":      skeleton_entries,
    }
    Path(output).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    return {"missing_added": len(missing),
            "total_in_code": len(code_titles),
            "already_in_catalogue": len(cat_titles_lower)}


def write_complete_catalogue(tool: str, output: str) -> dict:
    """
    Produce a COMPLETE per-tool catalogue: existing entries (upgraded to 31-field
    shape) PLUS scaffolded entries for any missing code titles.
    This is the per-tool catalogue ready to be deployed back into the tool's repo.
    """
    if tool not in TOOLS:
        raise ValueError(f"unknown tool '{tool}'")
    src = TOOLS[tool]
    cat_path = CATALOGUE_PATHS.get(tool, "")
    tool_lower = tool.lower()
    tool_prefix = {"Scattershot3": "SS", "Fracture": "FR", "Siphon": "SI",
                   "Auger": "AU", "Gearbox": "GB", "Aether": "AE",
                   "OSift": "OS", "AuthProbe": "AP", "pAIn": "PI",
                   "Bastion": "BA", "Dredge": "DR"}.get(tool, tool[:2].upper())

    # Step 1 — load + upgrade existing entries
    existing_normalised = []
    cat_titles_lower = set()
    existing_id_nums = []
    if cat_path and Path(cat_path).exists():
        try:
            data = json.loads(Path(cat_path).read_text(encoding="utf-8"))
            findings = data if isinstance(data, list) else (data.get("findings") or data.get("entries") or [])
            for entry in findings:
                if not isinstance(entry, dict):
                    continue
                norm = _normalise_to_canonical(entry, tool_lower)
                # Preserve unknown extension fields
                for k, v in entry.items():
                    if k not in CANONICAL_FIELDS and not k.startswith("_"):
                        norm[f"_x_{k}"] = v
                existing_normalised.append(norm)
                if norm.get("title"):
                    cat_titles_lower.add(norm["title"].strip().lower())
                if norm.get("id", "").startswith(f"{tool_prefix}-"):
                    try:
                        existing_id_nums.append(int(norm["id"].split("-", 1)[1]))
                    except (ValueError, IndexError):
                        pass
        except Exception as e:
            print(f"WARNING: could not load existing catalogue: {e}", file=sys.stderr)

    # Step 2 — scaffold missing code titles
    code_titles = extract_titles(src)
    next_id_num = (max(existing_id_nums) + 1) if existing_id_nums else 1
    new_scaffolded = []
    for t in code_titles:
        if t["title"].strip().lower() in cat_titles_lower:
            continue
        entry = {f: ([] if f in LIST_FIELDS else (False if f in BOOL_FIELDS else
                     (None if f in FLOAT_FIELDS else "")))
                 for f in CANONICAL_FIELDS}
        entry["id"]            = f"{tool_prefix}-{next_id_num:03d}"
        entry["title"]         = t["title"]
        entry["source_tools"]  = [tool_lower]
        entry["risk"]          = ""
        entry["remediation_brief"] = ""
        entry["_scaffold_from"] = f"{Path(src).name}:{t['line']}"
        entry["_template"]      = t["is_template"]
        new_scaffolded.append(entry)
        next_id_num += 1

    # Combine + write
    all_entries = existing_normalised + new_scaffolded
    out_doc = {
        "version":       "1.6.0",
        "tool":          tool_lower,
        "generated":     "(complete: upgraded existing + scaffolded missing)",
        "total":         len(all_entries),
        "from_existing": len(existing_normalised),
        "newly_scaffolded": len(new_scaffolded),
        "findings":      all_entries,
    }
    Path(output).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    return {
        "total":             len(all_entries),
        "from_existing":     len(existing_normalised),
        "newly_scaffolded":  len(new_scaffolded),
    }


# ─── Main ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="pr0t31n catalogue tooling")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ext = sub.add_parser("extract", help="extract titles from a source file")
    p_ext.add_argument("source_file")
    p_ext.add_argument("--templates-only", action="store_true",
                       help="only show f-string templates")

    p_val = sub.add_parser("validate", help="validate a catalogue against canonical layout")
    p_val.add_argument("catalogue_file")

    sub.add_parser("report", help="per-tool code-vs-catalogue gap report")

    p_mrg = sub.add_parser("merge", help="merge per-tool + master into one catalogue")
    p_mrg.add_argument("--output", required=True)
    p_mrg.add_argument("--exclude-master", action="store_true",
                       help="merge per-tool only; ignore Arbiter master")

    p_sc = sub.add_parser("scaffold", help="scaffold missing catalogue entries for a tool")
    p_sc.add_argument("--tool", required=True)
    p_sc.add_argument("--output", required=True)

    p_up = sub.add_parser("upgrade", help="upgrade an existing catalogue to canonical 31-field shape")
    p_up.add_argument("--catalogue", required=True)
    p_up.add_argument("--output", required=True)
    p_up.add_argument("--tool", default="")

    p_co = sub.add_parser("complete", help="produce a COMPLETE per-tool catalogue (upgrade existing + scaffold missing)")
    p_co.add_argument("--tool", required=True)
    p_co.add_argument("--output", required=True)

    args = ap.parse_args()

    if args.cmd == "extract":
        titles = extract_titles(args.source_file)
        if args.templates_only:
            titles = [t for t in titles if t["is_template"]]
        for t in titles:
            tag = "TMPL" if t["is_template"] else "    "
            print(f"  [{tag}] line {t['line']:5d}  {t['title']}")
        print(f"\n{len(titles)} title(s) extracted")
    elif args.cmd == "validate":
        result = validate_catalogue(args.catalogue_file)
        print(f"Validating: {result['path']}")
        print(f"  Entries:  {result['entries']}")
        print(f"  Status:   {'PASS' if result['ok'] else 'FAIL'}")
        if result["errors"]:
            print(f"  Errors (first 20):")
            for e in result["errors"]:
                print(f"    - {e}")
            if result["errors_truncated"]:
                print(f"    ... (additional errors not shown)")
        print(f"  Field coverage (entries with value present):")
        for f in CANONICAL_FIELDS:
            cov = result["field_coverage"][f]
            pct = (100.0 * cov / result["entries"]) if result["entries"] else 0
            print(f"    {f:25s} {cov:5d} ({pct:5.1f}%)")
    elif args.cmd == "report":
        report()
    elif args.cmd == "merge":
        merged = merge_catalogues(include_master=not args.exclude_master)
        from datetime import datetime
        merged["generated"] = datetime.now().strftime("%Y-%m-%d")
        Path(args.output).write_text(json.dumps(merged, indent=2), encoding="utf-8")
        print(f"Merged catalogue written → {args.output}")
        print(f"  Total entries:       {merged['_summary']['total_entries']}")
        print(f"  From master only:    {merged['_summary']['from_master_only']}")
        print(f"  From tools only:     {merged['_summary']['from_tools_only']}")
        print(f"  In master + tool:    {merged['_summary']['in_master_and_tool']}")
    elif args.cmd == "scaffold":
        scaffold(args.tool, args.output)
    elif args.cmd == "upgrade":
        result = upgrade_catalogue(args.catalogue, args.output, args.tool)
        print(f"Upgraded {result['entries']} entries → {result['output']}")
        if result["fields_added"]:
            print(f"  Fields added (count of entries gaining the field):")
            for f, n in sorted(result["fields_added"].items(), key=lambda x: -x[1]):
                print(f"    {f:25s} {n:5d}")
    elif args.cmd == "complete":
        result = write_complete_catalogue(args.tool, args.output)
        print(f"Wrote complete catalogue for {args.tool} → {args.output}")
        print(f"  Total entries:   {result['total']}")
        print(f"  Upgraded existing: {result['from_existing']}")
        list_field_str = f"  New scaffolded:    {result['newly_scaffolded']}"
        print(list_field_str)


if __name__ == "__main__":
    main()
