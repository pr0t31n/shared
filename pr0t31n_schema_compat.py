"""pr0t31n_schema_compat.py — single-source-of-truth helpers that fix
recurring schema bugs across the toolkit.

Bugs addressed:

  G2 (Gearbox): "Informational" → make_finding() upper-cases to
      "INFORMATIONAL" which is not in RISK_LEVELS, causing summary.json
      to always show 0 INFO findings.  normalize_risk() folds both
      INFORMATIONAL and INFORMATIONAL to INFO before make_finding is called.

  TitleCase native risk in Bastion/Gauntlet/Gearbox: the same
      normalize_risk() upper-cases AND folds Informational/Informational.

  output_file absolute paths (Scattershot3/OSift/Siphon/Fracture/Aether
      family/Gauntlet/Auger): finding_with_evidence() routes every value
      through schema.to_relative_output_file() so producers can stop
      worrying about it.

  Comma-joined output_file in Siphon (f"{_rq},{_rp}"): split_evidence_pair()
      promotes the second path into the new "request_file"/"response_file"
      slots (additive — backward-compatible with existing parsers that
      treat output_file as one path).
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional


VERSION = "1.0.0"
logger = logging.getLogger(__name__)


# Bootstrap path so callers don't need to know where shared lives.
if "/opt/pr0t31n/shared" not in sys.path:
    sys.path.insert(0, "/opt/pr0t31n/shared")

try:
    import pr0t31n_schema as _us
    _HAVE_SCHEMA = True
except ImportError:
    _us = None
    _HAVE_SCHEMA = False
    logger.warning("pr0t31n_schema not installed; compat layer degraded")


# ── Risk normalisation ─────────────────────────────────────────────────


_RISK_ALIASES = {
    # canonical
    "CRITICAL":       "CRITICAL",
    "HIGH":           "HIGH",
    "MEDIUM":         "MEDIUM",
    "LOW":            "LOW",
    "INFO":           "INFO",
    # TitleCase folds (Bastion, Gauntlet, Gearbox native pipeline)
    "Critical":       "CRITICAL",
    "High":           "HIGH",
    "Medium":         "MEDIUM",
    "Low":            "LOW",
    "Informational":  "INFO",   # G2 fix
    # All-caps mis-folds make_finding produced before the fix
    "INFORMATIONAL":  "INFO",   # G2 fix — folds legacy storage
    "INFORMATION":    "INFO",
    "INFOMATIONAL":   "INFO",   # typo seen in the wild
    # Numeric / synonym tolerance
    "CRIT":           "CRITICAL",
    "WARN":           "LOW",
    "WARNING":        "LOW",
    "MED":            "MEDIUM",
    "NONE":           "INFO",
    "":               "INFO",
}


def normalize_risk(risk: str | None) -> str:
    """Return one of CRITICAL/HIGH/MEDIUM/LOW/INFO.

    Tolerant of None, empty, TitleCase, all-caps mis-folds. Default INFO
    is the safe fallback — the producer should never inflate risk via
    typo, only ever deflate.
    """
    if risk is None: return "INFO"
    raw = str(risk).strip()
    if not raw: return "INFO"
    canon = _RISK_ALIASES.get(raw)
    if canon: return canon
    upper = raw.upper()
    canon = _RISK_ALIASES.get(upper)
    if canon: return canon
    logger.warning("normalize_risk: unrecognised risk %r — defaulting INFO", risk)
    return "INFO"


# ── Evidence path helpers (§13c) ───────────────────────────────────────


def to_relative_output_file(abs_path: str | Path | None,
                            run_dir: str | Path | None) -> str:
    """Wrap schema.to_relative_output_file with graceful fallback.

    Producers can pass an absolute path + run_dir and get a §13c-compliant
    relative path. Returns the input unchanged when run_dir is None or
    schema isn't installed (degrades to legacy behaviour rather than
    crashing the scan).
    """
    if abs_path is None or abs_path == "":
        return ""
    if run_dir is None or not _HAVE_SCHEMA:
        return str(abs_path)
    try:
        return _us.to_relative_output_file(str(abs_path), str(run_dir))
    except (ValueError, OSError) as exc:
        logger.debug("to_relative_output_file fallback: %s", exc)
        return str(abs_path)


def make_finding_safe(*, run_dir: str | Path | None = None,
                      output_file: str | Path | None = "",
                      risk: str = "INFO",
                      **kwargs) -> dict:
    """Drop-in replacement for schema.make_finding that:
      1. Normalises risk (folds Informational → INFO).
      2. Routes output_file through to_relative_output_file when run_dir is given.
      3. Falls back to a minimal dict if schema isn't installed.
    """
    if "title" not in kwargs:
        raise ValueError("make_finding_safe: title is required")
    rel = to_relative_output_file(output_file, run_dir) if output_file else ""
    risk_canon = normalize_risk(risk)

    if not _HAVE_SCHEMA:
        # Minimal fallback so producers keep working in dev/CI without shared.
        return {
            "id": kwargs.get("id", ""),
            "tool": kwargs.get("tool", ""),
            "title": kwargs["title"],
            "ip": kwargs.get("ip", ""),
            "port": int(kwargs.get("port") or 0),
            "risk": risk_canon,
            "command": kwargs.get("command", ""),
            "description": kwargs.get("description", ""),
            "output_file": rel,
            "sources": kwargs.get("sources", ""),
            **{k: v for k, v in kwargs.items() if k not in (
                "id","tool","title","ip","port","command","description","sources")},
        }

    # Defaults for fields make_finding requires
    kwargs.setdefault("ip", "")
    kwargs.setdefault("port", 0)
    kwargs.setdefault("command", "")
    kwargs.setdefault("description", "")
    kwargs.setdefault("remediation", "")
    kwargs.setdefault("sources", "")
    kwargs.setdefault("affected", "")
    return _us.make_finding(risk=risk_canon, output_file=rel, **kwargs)


def split_evidence_pair(combined: str) -> tuple[str, str]:
    """Siphon-style 'request_file,response_file' comma-joined paths.
    Returns (request_path, response_path). When the input doesn't
    contain a comma, returns (combined, '')."""
    if not combined or "," not in combined:
        return combined or "", ""
    parts = combined.split(",", 1)
    return parts[0].strip(), parts[1].strip()


def evidence_pair_extra(rq: str, rp: str, run_dir: str | Path | None) -> dict:
    """Return {request_file, response_file} extras for findings that have
    two evidence files (Siphon HTTP request+response pairs). Both routed
    through to_relative_output_file."""
    return {
        "request_file":  to_relative_output_file(rq, run_dir),
        "response_file": to_relative_output_file(rp, run_dir),
    }


# ── Universal output writer with risk-fold ─────────────────────────────


def write_universal_findings(run_dir: str | Path,
                              findings: list[dict],
                              *, tool: str, version: str) -> Path | None:
    """Drop-in replacement for schema.write_universal_findings that
    folds every finding's risk through normalize_risk BEFORE writing.

    G2 fix — ensures findings.json risk values are always one of
    CRITICAL/HIGH/MEDIUM/LOW/INFO and summary.json INFO counts populate.
    """
    if not _HAVE_SCHEMA:
        return None
    fixed = []
    for f in findings:
        if not isinstance(f, dict): continue
        f = dict(f)
        f["risk"] = normalize_risk(f.get("risk"))
        fixed.append(f)
    return _us.write_universal_findings(run_dir, fixed, tool=tool, version=version)


def write_summary(run_dir: str | Path, summary: dict) -> Path | None:
    """Wraps schema.write_summary to defend against INFORMATIONAL keys
    in risk_counts (G2 cleanup at the summary layer too)."""
    if not _HAVE_SCHEMA:
        return None
    summary = dict(summary)
    rc = dict(summary.get("risk_counts") or {})
    fixed_rc: dict[str, int] = {}
    for k, v in rc.items():
        fixed_rc[normalize_risk(k)] = fixed_rc.get(normalize_risk(k), 0) + int(v or 0)
    summary["risk_counts"] = fixed_rc
    return _us.write_summary(run_dir, summary)
