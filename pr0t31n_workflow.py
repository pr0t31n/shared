"""
pr0t31n_workflow.py — Shared finding-workflow actions for pr0t31n Flask apps.

Provides the per-finding triage workflow that Bastion (accept_finding, add_note)
and Gauntlet (update_finding_risk) pioneered, packaged so any management app
can adopt all three with one import:

    set_risk(project_dir, finding_id, new_risk, reason, operator)
    accept_finding(project_dir, finding_id, justification, accepted_by)
    unaccept_finding(project_dir, finding_id, operator)
    add_note(project_dir, finding_id, note_text, author)
    remove_note(project_dir, finding_id, note_idx)

The workflow data lives in three sidecar files alongside the tool's native
findings file — never modifying the producer-emitted findings directly:

    findingNotes.json        — { finding_id: [ {ts, author, text}, ... ] }
    findingRiskOverrides.json — { finding_id: {original, new, reason, operator, ts} }
    findingAcceptances.json   — { finding_id: {justification, accepted_by, ts, active} }

When the universal-schema findings.json is loaded (post-migration), helpers
in this module can merge the sidecar data INTO each finding dict at read
time so consumers see a single enriched object with:
    f["risk"]              — overridden risk (if any), else original
    f["original_risk"]     — what the producer emitted
    f["accepted"]          — bool, from acceptances sidecar
    f["acceptance"]        — {justification, accepted_by, ts} when accepted
    f["analyst_notes"]     — list of note dicts

Sidecars are read-mostly; mutations atomic via tmpfile + rename + lock.

Distribution: VENDORED. Each app imports from /opt/pr0t31n/shared/.
stdlib only.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "notes_path", "overrides_path", "acceptances_path",
    "load_notes", "load_overrides", "load_acceptances",
    "set_risk", "unset_risk",
    "accept_finding", "unaccept_finding",
    "add_note", "remove_note",
    "enrich_findings",
]

_lock = threading.Lock()


# ─── Paths ──────────────────────────────────────────────────────────────────
def notes_path(project_dir):       return Path(project_dir) / "findingNotes.json"
def overrides_path(project_dir):   return Path(project_dir) / "findingRiskOverrides.json"
def acceptances_path(project_dir): return Path(project_dir) / "findingAcceptances.json"


# ─── Loaders (safe defaults) ────────────────────────────────────────────────
def _load(path, default):
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def load_notes(project_dir):       return _load(notes_path(project_dir), {})
def load_overrides(project_dir):   return _load(overrides_path(project_dir), {})
def load_acceptances(project_dir): return _load(acceptances_path(project_dir), {})


def _atomic_write_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Risk override ──────────────────────────────────────────────────────────
_VALID_RISK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def set_risk(project_dir, finding_id, new_risk, *,
             original_risk="", reason="", operator=""):
    """Record an analyst risk override. Returns the override record."""
    new_risk = str(new_risk or "").upper()
    if new_risk not in _VALID_RISK:
        raise ValueError(f"invalid risk '{new_risk}'; must be one of {sorted(_VALID_RISK)}")
    if not finding_id:
        raise ValueError("finding_id required")
    with _lock:
        d = load_overrides(project_dir)
        d[finding_id] = {
            "original": original_risk,
            "new":      new_risk,
            "reason":   reason,
            "operator": operator,
            "ts":       _now(),
        }
        _atomic_write_json(overrides_path(project_dir), d)
        return d[finding_id]


def unset_risk(project_dir, finding_id):
    """Remove a risk override, restoring the producer-emitted risk."""
    with _lock:
        d = load_overrides(project_dir)
        removed = d.pop(finding_id, None)
        if removed is not None:
            _atomic_write_json(overrides_path(project_dir), d)
        return removed


# ─── Accept-with-justification ─────────────────────────────────────────────
def accept_finding(project_dir, finding_id, *, justification, accepted_by=""):
    """Mark a finding as accepted (known-good-but-flagged). Justification required."""
    if not finding_id:
        raise ValueError("finding_id required")
    if not (justification or "").strip():
        raise ValueError("justification is required for accept")
    with _lock:
        d = load_acceptances(project_dir)
        d[finding_id] = {
            "justification": justification.strip(),
            "accepted_by":   accepted_by or "",
            "ts":            _now(),
            "active":        True,
        }
        _atomic_write_json(acceptances_path(project_dir), d)
        return d[finding_id]


def unaccept_finding(project_dir, finding_id, operator=""):
    """Mark an acceptance as inactive (preserves history)."""
    with _lock:
        d = load_acceptances(project_dir)
        if finding_id in d:
            d[finding_id]["active"] = False
            d[finding_id]["unaccepted_by"] = operator
            d[finding_id]["unaccepted_ts"] = _now()
            _atomic_write_json(acceptances_path(project_dir), d)
            return d[finding_id]
        return None


# ─── Analyst notes ─────────────────────────────────────────────────────────
def add_note(project_dir, finding_id, note_text, author=""):
    """Append a note to the finding. Returns the new note record."""
    if not finding_id:
        raise ValueError("finding_id required")
    if not (note_text or "").strip():
        raise ValueError("note text required")
    with _lock:
        d = load_notes(project_dir)
        notes = d.setdefault(finding_id, [])
        rec = {
            "ts":     _now(),
            "author": author or "",
            "text":   note_text.strip(),
        }
        notes.append(rec)
        _atomic_write_json(notes_path(project_dir), d)
        return rec


def remove_note(project_dir, finding_id, note_idx):
    """Remove note at index. Returns the removed note or None."""
    with _lock:
        d = load_notes(project_dir)
        notes = d.get(finding_id, [])
        if 0 <= note_idx < len(notes):
            removed = notes.pop(note_idx)
            if not notes:
                d.pop(finding_id, None)
            _atomic_write_json(notes_path(project_dir), d)
            return removed
        return None


# ─── Enrichment — merge sidecars into finding dicts at read time ────────────
def enrich_findings(project_dir, findings):
    """
    Mutate findings in-place: add original_risk, override risk, accepted state,
    acceptance metadata, analyst_notes. Returns the same list for chaining.
    """
    overrides   = load_overrides(project_dir)
    acceptances = load_acceptances(project_dir)
    notes       = load_notes(project_dir)
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or ""
        if not fid:
            continue
        # Risk override
        ov = overrides.get(fid)
        if ov:
            f.setdefault("original_risk", ov.get("original") or f.get("risk", ""))
            f["risk"] = ov["new"]
            f["_risk_override_reason"]   = ov.get("reason", "")
            f["_risk_override_operator"] = ov.get("operator", "")
            f["_risk_override_ts"]       = ov.get("ts", "")
        # Acceptance
        ac = acceptances.get(fid)
        if ac and ac.get("active"):
            f["accepted"]   = True
            f["acceptance"] = {
                "justification": ac.get("justification", ""),
                "accepted_by":   ac.get("accepted_by", ""),
                "ts":            ac.get("ts", ""),
            }
        # Notes
        if fid in notes:
            f["analyst_notes"] = list(notes[fid])
    return findings


# ─── Self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Risk override
        rec = set_risk(td, "f-1", "MEDIUM", original_risk="HIGH",
                       reason="false positive in this env", operator="jdoe")
        assert rec["new"] == "MEDIUM"
        # Accept
        ac = accept_finding(td, "f-2", justification="known internal admin",
                            accepted_by="jdoe")
        assert ac["active"] is True
        # Notes
        add_note(td, "f-1", "verified in prod environment", author="jdoe")
        add_note(td, "f-1", "ticket TKT-123 opened", author="jane")
        # Enrich
        sample = [
            {"id": "f-1", "title": "XSS", "risk": "HIGH"},
            {"id": "f-2", "title": "Open Port", "risk": "INFO"},
            {"id": "f-3", "title": "Other", "risk": "LOW"},
        ]
        enrich_findings(td, sample)
        assert sample[0]["risk"] == "MEDIUM"  # overridden
        assert sample[0]["original_risk"] == "HIGH"
        assert len(sample[0]["analyst_notes"]) == 2
        assert sample[1]["accepted"] is True
        assert "acceptance" in sample[1]
        assert "analyst_notes" not in sample[2]
        # Unset / unaccept
        unset_risk(td, "f-1")
        unaccept_finding(td, "f-2", operator="jdoe")
        sample2 = [{"id": "f-1", "title": "X", "risk": "HIGH"},
                   {"id": "f-2", "title": "Y", "risk": "INFO"}]
        enrich_findings(td, sample2)
        assert sample2[0]["risk"] == "HIGH"  # back to original
        assert sample2[1].get("accepted") is not True  # acceptance now inactive
        print("pr0t31n_workflow: self-test PASS")
