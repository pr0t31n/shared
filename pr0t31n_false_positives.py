"""
pr0t31n_false_positives.py — Shared false-positive management for pr0t31n
Flask apps.

Each app stores its findings in its own native format (JSON array, JSONL,
SQLite, etc.). This module owns the parallel false_positives.json +
false_positives.csv files that live alongside the findings — apps call
into these helpers and handle their own findings-file mutation separately.

Files managed (per project):
  false_positives.json  — JSON array of finding dicts marked as false
                          positive. Dedupes by 'id' if present, otherwise
                          by content key (title + ip + port).
  false_positives.csv   — CSV mirror with the same column set as the
                          tool's findings.csv. Optional — only written
                          when the caller passes csv_fieldnames.

Distribution: VENDORED. Each app copies this file into its own repo (same
pattern as _auth.py and pr0t31n_schema.py). The canonical copy lives at
/opt/pr0t31n/shared/pr0t31n_false_positives.py.

stdlib only.
"""
from __future__ import annotations

import csv
import json
import threading
from pathlib import Path

__all__ = [
    "fp_paths",
    "load_false_positives",
    "add_false_positive",
    "remove_false_positive",
    "find_false_positive",
    "content_key",
]

_write_lock = threading.Lock()


def fp_paths(project_dir: "str | Path") -> "tuple[Path, Path]":
    """Return canonical (falsePositives.json, falsePositives.csv) paths.

    Canonical naming is camelCase (matches Crucible's pre-existing convention).
    Legacy snake_case files (false_positives.*) are still READ for backward
    compatibility by load_false_positives() — but new writes go to the
    canonical camelCase names only.
    """
    p = Path(project_dir)
    return p / "falsePositives.json", p / "falsePositives.csv"


def _legacy_fp_paths(project_dir: "str | Path") -> "tuple[Path, Path]":
    """Snake-case paths used by older code paths. Read-only fallback."""
    p = Path(project_dir)
    return p / "false_positives.json", p / "false_positives.csv"


def content_key(f: dict) -> tuple:
    """Stable content-based dedup key for findings without an 'id' field."""
    return (
        (f.get("title") or "").strip().lower(),
        (f.get("ip") or "").strip(),
        str(f.get("port") or "0"),
        (f.get("hostname") or "").strip().lower(),
    )


def load_false_positives(project_dir: "str | Path") -> list:
    """Return the list of FP finding dicts. Prefers falsePositives.json
    (canonical camelCase); falls back to legacy false_positives.json for
    backward compatibility with pre-standardisation projects."""
    fpj, _ = fp_paths(project_dir)
    if not fpj.exists():
        legacy_j, _ = _legacy_fp_paths(project_dir)
        if legacy_j.exists():
            fpj = legacy_j
        else:
            return []
    try:
        data = json.loads(fpj.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def find_false_positive(project_dir: "str | Path", finding_id: str) -> "dict | None":
    """Return the FP finding dict matching finding_id, or None."""
    if not finding_id:
        return None
    for f in load_false_positives(project_dir):
        if f.get("id") == finding_id:
            return f
    return None


def add_false_positive(project_dir: "str | Path", finding: dict, *,
                       csv_fieldnames: "list | None" = None) -> bool:
    """
    Append a finding to false_positives.json (and false_positives.csv if
    csv_fieldnames given). Idempotent: dedupes by 'id' when present,
    otherwise by content_key. Returns True if the finding was newly added,
    False if it was already present.
    """
    fpj, fpc = fp_paths(project_dir)
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    fid = finding.get("id")
    key = ("id", fid) if fid else ("content", content_key(finding))
    with _write_lock:
        current = load_false_positives(project_dir)
        for ex in current:
            ex_key = ("id", ex.get("id")) if ex.get("id") else ("content", content_key(ex))
            if ex_key == key:
                return False
        current.append(finding)
        tmp = fpj.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=2, default=str), encoding="utf-8")
        tmp.replace(fpj)
        if csv_fieldnames:
            new_file = not fpc.exists() or fpc.stat().st_size == 0
            with fpc.open("a", newline="", encoding="utf-8") as fh:
                wr = csv.DictWriter(fh, fieldnames=csv_fieldnames, extrasaction="ignore")
                if new_file:
                    wr.writeheader()
                wr.writerow(finding)
    return True


def remove_false_positive(project_dir: "str | Path", finding_id: str, *,
                          csv_fieldnames: "list | None" = None) -> "dict | None":
    """
    Remove a finding from false_positives.{json,csv} by id. Returns the
    removed finding dict (so the caller can re-insert it into findings.*),
    or None if not found.
    """
    if not finding_id:
        return None
    fpj, fpc = fp_paths(project_dir)
    with _write_lock:
        current = load_false_positives(project_dir)
        kept, removed = [], None
        for f in current:
            if f.get("id") == finding_id and removed is None:
                removed = f
            else:
                kept.append(f)
        if removed is None:
            return None
        tmp = fpj.with_suffix(".tmp")
        tmp.write_text(json.dumps(kept, indent=2, default=str), encoding="utf-8")
        tmp.replace(fpj)
        if csv_fieldnames and fpc.exists():
            try:
                with fpc.open(newline="", encoding="utf-8") as fh:
                    csv_rows = list(csv.DictReader(fh))
                csv_rows = [r for r in csv_rows if r.get("id") != finding_id]
                with fpc.open("w", newline="", encoding="utf-8") as fh:
                    wr = csv.DictWriter(fh, fieldnames=csv_fieldnames, extrasaction="ignore")
                    wr.writeheader()
                    wr.writerows(csv_rows)
            except Exception:
                pass
    return removed


# ─── Self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        f1 = {"id": "abc-123", "title": "XSS", "ip": "10.0.0.1", "port": 443, "risk": "HIGH"}
        f2 = {"id": "def-456", "title": "SQLi", "ip": "10.0.0.2", "port": 80, "risk": "CRITICAL"}
        # Add
        assert add_false_positive(td, f1, csv_fieldnames=["id","title","ip","port","risk"])
        assert add_false_positive(td, f2, csv_fieldnames=["id","title","ip","port","risk"])
        # Idempotent re-add
        assert not add_false_positive(td, f1, csv_fieldnames=["id","title","ip","port","risk"])
        # Load
        loaded = load_false_positives(td)
        assert len(loaded) == 2
        # Find
        assert find_false_positive(td, "abc-123")["title"] == "XSS"
        # Remove
        rem = remove_false_positive(td, "abc-123", csv_fieldnames=["id","title","ip","port","risk"])
        assert rem and rem["id"] == "abc-123"
        assert len(load_false_positives(td)) == 1
        # Remove nonexistent
        assert remove_false_positive(td, "nonexistent-id") is None
        # CSV check (canonical camelCase filename)
        fpc = Path(td) / "falsePositives.csv"
        assert fpc.exists()
        with fpc.open() as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1 and rows[0]["id"] == "def-456"
        # Backward-compat: legacy snake_case file is still read if canonical absent
        import os as _os
        for f in ("falsePositives.json", "falsePositives.csv"):
            _os.remove(Path(td) / f)
        (Path(td) / "false_positives.json").write_text(json.dumps([{"id": "legacy", "title": "Old FP"}]))
        legacy = load_false_positives(td)
        assert len(legacy) == 1 and legacy[0]["id"] == "legacy", legacy
        print("pr0t31n_false_positives: self-test PASS (incl. legacy compat)")
