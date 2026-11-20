"""pr0t31n_checkpoint — shared checkpoint / progress manager.

Thread-safe, JSON-backed phase tracking with optional runtime-state
persistence for scan resume.  Extracted from the ProgressManager
implementations in Fracture, Siphon, OSift and Scattershot3 so every
pr0t31n tool uses the same checkpoint semantics.

Usage (lazy import — tool degrades gracefully when module is absent)::

    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_checkpoint as _ck
    except ImportError:
        _ck = None

    # Create
    pm = _ck.ProgressManager(project_dir / "checkpoint.json") if _ck else None

    # Phase tracking
    if pm and not pm.is_phase_complete("p3_nuclei"):
        pm.set_phase_status("p3_nuclei", "running", "Phase 3: Nuclei")
        do_nuclei_scan()
        pm.set_phase_status("p3_nuclei", "complete", "Phase 3: Nuclei")

    # Or use the convenience wrapper
    _ck.checkpoint_phase(pm, "p3_nuclei", "Phase 3: Nuclei", do_nuclei_scan)

    # Runtime state (v2 checkpoint)
    pm.save_scan_state({"alive_ips": [...], "all_results": {...}})
    state = pm.load_scan_state()
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path


class ProgressManager:
    """Thread-safe checkpoint manager for scan recovery.

    Persists phase completion status and optional runtime state to a JSON
    file using atomic writes (mkstemp + replace).  On resume, completed
    phases are skipped; running/error phases are reset to pending.
    """

    def __init__(self, checkpoint_file: str | Path) -> None:
        self._file = Path(checkpoint_file)
        self._lock = threading.Lock()
        self._state = self._load()

    # ── persistence ───────────────────────────────────────────────────────

    def _load(self) -> dict:
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                data.setdefault("version", 1)
                data.setdefault("started", datetime.now().isoformat())
                data.setdefault("completed_phases", [])
                data.setdefault("phase_status", {})
                return data
            except Exception:
                pass
        return {
            "version":          1,
            "started":          datetime.now().isoformat(),
            "completed_phases": [],
            "phase_status":     {},
        }

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._file.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(tmp, str(self._file))
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    # ── phase tracking ────────────────────────────────────────────────────

    def is_phase_complete(self, phase: str) -> bool:
        with self._lock:
            return phase in self._state.get("completed_phases", [])

    def set_phase_status(self, phase: str, status: str,
                         label: str = "", detail: str = "") -> None:
        with self._lock:
            self._state.setdefault("phase_status", {})[phase] = {
                "status":     status,
                "label":      label or phase,
                "detail":     detail,
                "updated_at": datetime.now().isoformat(),
            }
            if status == "complete":
                lst = self._state.setdefault("completed_phases", [])
                if phase not in lst:
                    lst.append(phase)
            self._save()

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    # ── v2 checkpoint: full runtime state ─────────────────────────────────

    def save_scan_state(self, state: dict) -> None:
        """Store full serialisable runtime state alongside phase tracking."""
        with self._lock:
            self._state["scan_state"] = state
            self._state["version"] = 2
            self._state["checkpoint_ts"] = datetime.now().isoformat()
            self._save()

    def load_scan_state(self) -> dict:
        """Return stored runtime state, or empty dict if none."""
        with self._lock:
            return self._state.get("scan_state", {})

    def has_resumable_state(self) -> bool:
        """True when this checkpoint carries v2 runtime state."""
        with self._lock:
            return (self._state.get("version", 1) >= 2
                    and bool(self._state.get("scan_state")))

    def prepare_resume(self) -> dict:
        """Reset running/error phases to pending and return full state.

        Called once at the start of a resume run.  Phases that were
        mid-flight when the previous run was interrupted are demoted to
        'pending' so they re-execute; completed phases remain complete
        and are skipped.
        """
        with self._lock:
            ps = self._state.get("phase_status", {})
            for k, v in ps.items():
                if v.get("status") in ("running", "error"):
                    v["status"] = "pending"
                    v["updated_at"] = datetime.now().isoformat()
            self._save()
            return dict(self._state)


# ── convenience wrappers ──────────────────────────────────────────────────


def checkpoint_phase(pm: ProgressManager | None, phase_key: str,
                     label: str, fn, *args, **kwargs):
    """Run *fn* only if the phase is not already complete.

    Marks the phase running before the call and complete on success.
    On exception the phase is marked error and the exception re-raised.
    Safe to call with ``pm=None`` — the function runs unconditionally.
    """
    if pm is not None and pm.is_phase_complete(phase_key):
        return None
    if pm is not None:
        pm.set_phase_status(phase_key, "running", label)
    try:
        result = fn(*args, **kwargs)
        if pm is not None:
            pm.set_phase_status(phase_key, "complete", label)
        return result
    except Exception as e:
        if pm is not None:
            pm.set_phase_status(phase_key, "error", label, str(e))
        raise


def is_complete(pm: ProgressManager | None, phase_key: str) -> bool:
    """Null-safe check — returns False when pm is None."""
    return pm is not None and pm.is_phase_complete(phase_key)
