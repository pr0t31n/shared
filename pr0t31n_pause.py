"""pr0t31n_pause — Shared pause / resume / stop-reason infrastructure.

Provides :class:`PauseManager` for graceful pause of pr0t31n tools.

Usage (inside a tool's ``main()``):

    from pr0t31n_pause import PauseManager, EXIT_PAUSED

    pause = PauseManager(run_dir, "fracture")
    pause.start_watcher(
        checkpoint_callback=lambda: progress.save_scan_state(get_state()),
        grace_period=30,
    )

    # Between operations — check and exit if pause was requested:
    if pause.check_and_pause():
        sys.exit(EXIT_PAUSED)

    # At normal completion:
    pause.write_stop_reason("completed", "all_phases_done")
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "PauseManager",
    "EXIT_PAUSED",
    "STOP_ACTIONS",
]

log = logging.getLogger("pr0t31n.pause")

EXIT_PAUSED = 42

STOP_ACTIONS = {
    "completed",
    "paused_user",
    "paused_engagement_hours",
    "paused_scheduled",
    "paused_crucible",
    "killed_user",
    "killed_oom",
    "killed_crucible",
    "crashed",
    "failed",
}

_SENTINEL_NAME = "_pause_requested"
_STOP_REASON_NAME = "stop_reason.json"
_WATCHER_POLL_INTERVAL = 2


class PauseManager:
    """Manages graceful pause / resume for a single pr0t31n tool run.

    The manager watches for a sentinel file written by Crucible (or any
    external controller).  When detected it:

    1. Sets an internal flag so :meth:`check_and_pause` returns ``True``.
    2. Sends SIGTERM to every registered subprocess **and** every child
       process of the current process (via psutil) to unblock the main
       thread if it is waiting on one.
    3. After *grace_period* seconds, sends SIGKILL to survivors.
    4. Records incomplete operations in *stop_reason.json*.

    The tool's main thread calls :meth:`check_and_pause` between phases or
    after a subprocess exits.  When it returns ``True`` the tool saves its
    checkpoint and calls ``sys.exit(EXIT_PAUSED)``.
    """

    def __init__(self, run_dir: str | Path, tool_name: str) -> None:
        self._run_dir = Path(run_dir)
        self._tool = tool_name
        self._sentinel = self._run_dir / _SENTINEL_NAME
        self._stop_file = self._run_dir / _STOP_REASON_NAME
        self._pause_event = threading.Event()
        self._pause_reason: dict = {}
        self._grace_period = 30
        self._checkpoint_cb = None

        self._subprocs: dict[int, dict] = {}
        self._subprocs_lock = threading.Lock()
        self._incomplete: list[dict] = []
        self._completed = False

        self._watcher: threading.Thread | None = None
        self._started = False

        atexit.register(self._atexit_cleanup)

    # ── lifecycle ────────────────────────────────────────────────────────

    def start_watcher(self, *, checkpoint_callback=None,
                      grace_period: int = 30) -> None:
        """Start the background sentinel-file watcher.

        Parameters
        ----------
        checkpoint_callback
            Callable invoked (from the main thread, inside
            :meth:`check_and_pause`) to persist the tool's current state
            before exiting.
        grace_period
            Seconds to wait between SIGTERM and SIGKILL for subprocesses.
        """
        if self._started:
            return
        self._started = True
        self._checkpoint_cb = checkpoint_callback
        self._grace_period = grace_period
        self._watcher = threading.Thread(
            target=self._watch_loop, name="pause-watcher", daemon=True)
        self._watcher.start()

    @property
    def is_pause_requested(self) -> bool:
        return self._pause_event.is_set()

    def check_and_pause(self, checkpoint_callback=None) -> bool:
        """Check whether a pause has been requested.

        If yes:
        1. Terminate all tracked subprocesses (SIGTERM → grace → SIGKILL).
        2. Invoke the checkpoint callback to save tool state.
        3. Write *stop_reason.json* with incomplete operations.
        4. Remove the sentinel file.

        Returns ``True`` when a pause was executed — the caller should
        ``sys.exit(EXIT_PAUSED)`` immediately after.
        """
        if not self._pause_event.is_set():
            return False

        log.info("Pause requested — executing graceful shutdown")

        self._terminate_tracked(self._grace_period)

        cb = checkpoint_callback or self._checkpoint_cb
        if cb:
            try:
                cb()
            except Exception:
                log.exception("Checkpoint callback failed during pause")

        reason = self._pause_reason or {}
        self._write_stop_reason_file(
            action=reason.get("reason", "paused_user"),
            reason=reason.get("reason", "paused_user"),
            detail=reason.get("detail", ""),
            initiated_by=reason.get("initiated_by", "user"),
        )

        self._sentinel.unlink(missing_ok=True)
        return True

    # ── subprocess tracking ──────────────────────────────────────────────

    def register(self, proc: subprocess.Popen, operation: str,
                 output_files: list[str] | None = None) -> int:
        """Register a subprocess for pause-aware tracking.

        Returns the tracking key (``proc.pid``).
        """
        key = proc.pid
        with self._subprocs_lock:
            self._subprocs[key] = {
                "proc": proc,
                "operation": operation,
                "output_files": list(output_files or []),
                "started": time.time(),
            }
        return key

    def unregister(self, key: int) -> None:
        """Unregister a subprocess that completed normally."""
        with self._subprocs_lock:
            self._subprocs.pop(key, None)

    def run_tracked(self, cmd, *, operation: str = "",
                    output_files: list[str] | None = None,
                    timeout: int | None = None,
                    **popen_kw) -> subprocess.CompletedProcess | None:
        """Run a subprocess with automatic pause tracking.

        If a pause is requested while the subprocess is running, the
        subprocess is terminated and ``None`` is returned.  The caller
        should then call :meth:`check_and_pause` which will return
        ``True``.

        Otherwise returns the :class:`subprocess.CompletedProcess`.
        """
        if self._pause_event.is_set():
            return None

        popen_kw.setdefault("stdout", subprocess.PIPE)
        popen_kw.setdefault("stderr", subprocess.PIPE)
        proc = subprocess.Popen(cmd, **popen_kw)
        key = self.register(proc, operation or " ".join(str(c) for c in cmd),
                            output_files)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        finally:
            self.unregister(key)

        return subprocess.CompletedProcess(
            cmd, proc.returncode,
            stdout=stdout, stderr=stderr)

    # ── stop reason ──────────────────────────────────────────────────────

    def write_stop_reason(self, action: str, reason: str = "",
                          detail: str = "",
                          initiated_by: str = "") -> None:
        """Write stop_reason.json for a non-pause exit (completed, crashed, etc.)."""
        if action == "completed":
            self._completed = True
        self._write_stop_reason_file(action, reason or action,
                                     detail, initiated_by)

    def read_stop_reason(self) -> dict:
        """Read stop_reason.json from a previous run."""
        if self._stop_file.exists():
            try:
                return json.loads(self._stop_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def get_incomplete_operations(self) -> list[dict]:
        """Return incomplete operations from the last pause."""
        sr = self.read_stop_reason()
        return sr.get("incomplete_operations", [])

    def cleanup_incomplete(self) -> list[str]:
        """Delete output files from incomplete operations on resume.

        Returns a list of paths that were cleaned up.
        """
        cleaned = []
        for op in self.get_incomplete_operations():
            for rel_path in op.get("output_files", []):
                fp = self._run_dir / rel_path
                if fp.exists():
                    try:
                        fp.unlink()
                        cleaned.append(str(fp))
                        log.info("Cleaned incomplete output: %s", fp)
                    except OSError:
                        log.warning("Could not clean: %s", fp)
        return cleaned

    def log_run_type(self, resumed: bool = False,
                     logger=None) -> None:
        """Log whether this is a new run or a resumed run."""
        msg = (f"{self._tool} RESUMED from checkpoint"
               if resumed else f"{self._tool} started (NEW RUN)")
        (logger or log).info(msg)

    # ── process tree cleanup ─────────────────────────────────────────────

    def kill_all_children(self, grace: int = 5) -> None:
        """Kill all child processes of the current process.

        Uses psutil for tree enumeration when available, falls back to
        killing tracked subprocesses only.
        """
        self._terminate_tracked(grace)
        try:
            import psutil
            current = psutil.Process()
            children = current.children(recursive=True)
            if not children:
                return
            for child in children:
                try:
                    child.send_signal(signal.SIGTERM)
                except (psutil.NoSuchProcess, OSError):
                    pass
            _, alive = psutil.wait_procs(children, timeout=grace)
            for p in alive:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, OSError):
                    pass
            psutil.wait_procs(alive, timeout=3)
        except ImportError:
            pass

    # ── internal ─────────────────────────────────────────────────────────

    def _watch_loop(self) -> None:
        while not self._pause_event.is_set():
            if self._sentinel.exists():
                try:
                    raw = self._sentinel.read_text().strip()
                    self._pause_reason = json.loads(raw) if raw else {}
                except (json.JSONDecodeError, OSError):
                    self._pause_reason = {}
                self._pause_event.set()
                log.info("Pause sentinel detected: %s", self._pause_reason)
                # Kill tracked subprocesses first
                self._signal_tracked(signal.SIGTERM)
                # Kill ALL child processes (nmap, nuclei, etc.) — most
                # tools do not register their subprocesses, so the tracked
                # set alone is insufficient.
                self._signal_all_children(signal.SIGTERM)
                # After grace period, SIGKILL all survivors (tracked + untracked)
                threading.Timer(
                    self._grace_period,
                    self._sigkill_all_survivors).start()
                break
            time.sleep(_WATCHER_POLL_INTERVAL)

    def _signal_all_children(self, sig: int) -> None:
        """Send *sig* to every child process of the current process.

        Uses psutil for full process-tree enumeration.  Falls back
        silently when psutil is unavailable (tracked subprocesses are
        still handled by ``_signal_tracked``).
        """
        try:
            import psutil
            current = psutil.Process()
            for child in current.children(recursive=True):
                try:
                    child.send_signal(sig)
                except (psutil.NoSuchProcess, PermissionError, OSError):
                    pass
        except ImportError:
            log.warning("psutil not available — only tracked subprocesses "
                        "will be signalled on pause")

    def _sigkill_all_survivors(self) -> None:
        """SIGKILL every surviving subprocess — tracked and untracked."""
        # Tracked survivors
        with self._subprocs_lock:
            for key, info in list(self._subprocs.items()):
                proc = info["proc"]
                if proc.poll() is not None:
                    continue
                log.warning("SIGKILL on surviving tracked subprocess "
                            "PID %d (%s)", proc.pid, info["operation"])
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.kill()
                    except OSError:
                        pass
        # All remaining children (untracked nmap, nuclei, etc.)
        try:
            import psutil
            current = psutil.Process()
            for child in current.children(recursive=True):
                try:
                    child.kill()
                except (psutil.NoSuchProcess, PermissionError, OSError):
                    pass
        except ImportError:
            pass

    def _signal_tracked(self, sig: int) -> None:
        with self._subprocs_lock:
            for key, info in list(self._subprocs.items()):
                proc = info["proc"]
                if proc.poll() is not None:
                    continue
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, sig)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.send_signal(sig)
                    except OSError:
                        pass

    def _sigkill_survivors(self) -> None:
        """Legacy — kept for any external callers; delegates to the
        comprehensive version."""
        self._sigkill_all_survivors()

    def _terminate_tracked(self, grace: int) -> None:
        """SIGTERM all tracked subprocesses, wait *grace* seconds, SIGKILL."""
        with self._subprocs_lock:
            active = [(k, info) for k, info in self._subprocs.items()
                      if info["proc"].poll() is None]
        if not active:
            return

        for key, info in active:
            proc = info["proc"]
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.terminate()
                except OSError:
                    pass

        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            with self._subprocs_lock:
                still_alive = [info for _, info in self._subprocs.items()
                               if info["proc"].poll() is None]
            if not still_alive:
                break
            time.sleep(0.5)

        with self._subprocs_lock:
            for key, info in list(self._subprocs.items()):
                proc = info["proc"]
                if proc.poll() is None:
                    log.warning("SIGKILL subprocess PID %d (%s)",
                                proc.pid, info["operation"])
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        try:
                            proc.kill()
                        except OSError:
                            pass

        for key, info in active:
            proc = info["proc"]
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

        with self._subprocs_lock:
            for key, info in list(self._subprocs.items()):
                proc = info["proc"]
                rc = proc.poll()
                if rc is None or rc != 0:
                    self._incomplete.append({
                        "operation": info["operation"],
                        "output_files": info["output_files"],
                        "pid": proc.pid,
                        "killed": True,
                    })

    def _write_stop_reason_file(self, action: str, reason: str,
                                detail: str, initiated_by: str) -> None:
        data = {
            "action": action,
            "reason": reason,
            "detail": detail,
            "initiated_by": initiated_by,
            "tool": self._tool,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incomplete_operations": list(self._incomplete),
        }
        try:
            self._run_dir.mkdir(parents=True, exist_ok=True)
            self._stop_file.write_text(json.dumps(data, indent=2))
        except OSError:
            log.exception("Failed to write stop_reason.json")

    def _atexit_cleanup(self) -> None:
        with self._subprocs_lock:
            active = [(k, info) for k, info in self._subprocs.items()
                      if info["proc"].poll() is None]
        if not active:
            return
        if self._completed:
            for _k, info in active:
                try:
                    info["proc"].wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            return
        log.warning("atexit: killing %d remaining subprocesses", len(active))
        for key, info in active:
            proc = info["proc"]
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                pass
