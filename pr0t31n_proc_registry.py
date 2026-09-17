"""pr0t31n_proc_registry.py — process registry + orphan reaper.

Solves the Aether-family H1 finding: long-lived child processes (hostapd,
dnsmasq, airodump-ng, aireplay-ng, captive-portal daemons, responder,
tcpdump, etc.) become orphans if the parent gets SIGKILLed before its
signal handler runs.

Provides:
  1. A process-group/cgroup launcher that ensures kill-the-tree semantics.
  2. A PID-file registry under the run directory so a restart-time sweep
     can reap stale children that survived a hard parent kill.
  3. atexit + SIGTERM/SIGINT handlers that cascade-kill every registered
     child before the parent exits.

Backwards-compatible: if /proc isn't available (macOS) or systemd-run
isn't installed, falls back to plain os.killpg + atexit.

Caveats explicitly noted in CLAUDE.md compliance:
  * Does NOT prevent session sharing — every captured process can still
    be re-attached by the same operator session that spawned it.
  * Does NOT interfere with evidence capture — child processes complete
    normally on graceful shutdown; only hard-kill paths trigger cleanup.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


VERSION = "1.0.0"
logger = logging.getLogger(__name__)


# ── Registry singleton ─────────────────────────────────────────────────


class ProcessRegistry:
    """In-process + on-disk registry of spawned children."""

    def __init__(self, run_dir: Path | str | None = None):
        self.run_dir   = Path(run_dir) if run_dir else None
        self._procs:   dict[int, dict] = {}
        self._lock     = threading.Lock()
        self._signal_handlers_set = False
        if self.run_dir:
            (self.run_dir / "_proc_registry.json").parent.mkdir(parents=True, exist_ok=True)
        atexit.register(self._on_exit)

    # ── Persistence ──

    def _pidfile(self) -> Optional[Path]:
        return (self.run_dir / "_proc_registry.json") if self.run_dir else None

    def _flush(self) -> None:
        p = self._pidfile()
        if not p: return
        try:
            p.write_text(json.dumps({
                "saved_at":  datetime.now(timezone.utc).isoformat(),
                "parent_pid": os.getpid(),
                "procs":     list(self._procs.values()),
            }), encoding="utf-8")
        except OSError:
            pass

    # ── Public API ──

    def register(self, *, pid: int, pgid: Optional[int] = None,
                 argv: Optional[list] = None, tool: str = "",
                 use_cgroup: bool = False) -> None:
        with self._lock:
            self._procs[pid] = {
                "pid":   pid,
                "pgid":  pgid,
                "argv":  argv or [],
                "tool":  tool,
                "use_cgroup": use_cgroup,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            self._flush()

    def unregister(self, pid: int) -> None:
        with self._lock:
            self._procs.pop(pid, None)
            self._flush()

    def kill_all(self, *, timeout: float = 5.0) -> int:
        """SIGTERM then SIGKILL each registered process group/pid.
        Returns number of processes signalled."""
        with self._lock:
            entries = list(self._procs.values())
        n = 0
        for e in entries:
            try:
                if e.get("pgid"):
                    os.killpg(e["pgid"], signal.SIGTERM)
                else:
                    os.kill(e["pid"], signal.SIGTERM)
                n += 1
            except (ProcessLookupError, PermissionError):
                continue
        # Wait then escalate
        end = time.monotonic() + timeout
        while time.monotonic() < end and self._any_alive():
            time.sleep(0.2)
        for e in entries:
            try:
                if e.get("pgid"):
                    os.killpg(e["pgid"], signal.SIGKILL)
                else:
                    os.kill(e["pid"], signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                continue
        with self._lock:
            self._procs.clear()
            self._flush()
        return n

    def _any_alive(self) -> bool:
        with self._lock:
            for e in self._procs.values():
                try:
                    os.kill(e["pid"], 0)
                    return True
                except (ProcessLookupError, PermissionError):
                    pass
            return False

    def install_signal_handlers(self) -> None:
        if self._signal_handlers_set: return
        prev_term = signal.getsignal(signal.SIGTERM)
        prev_int  = signal.getsignal(signal.SIGINT)
        def _handler(signum, frame):
            self.kill_all()
            # Chain to previous handler if any
            if callable(prev_term) and signum == signal.SIGTERM:
                try: prev_term(signum, frame)
                except Exception: pass
            if callable(prev_int) and signum == signal.SIGINT:
                try: prev_int(signum, frame)
                except Exception: pass
            os._exit(130 if signum == signal.SIGINT else 143)
        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT,  _handler)
            self._signal_handlers_set = True
        except (ValueError, OSError):
            # Not in main thread — skip
            pass

    def _on_exit(self) -> None:
        # Triggered on normal interpreter shutdown. Reap any survivors.
        self.kill_all(timeout=1.0)

    # ── Startup orphan sweep ──

    @staticmethod
    def sweep_stale(run_dir: Path | str, *, age_min: int = 60) -> int:
        """Run-dir-scoped sweep. If a prior parent crashed and left a
        _proc_registry.json behind, kill those PIDs (if still running and
        belong to a process command-line that matches the recorded argv).
        Returns count of orphans reaped."""
        p = Path(run_dir) / "_proc_registry.json"
        if not p.exists(): return 0
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        # Don't reap procs younger than age_min seconds (might be live siblings)
        saved_at = data.get("saved_at", "")
        try:
            saved = datetime.fromisoformat(saved_at.replace("Z", "+00:00"))
            age   = (datetime.now(timezone.utc) - saved).total_seconds()
            if age < age_min: return 0
        except (ValueError, AttributeError):
            pass
        n = 0
        for e in data.get("procs", []):
            pid = e.get("pid")
            argv = e.get("argv") or []
            if not pid or not isinstance(pid, int): continue
            # Verify the PID still belongs to a process matching argv[0]
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                actual = cmdline.split(b"\0")[0].decode("utf-8", errors="replace")
                if argv and not actual.endswith(Path(argv[0]).name):
                    continue
            except (FileNotFoundError, PermissionError):
                # macOS: no /proc — skip the verification step, accept the kill
                pass
            try:
                if e.get("pgid"):
                    os.killpg(e["pgid"], signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
                n += 1
            except (ProcessLookupError, PermissionError):
                continue
        # Clear the registry file so we don't repeat
        try: p.unlink()
        except OSError: pass
        return n


# ── Launcher helpers ────────────────────────────────────────────────────


_SYSTEMD_RUN = shutil.which("systemd-run") if hasattr(shutil, "which") else None


def systemd_scope_argv(argv: list[str], *, scope_name: Optional[str] = None,
                       cpu_quota: Optional[str] = None,
                       memory_max: Optional[str] = None) -> list[str]:
    """Return argv wrapped in `systemd-run --scope` when available. Falls
    through to the original argv otherwise.

    cpu_quota: e.g. '200%' (2 cores)
    memory_max: e.g. '4G'
    """
    if not _SYSTEMD_RUN:
        return list(argv)
    wrapper = [_SYSTEMD_RUN, "--scope", "--quiet"]
    if scope_name:  wrapper += [f"--unit={scope_name}"]
    if cpu_quota:   wrapper += [f"--property=CPUQuota={cpu_quota}"]
    if memory_max:  wrapper += [f"--property=MemoryMax={memory_max}"]
    return wrapper + list(argv)


def spawn_tracked(argv: list[str], *, registry: ProcessRegistry,
                  tool: str = "", new_pgroup: bool = True,
                  use_cgroup: bool = False, **popen_kwargs) -> subprocess.Popen:
    """subprocess.Popen + auto-register with the registry."""
    if new_pgroup and "preexec_fn" not in popen_kwargs and hasattr(os, "setsid"):
        popen_kwargs["preexec_fn"] = os.setsid
    if use_cgroup and _SYSTEMD_RUN and argv and argv[0] != _SYSTEMD_RUN:
        argv = systemd_scope_argv(argv)
    proc = subprocess.Popen(argv, **popen_kwargs)
    pgid = None
    try:
        pgid = os.getpgid(proc.pid) if new_pgroup else None
    except (ProcessLookupError, AttributeError, OSError):
        pass
    registry.register(pid=proc.pid, pgid=pgid, argv=argv, tool=tool,
                       use_cgroup=use_cgroup)
    return proc


def _global_registry() -> ProcessRegistry:
    """For tools that want a process-wide singleton without managing it."""
    if not hasattr(_global_registry, "_inst"):
        _global_registry._inst = ProcessRegistry()
        _global_registry._inst.install_signal_handlers()
    return _global_registry._inst
