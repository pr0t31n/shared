"""pr0t31n_wireless_base.py — shared helpers for the Aether family.

Extracts the ~150 lines of helper boilerplate that was duplicated across
Aether / Aether-B (Whisper) / Aether-Z (Hornet) / Aether-U (Anchor) —
total ~600 lines of pure copy-paste eliminated.

Provides:
  * clients_base(), build_project_dir() — replaces _clients_base() and
    _build_project_dir() per-tool implementations.
  * SpectreEmitter — __SPECTRE_LOG__ / _ERR_ / _STATUS_ / _FINDING_ token
    emission. Each variant just calls .log() / .err() / .status() /
    .finding() instead of repeating the token formatting.
  * WirelessRunner — wraps pr0t31n_tool_runner for §14 .log compliance
    AND pr0t31n_proc_registry for process-tree tracking (fixes the
    Aether H1 orphan finding).
  * write_findings_safe() — fold risk through normalize_risk + route
    output_file through to_relative_output_file before writing.

Backwards-compatible: every variant can adopt incrementally by importing
just the helpers it needs.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


VERSION = "1.0.0"
logger = logging.getLogger(__name__)


# Bootstrap path for siblings
if "/opt/pr0t31n/shared" not in sys.path:
    sys.path.insert(0, "/opt/pr0t31n/shared")

try:
    import pr0t31n_proc_registry as _reg
    import pr0t31n_schema_compat as _sc
    import pr0t31n_timeouts as _to
    import pr0t31n_tool_runner as _tr
    _HAVE_SHARED = True
except ImportError as exc:
    _HAVE_SHARED = False
    logger.warning("shared modules incomplete: %s", exc)


# ── Project-dir helpers (replaces _clients_base + _build_project_dir) ──


def clients_base() -> Path:
    """Platform-appropriate /clients parent dir."""
    sys_name = platform.system()
    if sys_name == "Windows": base = Path("C:/clients")
    elif sys_name == "Darwin": base = Path("/Users/Shared/clients")
    else:                      base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def build_project_dir(client_short: str, start_date: str,
                      tool_name: str) -> Path:
    """<clients_base>/<slug>/<year>/<tool_name>/<slug>_<YYYYMMDD_HHMMSS>/"""
    slug = re.sub(r"[^\w-]", "_", (client_short or "client").strip().lower()).strip("_") or "client"
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now(timezone.utc).strftime("%Y"))
    dt_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ── Spectre token emitter ──────────────────────────────────────────────


class SpectreEmitter:
    """__SPECTRE_LOG__ / _ERR_ / _STATUS_ / _FINDING_ / _PROMPT_ token
    emission. Pass managed=True when SPECTRE_MANAGED=1."""

    LOG     = "__SPECTRE_LOG__"
    ERR     = "__SPECTRE_ERR__"
    STATUS  = "__SPECTRE_STATUS__"
    FINDING = "__SPECTRE_FINDING__"
    PROMPT  = "__SPECTRE_PROMPT__"

    def __init__(self, managed: Optional[bool] = None):
        self.managed = (managed if managed is not None
                        else os.environ.get("SPECTRE_MANAGED") == "1")

    def _emit(self, token: str, msg: str) -> None:
        if self.managed:
            sys.stdout.write(f"{token} {msg}\n")
            sys.stdout.flush()

    def log(self, msg: str) -> None:     self._emit(self.LOG, msg)
    def err(self, msg: str) -> None:     self._emit(self.ERR, msg)
    def prompt(self, msg: str) -> None:  self._emit(self.PROMPT, msg)

    def status(self, payload: dict) -> None:
        self._emit(self.STATUS, json.dumps(payload, default=str))

    def finding(self, finding: dict) -> None:
        # Apply schema normalisation before emission.
        if _HAVE_SHARED:
            finding = dict(finding)
            finding["risk"] = _sc.normalize_risk(finding.get("risk"))
        self._emit(self.FINDING, json.dumps(finding, default=str))


# ── Wireless runner ────────────────────────────────────────────────────


class WirelessRunner:
    """Wraps pr0t31n_tool_runner with:
      * Process-tree tracking via pr0t31n_proc_registry (fixes Aether H1).
      * Generous default timeouts from pr0t31n_timeouts.
      * Automatic .log sibling emission via tool_runner.write_tool_log.
      * Risk + output_file normalisation on findings via schema_compat.
    """

    def __init__(self, *, tool: str, run_dir: Path | str,
                  emitter: Optional[SpectreEmitter] = None):
        self.tool      = tool
        self.run_dir   = Path(run_dir)
        self.emitter   = emitter or SpectreEmitter()
        self.registry  = _reg.ProcessRegistry(run_dir=self.run_dir) if _HAVE_SHARED else None
        if self.registry: self.registry.install_signal_handlers()

    def run_tool(self, cmd: list[str], *, tool_key: str = "",
                  output_file: Optional[Path | str] = None,
                  timeout: Optional[int] = None,
                  deep_scan: bool = False,
                  large_target_set: bool = False,
                  **kwargs):
        """subprocess.run with .log sibling + generous timeout. Returns
        CompletedProcess."""
        if not _HAVE_SHARED:
            import subprocess
            return subprocess.run(cmd, timeout=timeout or 1800, **kwargs)
        if timeout is None:
            key = tool_key or (cmd[0] if cmd else "subprocess_default")
            key = Path(key).name
            timeout = _to.resolve(key,
                                   deep_scan=deep_scan,
                                   large_target_set=large_target_set)
        return _tr.run_tool(cmd, output_file=output_file,
                             timeout=timeout, tool_name=tool_key,
                             **kwargs)

    def spawn(self, cmd: list[str], *, tool_key: str = "",
               use_cgroup: bool = False, **popen_kwargs):
        """Long-lived Popen (hostapd / dnsmasq / aireplay / responder).
        Auto-registered for orphan reaping."""
        if not _HAVE_SHARED:
            import subprocess
            return subprocess.Popen(cmd, **popen_kwargs)
        return _reg.spawn_tracked(cmd, registry=self.registry,
                                    tool=tool_key, use_cgroup=use_cgroup,
                                    **popen_kwargs)


# ── Findings writer with schema normalisation ──────────────────────────


def write_findings_safe(run_dir: Path | str,
                         findings: list[dict],
                         *, tool: str, version: str) -> None:
    """Fold risk through normalize_risk + emit findings.json + summary.json."""
    if not _HAVE_SHARED:
        # Local-only fallback
        (Path(run_dir) / "findings.json").write_text(
            json.dumps({"findings": findings}, indent=2, default=str),
            encoding="utf-8")
        return
    _sc.write_universal_findings(run_dir, findings, tool=tool, version=version)


# ── Startup orphan sweep (call once at script entry) ───────────────────


def sweep_orphans_on_start(run_dir: Optional[Path | str] = None) -> int:
    """Look for a stale _proc_registry.json and reap orphaned children
    that survived a prior parent SIGKILL. Call early in main()."""
    if not _HAVE_SHARED or run_dir is None: return 0
    return _reg.ProcessRegistry.sweep_stale(run_dir)
