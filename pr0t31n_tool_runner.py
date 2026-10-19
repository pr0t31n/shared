"""
pr0t31n shared tool runner — universal third-party tool execution logging.

Every pr0t31n tool that invokes an external binary (nmap, nuclei, gobuster,
shcheck, sslscan, etc.) MUST emit a sibling .log file containing:

  • Header: tool name, resolved path, version, start time, end time,
    duration, exit code
  • A bash-session-style transcript: a prompt line with the exact command
    line as it would appear in a terminal, the full stdout, the stderr
    (clearly marked), and a final prompt line indicating shell return.

This module is the canonical implementation.  Tools should call either:

  • run_tool(cmd, output_file=..., ...)  — subprocess.run wrapper that
    emits the log automatically and returns CompletedProcess.

  • write_tool_log(cmd=..., stdout=..., stderr=..., ...)  — low-level
    emitter for code paths that already use Popen with streaming, or
    that capture output via some other mechanism.

Schema version 1.0 — additive changes only.  See CLAUDE.md Section 15.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from shlex import quote as _shquote
from threading import Lock

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

SCHEMA_VERSION = "1.0"


# ── Version detection ────────────────────────────────────────────────────────
#
# Per-tool version-flag candidates.  Tried in order; first one that returns
# any output containing a digit wins.  Cached per-process by (basename, path).
# Unknown tools fall through to the generic candidate list.

_VERSION_FLAGS: dict[str, list[list[str]]] = {
    "nmap":         [["--version"]],
    "nuclei":       [["-version"]],
    "nikto":        [["-Version"]],
    "gobuster":     [["version"]],
    "ffuf":         [["-V"]],
    "feroxbuster":  [["--version"]],
    "wpscan":       [["--version"]],
    "whatweb":      [["--version"]],
    "sslscan":      [["--version"]],
    "testssl.sh":   [["--version"]],
    "testssl":      [["--version"]],
    "shcheck":      [["--help"]],
    "shcheck.py":   [["--help"]],
    "curl":         [["--version"]],
    "wget":         [["--version"]],
    "hydra":        [["-h"]],
    "msfconsole":   [["--version"]],
    "searchsploit": [["--version"]],
    "smbmap":       [["--version"]],
    "smbclient":    [["--version"]],
    "enum4linux":   [["--version"], ["-h"]],
    "enum4linux-ng": [["--version"], ["-h"]],
    "rpcclient":    [["--version"]],
    "dig":          [["-v"]],
    "dnsx":         [["-version"]],
    "subfinder":    [["-version"]],
    "amass":        [["--version"], ["-version"]],
    "katana":       [["-version"]],
    "httpx":        [["-version"]],
    "trufflehog":   [["--version"]],
    "gitleaks":     [["version"]],
    "sqlmap":       [["--version"]],
    "zap":          [["-version"]],
    "zap.sh":       [["-version"]],
    "openssl":      [["version"]],
    "ssh-audit":    [["--version"], ["-h"]],
    "ssh-audit.py": [["--version"], ["-h"]],
    "snmpwalk":     [["-V"]],
    "ipmitool":     [["-V"]],
    "responder":    [["--version"], ["-h"]],
    "gowitness":    [["version"]],
    "webanalyze":   [["-version"]],
    "tcpdump":      [["--version"]],
    "nc":           [["-h"]],
    "ncat":         [["--version"]],
    "go":           [["version"]],
    "python3":      [["--version"]],
    "aircrack-ng":  [["--help"]],
    "airodump-ng":  [["--help"]],
    "kismet":       [["--version"]],
    "wifite":       [["--help"]],
    "asleap":       [["-h"]],
    "odat":         [["--version"], ["-h"]],
    "msdat":        [["--version"], ["-h"]],
    "enumdb":       [["--version"], ["-h"]],
    "xsstrike":     [["--help"]],
    "dirsearch":    [["--version"]],
    "kiterunner":   [["--version"], ["-h"]],
    "kr":           [["--version"]],
    "git":          [["--version"]],
    "shortscan":    [["-version"]],
}

_GENERIC_VERSION_FLAGS = [["--version"], ["-version"], ["-V"], ["version"], ["-v"]]

_VERSION_CACHE: dict[tuple[str, str], str] = {}
_VERSION_LOCK = Lock()
_VERSION_TIMEOUT = 4


def detect_version(tool_path: str, basename: str | None = None) -> str:
    """Return a short version string for *tool_path* (cached per process).

    Falls back to "unknown" if no candidate flag produced parseable output.
    Never raises — version detection failures must not break the scan.
    """
    if not tool_path:
        return "unknown"
    bn = basename or Path(tool_path).name
    key = (bn, tool_path)
    with _VERSION_LOCK:
        if key in _VERSION_CACHE:
            return _VERSION_CACHE[key]
    candidates = _VERSION_FLAGS.get(bn) or _GENERIC_VERSION_FLAGS
    result = "unknown"
    for argv in candidates:
        try:
            proc = subprocess.run(
                [tool_path, *argv],
                capture_output=True, text=True,
                timeout=_VERSION_TIMEOUT, errors="replace",
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        # Strip ANSI escapes — nuclei and friends colourise --version output
        # even when stdout is not a TTY.
        blob = _ANSI_RE.sub("", (proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if not blob:
            continue
        # Skip usage banners and option-listing lines — tools that don't
        # implement --version often fall through to printing help, whose
        # first digit-bearing line is "usage: tool [-1 ...]" or similar.
        # We want a version string, not the usage banner.
        _SKIP_PREFIXES = ("usage:", "Usage:", "options:", "Options:",
                          "OPTIONS", "  -", "\t-")
        for line in blob.splitlines():
            ln = line.strip()
            if not ln or len(ln) >= 240:
                continue
            if any(ln.startswith(p.strip()) for p in _SKIP_PREFIXES):
                continue
            if any(ch.isdigit() for ch in ln):
                result = ln
                break
        if result != "unknown":
            break
    with _VERSION_LOCK:
        _VERSION_CACHE[key] = result
    return result


# ── Bash-prompt formatting ───────────────────────────────────────────────────

def _prompt(cwd: str | None = None) -> str:
    """Build a PS1-style prompt: user@host:cwd$ — with HOME tildified."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
    host = socket.gethostname().split(".")[0] or "localhost"
    where = cwd or os.getcwd()
    home = os.path.expanduser("~")
    if home and where.startswith(home):
        where = "~" + where[len(home):]
    return f"{user}@{host}:{where}$ "


def _cmd_str(cmd: list | str) -> str:
    """Render a command as a single bash-quoted string."""
    if isinstance(cmd, str):
        return cmd
    return " ".join(_shquote(str(c)) for c in cmd)


def _ts_iso(dt: datetime) -> str:
    """ISO 8601 with seconds precision + local-tz offset."""
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.isoformat(timespec="seconds")


# ── Log path derivation ──────────────────────────────────────────────────────
#
# Rule: the .log file always lives in the same directory as the primary
# output artifact.  If no output artifact is provided (rare — only when a
# tool produces no file, e.g. ad-hoc reachability probes), the log goes
# into *log_dir* or — last resort — the cwd.

def derive_log_path(output_file: str | Path | None,
                    log_dir: str | Path | None,
                    tool_name: str) -> Path:
    if output_file:
        of = Path(output_file)
        # Append .log to the FULL filename so "nmap.xml" → "nmap.xml.log",
        # preserving the original extension and making sibling pairs obvious.
        return of.with_name(of.name + ".log")
    base = Path(log_dir) if log_dir else Path.cwd()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return base / f"{tool_name}_{ts}.log"


# ── Log writer ───────────────────────────────────────────────────────────────

_MAX_TEXT_CHARS = 8 * 1024 * 1024   # 8 MiB cap per stream — prevents runaway
                                     # log files for tools like ferox / nuclei
                                     # against very large wordlists.


def _truncate(text: str, limit: int = _MAX_TEXT_CHARS) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    head = text[:limit]
    omitted = len(text) - limit
    return head + f"\n\n[... {omitted} bytes truncated by pr0t31n_tool_runner — output exceeded {limit} bytes ...]\n"


def write_tool_log(
    *,
    cmd: list | str,
    started: datetime,
    ended: datetime,
    exit_code: int | None,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    tool_name: str,
    tool_path: str | None = None,
    tool_version: str | None = None,
    output_file: str | Path | None = None,
    log_dir: str | Path | None = None,
    cwd: str | None = None,
    extra_header: dict | None = None,
    errors_log: str | Path | None = None,
) -> Path:
    """Write a bash-session-style .log file alongside the tool's primary output.

    Returns the resolved log file path.  Never raises on write failure — the
    caller's primary output must not be lost because logging blew up.
    """
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    stdout = _truncate(stdout or "")
    stderr = _truncate(stderr or "")

    if tool_version is None and tool_path:
        tool_version = detect_version(tool_path, tool_name)

    log_path = derive_log_path(output_file, log_dir, tool_name)

    duration_s = (ended - started).total_seconds()

    header_lines = [
        f"# ── pr0t31n tool execution log (schema {SCHEMA_VERSION}) ────────",
        f"# Tool        : {tool_name}",
    ]
    if tool_path:
        header_lines.append(f"# Path        : {tool_path}")
    header_lines += [
        f"# Version     : {tool_version or 'unknown'}",
        f"# Started     : {_ts_iso(started)}",
        f"# Ended       : {_ts_iso(ended)}",
        f"# Duration    : {duration_s:.3f}s",
        f"# Exit code   : {exit_code if exit_code is not None else 'n/a'}",
    ]
    if output_file:
        header_lines.append(f"# Output file : {output_file}")
    if cwd:
        header_lines.append(f"# CWD         : {cwd}")
    if extra_header:
        for k, v in extra_header.items():
            if v is None:
                continue
            header_lines.append(f"# {str(k)[:11]:<11} : {v}")
    header_lines += [
        "# " + "─" * 64,
        "",
    ]

    p1 = _prompt(cwd)
    body_lines = [p1 + _cmd_str(cmd)]
    if stdout:
        body_lines.append(stdout if stdout.endswith("\n") else stdout + "\n")
    if stderr:
        body_lines.append("# ── stderr ──")
        body_lines.append(stderr if stderr.endswith("\n") else stderr + "\n")
    body_lines.append(_prompt(cwd))

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "\n".join(header_lines) + "\n".join(body_lines),
            encoding="utf-8", errors="replace",
        )
    except Exception:
        # Logging must never break the scan.  Best-effort only.
        pass

    # ── Tool-output error detection (CLAUDE.md Section 14) ───────────────────
    # If the caller passes an *errors_log* path, scan the captured streams for
    # tool-specific error markers (e.g. nuclei "[ERR]", nmap "Failed to
    # resolve") and append a one-line summary per match to errors_log + a
    # corresponding JSON line to errors_log + ".json".  Best-effort.
    if errors_log:
        try:
            import importlib
            try:
                _el = importlib.import_module("pr0t31n_event_log")
            except ImportError:
                # Module not yet on sys.path — try the canonical install location.
                import sys as _s
                if "/opt/pr0t31n/shared" not in _s.path:
                    _s.path.insert(0, "/opt/pr0t31n/shared")
                _el = importlib.import_module("pr0t31n_event_log")
            events = _el.detect_tool_errors(tool_name, stdout, stderr, output_file=output_file)
            if events:
                errors_log = Path(errors_log)
                errors_log.parent.mkdir(parents=True, exist_ok=True)
                errors_json = errors_log.with_suffix(errors_log.suffix + ".json")
                with errors_log.open("a", encoding="utf-8") as f:
                    for ev in events:
                        f.write(f"[{ev['ts']}] [{ev['level']}] [{ev['tool']}] "
                                f"{ev['message']}  (source={ev.get('source', '?')})\n")
                with errors_json.open("a", encoding="utf-8") as f:
                    import json as _json
                    for ev in events:
                        f.write(_json.dumps(ev) + "\n")
        except Exception:
            pass

    return log_path


# ── Convenience runner ───────────────────────────────────────────────────────

def run_tool(
    cmd: list | str,
    *,
    tool_name: str | None = None,
    tool_path: str | None = None,
    output_file: str | Path | None = None,
    log_dir: str | Path | None = None,
    timeout: int | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    text: bool = True,
    check: bool = False,
    extra_header: dict | None = None,
    errors_log: str | Path | None = None,
) -> subprocess.CompletedProcess:
    """subprocess.run drop-in that auto-emits a .log sibling on completion.

    Captures stdout+stderr.  On timeout or OS error, still emits a .log with
    whatever output was collected and a "Note:" header line indicating the
    failure mode, then re-raises so callers see the same exception they would
    have seen from subprocess.run().
    """
    if isinstance(cmd, list):
        argv = [str(c) for c in cmd]
        first = argv[0] if argv else "tool"
    else:
        argv = cmd
        first = cmd.split()[0] if cmd.split() else "tool"

    if tool_name is None:
        tool_name = Path(first).name
    if tool_path is None:
        tool_path = first

    started = datetime.now().astimezone()
    try:
        proc = subprocess.run(
            argv, cwd=cwd, env=env, text=text,
            capture_output=True, timeout=timeout,
            errors="replace", check=check,
        )
        ended = datetime.now().astimezone()
        write_tool_log(
            cmd=cmd, started=started, ended=ended,
            exit_code=proc.returncode,
            stdout=proc.stdout, stderr=proc.stderr,
            tool_name=tool_name, tool_path=tool_path,
            output_file=output_file, log_dir=log_dir, cwd=cwd,
            extra_header=extra_header, errors_log=errors_log,
        )
        return proc
    except subprocess.TimeoutExpired as exc:
        ended = datetime.now().astimezone()
        _so = exc.stdout if isinstance(exc.stdout, (str, bytes)) else b""
        _se = exc.stderr if isinstance(exc.stderr, (str, bytes)) else b""
        write_tool_log(
            cmd=cmd, started=started, ended=ended,
            exit_code=None, stdout=_so, stderr=_se,
            tool_name=tool_name, tool_path=tool_path,
            output_file=output_file, log_dir=log_dir, cwd=cwd,
            extra_header={**(extra_header or {}), "Note": f"TIMEOUT after {timeout}s"},
            errors_log=errors_log,
        )
        raise
    except Exception as exc:
        ended = datetime.now().astimezone()
        write_tool_log(
            cmd=cmd, started=started, ended=ended,
            exit_code=None, stdout="", stderr=str(exc),
            tool_name=tool_name, tool_path=tool_path,
            output_file=output_file, log_dir=log_dir, cwd=cwd,
            extra_header={**(extra_header or {}), "Note": f"EXCEPTION: {type(exc).__name__}"},
            errors_log=errors_log,
        )
        raise


__all__ = [
    "SCHEMA_VERSION",
    "detect_version",
    "derive_log_path",
    "write_tool_log",
    "run_tool",
]
