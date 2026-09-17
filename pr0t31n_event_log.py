"""
pr0t31n shared event log — universal timestamped event recorder + tool-output
error detector.

Every pr0t31n tool MUST emit timestamped log entries for:

  • EVENT     — milestones, phase transitions, startup/shutdown
  • INFO      — informational notices
  • WARN      — non-fatal warnings
  • ERROR     — execution errors raised by the tool's own code
  • EXCEPTION — uncaught Python exceptions (with traceback)
  • TOOL_ERROR — errors REPORTED BY a called third-party tool inside its
                 stdout/stderr or its result file (e.g. nmap "Failed to
                 resolve", nuclei "[ERR]", sslscan "Connection refused")

This module is the canonical implementation.  It is intentionally minimal —
it does NOT duplicate the existing per-tool loggers (Scattershot3's
OutputManager, Fracture's OutputManager, OSift's BaseLogger, Gearbox's
ctx.logger).  Instead it provides:

  1. EventLogger — a thin, append-only writer that produces *both* a
     human-readable .log line and a machine-readable .log.json line.
     Tools whose existing loggers already do this should *not* be migrated
     to EventLogger — they should adopt detect_tool_errors() and the
     range-query helpers only.

  2. detect_tool_errors(tool, stdout, stderr, output_file=None) — scans
     a third-party tool's output for known error markers and returns a
     list of dict events (one per matched error) ready to be appended to
     the originating tool's errors.log / errors.json.

  3. filter_entries(entries, from_dt, to_dt) — pure function that filters
     a list of log entries by timestamp range (inclusive).  Used by Flask
     /api/logs and /api/errors endpoints to back the time-range filter UI.

  4. count_errors(entries) — pure function counting entries with
     level/severity == ERROR / EXCEPTION / TOOL_ERROR.  Used by tab pill
     counters that must reflect *error count*, not total log count.

Schema version 1.0 — additive changes only.  See CLAUDE.md Section 14.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "1.0"

# Canonical event levels.  Apps may use lowercase or full words; the helpers
# below match case-insensitively.  ERROR / EXCEPTION / TOOL_ERROR all count
# toward "error" for pill counting.
EVENT_LEVELS = ("EVENT", "INFO", "WARN", "ERROR", "EXCEPTION", "TOOL_ERROR")
ERROR_LEVELS = {"ERROR", "EXCEPTION", "TOOL_ERROR", "FATAL", "CRITICAL"}


# ── Per-tool stdout/stderr error patterns ────────────────────────────────────
#
# Each entry: tool_name → list of (regex, severity, label) tuples.
# Regex is compiled with re.IGNORECASE | re.MULTILINE.
# Matched groups (if present) replace {0}, {1}, … in the label.
#
# Patterns are deliberately conservative — they flag genuine ERROR-level
# conditions, not informational notices.  Adding a pattern requires that the
# false-positive rate be near zero on healthy scans (otherwise every clean
# run would emit phantom errors).

_TOOL_ERROR_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    "nmap": [
        (r"Failed to resolve\s+(\"[^\"]+\"|\S+)",                    "ERROR", "nmap could not resolve host: {0}"),
        (r"Couldn't open .* for writing",                              "ERROR", "nmap could not write output file"),
        (r"^QUITTING!",                                                 "ERROR", "nmap aborted"),
        (r"Note: Host seems down\. If it is really up",               "WARN",  "nmap reports host appears down"),
    ],
    "nuclei": [
        (r"^\s*\[(ERR|FTL)\]\s+(.+?)$",                              "ERROR", "nuclei {0}: {1}"),
        (r"failed to load (provider keys|templates)[^\n]*",            "WARN",  "nuclei failed to load {0}"),
        (r"context deadline exceeded",                                  "WARN",  "nuclei: request timed out"),
    ],
    "nikto": [
        (r"ERROR:\s*(.+?)$",                                            "ERROR", "nikto: {0}"),
        (r"^\+\s*ERROR:\s*(.+?)$",                                     "ERROR", "nikto: {0}"),
        (r"No web server found",                                        "ERROR", "nikto: no web server on target"),
    ],
    "gobuster": [
        (r"Error:\s*(.+?)$",                                            "ERROR", "gobuster: {0}"),
        (r"the server returns a status code that matches",             "WARN",  "gobuster: wildcard / catch-all response — results may be noisy"),
        (r"unable to connect to",                                       "ERROR", "gobuster: unable to connect"),
    ],
    "ffuf": [
        (r"\[ERR\]\s*(.+?)$",                                          "ERROR", "ffuf: {0}"),
        (r"Encountered error.*",                                        "ERROR", "ffuf: encountered error"),
    ],
    "feroxbuster": [
        (r"ERR\s+(.+?)$",                                               "ERROR", "feroxbuster: {0}"),
        (r"error sending request",                                      "ERROR", "feroxbuster: error sending request"),
    ],
    "shcheck": [
        (r"SSL:\s*Certificate validation error",                       "ERROR", "shcheck: TLS certificate validation failed"),
        (r"Traceback \(most recent call last\)",                       "EXCEPTION", "shcheck raised a Python exception"),
        (r"Failed to establish a new connection",                       "ERROR", "shcheck: connection refused"),
    ],
    "sslscan": [
        (r"Connection refused",                                         "ERROR", "sslscan: connection refused"),
        (r"Connection error",                                           "ERROR", "sslscan: connection error"),
        (r"^ERROR:\s*(.+?)$",                                           "ERROR", "sslscan: {0}"),
        (r"Failed to find any ciphers",                                "WARN",  "sslscan: no ciphers negotiated"),
    ],
    "testssl": [
        (r"^Fatal[:\s]+(.+?)$",                                         "ERROR", "testssl.sh: FATAL {0}"),
        (r"^ERROR:\s*(.+?)$",                                           "ERROR", "testssl.sh: {0}"),
        (r"can.?t connect",                                              "ERROR", "testssl.sh: cannot connect"),
    ],
    "testssl.sh": [
        (r"^Fatal[:\s]+(.+?)$",                                         "ERROR", "testssl.sh: FATAL {0}"),
        (r"^ERROR:\s*(.+?)$",                                           "ERROR", "testssl.sh: {0}"),
        (r"can.?t connect",                                              "ERROR", "testssl.sh: cannot connect"),
    ],
    "wpscan": [
        (r"^\[!\]\s+(.+?error.+?)$",                                    "ERROR", "wpscan: {0}"),
        (r"Scan Aborted",                                               "ERROR", "wpscan: scan aborted"),
    ],
    "whatweb": [
        (r"ERROR\s+(.+?)$",                                              "ERROR", "whatweb: {0}"),
    ],
    "sqlmap": [
        (r"\[CRITICAL\]\s*(.+?)$",                                      "ERROR", "sqlmap CRITICAL: {0}"),
        (r"\[ERROR\]\s*(.+?)$",                                          "ERROR", "sqlmap: {0}"),
    ],
    "hydra": [
        (r"\[ERROR\]\s*(.+?)$",                                          "ERROR", "hydra: {0}"),
    ],
    "amass": [
        (r"\[ERR\]\s*(.+?)$",                                            "ERROR", "amass: {0}"),
        (r"FATAL\s+(.+?)$",                                              "ERROR", "amass FATAL: {0}"),
    ],
    "subfinder": [
        (r"\[FATAL\]\s*(.+?)$",                                          "ERROR", "subfinder FATAL: {0}"),
        (r"\[ERR\]\s*(.+?)$",                                            "ERROR", "subfinder: {0}"),
    ],
    "dnsx": [
        (r"\[FATAL\]\s*(.+?)$",                                          "ERROR", "dnsx FATAL: {0}"),
        (r"\[ERR\]\s*(.+?)$",                                            "ERROR", "dnsx: {0}"),
    ],
    "katana": [
        (r"\[FATAL\]\s*(.+?)$",                                          "ERROR", "katana FATAL: {0}"),
    ],
    "httpx": [
        (r"\[FATAL\]\s*(.+?)$",                                          "ERROR", "httpx FATAL: {0}"),
    ],
    "trufflehog": [
        (r"ERROR\s+(.+?)$",                                              "ERROR", "trufflehog: {0}"),
    ],
    "tcpdump": [
        (r"^tcpdump:\s+(.+?error.+?)$",                                 "ERROR", "tcpdump: {0}"),
        (r"No such device exists",                                       "ERROR", "tcpdump: capture interface not found"),
    ],
    "tshark": [
        (r"tshark:\s+(.+?error.+?)$",                                   "ERROR", "tshark: {0}"),
    ],
}

# Patterns common to almost every tool — applied after per-tool patterns so
# we don't double-flag known patterns.  Match against stderr most of the time.
_COMMON_PATTERNS: list[tuple[str, str, str]] = [
    (r"command not found",                                              "ERROR",     "shell: command not found"),
    (r"Permission denied",                                              "ERROR",     "permission denied"),
    (r"Traceback \(most recent call last\)",                           "EXCEPTION", "Python exception in tool stderr"),
    (r"panic: runtime error",                                          "EXCEPTION", "Go runtime panic"),
    (r"Segmentation fault",                                            "EXCEPTION", "SIGSEGV"),
    (r"core dumped",                                                    "ERROR",     "process core dumped"),
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def _compile(patterns: list[tuple[str, str, str]]) -> list[tuple[re.Pattern, str, str]]:
    return [(re.compile(p, re.IGNORECASE | re.MULTILINE), sev, lbl) for p, sev, lbl in patterns]


_COMPILED_TOOL = {k: _compile(v) for k, v in _TOOL_ERROR_PATTERNS.items()}
_COMPILED_COMMON = _compile(_COMMON_PATTERNS)


def detect_tool_errors(
    tool_name: str,
    stdout: str | None,
    stderr: str | None,
    *,
    output_file: str | Path | None = None,
    max_errors: int = 100,
) -> list[dict]:
    """Scan a tool's stdout/stderr for known error markers.

    Returns a list of event dicts ready to be appended to errors.log:
        {ts, level, tool, message, line, source, output_file}

    Caps at *max_errors* per invocation so a flood (e.g. nuclei against an
    unresponsive host) doesn't fill the log with thousands of identical lines.
    """
    results: list[dict] = []
    now = datetime.now().astimezone().isoformat(timespec="seconds")

    # Match against both stdout and stderr.  Strip ANSI escapes first — nuclei
    # and friends colourise output even when the stream isn't a TTY.
    streams = [
        ("stdout", _ANSI_RE.sub("", stdout or "")),
        ("stderr", _ANSI_RE.sub("", stderr or "")),
    ]

    tool_patterns = _COMPILED_TOOL.get(tool_name) or _COMPILED_TOOL.get(tool_name.replace(".py", ""), [])

    for source, text in streams:
        if not text:
            continue
        # Tool-specific patterns first
        for pat, sev, lbl_template in tool_patterns + _COMPILED_COMMON:
            if len(results) >= max_errors:
                break
            for m in pat.finditer(text):
                if len(results) >= max_errors:
                    break
                groups = m.groups()
                try:
                    label = lbl_template.format(*groups) if groups else lbl_template
                except (IndexError, KeyError):
                    label = lbl_template
                line = m.group(0).strip()[:400]
                results.append({
                    "ts":         now,
                    "level":      sev,
                    "tool":       tool_name,
                    "message":    label,
                    "line":       line,
                    "source":     source,
                    "output_file": str(output_file) if output_file else "",
                })

    return results


# ── EventLogger ──────────────────────────────────────────────────────────────

class EventLogger:
    """Append-only writer that emits BOTH human-readable and JSON log lines.

    Use this in NEW tools or in places where no existing logger is doing the
    job.  Do NOT replace existing loggers (Scattershot3 OutputManager,
    Fracture OutputManager, OSift BaseLogger, Gearbox ctx.logger) — they
    already cover their callsites; this class is for the parts of the codebase
    where logging is currently inconsistent or missing.
    """

    def __init__(self, log_path: str | Path, errors_path: str | Path | None = None,
                 *, tool: str = "", source: str = ""):
        self.log_path     = Path(log_path)
        self.errors_path  = Path(errors_path) if errors_path else None
        self.log_json     = self.log_path.with_suffix(self.log_path.suffix + ".json")
        self.errors_json  = (self.errors_path.with_suffix(self.errors_path.suffix + ".json")
                             if self.errors_path else None)
        self.tool         = tool
        self.source       = source
        self._lock        = threading.Lock()
        # §13b: scan.log / scan.log.json / errors.log / errors.log.json are
        # required run-dir files. Create them empty on init so a clean run
        # (no errors emitted) still produces the full set — readers and pill
        # counters expect the files to exist even when empty.
        for p in (self.log_path, self.log_json, self.errors_path, self.errors_json):
            if p:
                try:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    if not p.exists():
                        p.open("a", encoding="utf-8").close()
                except Exception:
                    pass

    def _emit(self, level: str, message: str, **extra) -> None:
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        entry = {
            "ts":       ts,
            "level":    level.upper(),
            "tool":     extra.pop("tool", None) or self.tool,
            "source":   extra.pop("source", None) or self.source,
            "message":  message,
        }
        entry.update({k: v for k, v in extra.items() if v is not None})
        line = f"[{ts}] [{entry['level']}] [{entry['tool'] or '-'}] {message}"

        with self._lock:
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
            try:
                with self.log_json.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass
            if entry["level"] in ERROR_LEVELS and self.errors_path:
                try:
                    with self.errors_path.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
                except Exception:
                    pass
                if self.errors_json:
                    try:
                        with self.errors_json.open("a", encoding="utf-8") as f:
                            f.write(json.dumps(entry) + "\n")
                    except Exception:
                        pass

    # Public level helpers — all forward to _emit
    def event(self,    msg: str, **kw) -> None: self._emit("EVENT",     msg, **kw)
    def info(self,     msg: str, **kw) -> None: self._emit("INFO",      msg, **kw)
    def warn(self,     msg: str, **kw) -> None: self._emit("WARN",      msg, **kw)
    def error(self,    msg: str, **kw) -> None: self._emit("ERROR",     msg, **kw)
    def tool_error(self, msg: str, **kw) -> None: self._emit("TOOL_ERROR", msg, **kw)
    def exception(self, msg: str, exc: BaseException | None = None, **kw) -> None:
        tb = ""
        if exc is not None:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        self._emit("EXCEPTION", msg + (("\n" + tb) if tb else ""), **kw)

    def append_tool_errors(self, tool: str, stdout: str | None, stderr: str | None,
                            *, output_file: str | Path | None = None) -> int:
        """Run detect_tool_errors() and append matched entries via tool_error()."""
        events = detect_tool_errors(tool, stdout, stderr, output_file=output_file)
        for e in events:
            self._emit(e["level"], e["message"],
                       tool=e["tool"], source=e["source"],
                       line=e.get("line"), output_file=e.get("output_file"))
        return len(events)


# ── Range query + counters ───────────────────────────────────────────────────

_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?")


def parse_dt_arg(value: str | None) -> datetime | None:
    """Parse an HTML5 datetime-local value (YYYY-MM-DDTHH:MM[:SS]).

    Treats naive input as local-time so it round-trips with the picker UI.
    Returns None when the value is missing or unparseable — callers should
    treat None as "no bound on this side."
    """
    if not value:
        return None
    s = value.strip()
    if not s:
        return None
    try:
        # Python 3.11+ accepts many ISO 8601 forms via fromisoformat
        dt = datetime.fromisoformat(s)
    except ValueError:
        m = _ISO_RE.match(s)
        if not m:
            return None
        y, mo, d, h, mi = (int(g) for g in m.groups()[:5])
        se = int(m.group(6)) if m.group(6) else 0
        dt = datetime(y, mo, d, h, mi, se)
    # Treat naive datetimes as local-time, so they compare correctly to ts
    # strings that include offsets.
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def _entry_ts(entry: dict) -> datetime | None:
    """Extract and parse a log entry's timestamp.  Returns None when missing
    or malformed (caller decides whether to include or drop it)."""
    if not isinstance(entry, dict):
        return None
    raw = entry.get("ts") or entry.get("time") or entry.get("timestamp")
    if not raw:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(raw).astimezone()
        except (OSError, ValueError):
            return None
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        # Try common "YYYY-MM-DD HH:MM:SS" form
        m = _ISO_RE.match(raw)
        if not m:
            return None
        y, mo, d, h, mi = (int(g) for g in m.groups()[:5])
        se = int(m.group(6)) if m.group(6) else 0
        dt = datetime(y, mo, d, h, mi, se)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def filter_entries(entries: Iterable[dict],
                    from_dt: datetime | None = None,
                    to_dt:   datetime | None = None,
                    *,
                    drop_untimestamped: bool = False) -> list[dict]:
    """Inclusive filter: keep entries with from_dt <= ts <= to_dt.

    When *from_dt* or *to_dt* is None that side is unbounded.
    Entries whose timestamp cannot be parsed are kept by default (so a
    malformed-ts entry is never silently hidden); pass
    drop_untimestamped=True to drop them.
    """
    out: list[dict] = []
    for e in entries:
        ts = _entry_ts(e)
        if ts is None:
            if not drop_untimestamped:
                out.append(e)
            continue
        if from_dt is not None and ts < from_dt:
            continue
        if to_dt is not None and ts > to_dt:
            continue
        out.append(e)
    return out


def count_errors(entries: Iterable[dict]) -> int:
    """Return the count of entries whose level/severity is an error class.

    Recognises 'level', 'severity', or 'risk' fields.  Case-insensitive.
    Used by Flask app tab pills (per CLAUDE.md Section 14d) which must
    reflect *error count*, not total log count.
    """
    n = 0
    for e in entries:
        if not isinstance(e, dict):
            continue
        v = e.get("level") or e.get("severity") or e.get("risk") or ""
        if str(v).upper() in ERROR_LEVELS:
            n += 1
    return n


__all__ = [
    "SCHEMA_VERSION",
    "EVENT_LEVELS",
    "ERROR_LEVELS",
    "EventLogger",
    "detect_tool_errors",
    "filter_entries",
    "count_errors",
    "parse_dt_arg",
]
