"""
pr0t31n shared Trawler integration.

Trawler (/opt/pr0t31n/Trawler/trawler.py) is a passive pcap traffic analyser.
Every pr0t31n tool that produces a network capture (.pcap, .pcapng, .cap)
MUST call run_trawler_on_pcap() after the capture completes — per CLAUDE.md
Section 16 — so:

  • Trawler output lands in the originating tool's run directory
  • Trawler findings are merged into the originating tool's findings.json
  • The .log + errors.log conventions of Section 14 are preserved

This module is the canonical implementation.  Trawler invocations from tools
SHOULD use this rather than spawning Trawler directly, so the integration
stays consistent if Trawler's CLI changes.

Schema version 1.0 — additive changes only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "1.0"

TRAWLER_PATH = Path("/opt/pr0t31n/Trawler/trawler.py")
DEFAULT_TIMEOUT = 600   # 10 min ceiling — most Trawler runs finish in <60s.


def _have_trawler() -> tuple[bool, str]:
    """Return (available, reason).  Best-effort: only checks for the script
    + Python executable; doesn't try to import or run Trawler itself."""
    if not TRAWLER_PATH.exists():
        return False, f"trawler.py not found at {TRAWLER_PATH}"
    if not shutil.which(sys.executable):
        return False, f"python executable not resolvable ({sys.executable})"
    return True, ""


def _ips_from_pcap(pcap: Path, top_n: int = 20) -> list[str]:
    """Fallback target derivation: extract the top-N most-talked-about IPv4
    addresses from the pcap using tshark.  Used only when the caller cannot
    supply explicit targets (e.g. wireless captures without DHCP context).

    Returns an empty list if tshark isn't installed or the pcap yields nothing.
    """
    tshark = shutil.which("tshark")
    if not tshark or not pcap.exists():
        return []
    try:
        proc = subprocess.run(
            [tshark, "-r", str(pcap), "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst", "-Q"],
            capture_output=True, text=True, timeout=60, errors="replace",
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    counts: dict[str, int] = {}
    for line in (proc.stdout or "").splitlines():
        for ip in line.split("\t"):
            ip = (ip or "").strip()
            if not ip or ":" in ip:        # skip blanks and IPv6 for v1
                continue
            counts[ip] = counts.get(ip, 0) + 1
    return [ip for ip, _ in sorted(counts.items(), key=lambda x: -x[1])[:top_n]]


def run_trawler_on_pcap(
    pcap: str | Path,
    out_dir: str | Path,
    *,
    targets: Iterable[str] | None = None,
    scope: str = "int",
    include_internal: bool = False,
    client: str = "trawler",
    timeout: int = DEFAULT_TIMEOUT,
    output_mgr=None,
    findings_path: str | Path | None = None,
    errors_log: str | Path | None = None,
) -> dict:
    """Run Trawler against *pcap*, save its output under *out_dir*, and merge
    any Trawler findings into *findings_path* (when provided).

    Returns a dict:
        {
          "ran":            bool,
          "skipped_reason": str,
          "trawler_dir":    str (absolute) or "",
          "findings":       list[dict] — Trawler findings parsed from its
                            findings.json (empty when Trawler couldn't run),
          "merged_into":    str — path to the findings file we appended to
                            (empty when no merge was performed),
        }

    All failure paths are non-fatal: Trawler MUST NOT break the originating
    tool.  Errors are recorded to *errors_log* (or stderr) and the function
    returns ran=False with skipped_reason populated.
    """
    pcap = Path(pcap)
    out_dir = Path(out_dir)
    trawler_dir = out_dir / "trawler"
    result = {"ran": False, "skipped_reason": "", "trawler_dir": "",
              "findings": [], "merged_into": ""}

    ok, why = _have_trawler()
    if not ok:
        result["skipped_reason"] = why
        _log_err(errors_log, "trawler", f"skipped — {why}")
        return result
    if not pcap.exists():
        result["skipped_reason"] = f"pcap missing: {pcap}"
        _log_err(errors_log, "trawler", result["skipped_reason"])
        return result
    if pcap.stat().st_size == 0:
        result["skipped_reason"] = f"pcap empty: {pcap}"
        return result

    # Resolve targets.  Caller-supplied wins; otherwise we extract the top
    # talkers from the pcap.  Trawler refuses to run with no targets.
    tgt_list = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not tgt_list:
        tgt_list = _ips_from_pcap(pcap)
    if not tgt_list:
        result["skipped_reason"] = "no targets resolvable from pcap"
        return result

    trawler_dir.mkdir(parents=True, exist_ok=True)
    targets_file = trawler_dir / "_trawler_targets.txt"
    try:
        targets_file.write_text("\n".join(tgt_list), encoding="utf-8")
    except Exception as exc:
        result["skipped_reason"] = f"could not write targets file: {exc}"
        _log_err(errors_log, "trawler", result["skipped_reason"])
        return result

    cmd = [
        sys.executable, str(TRAWLER_PATH),
        "--pcap", str(pcap),
        "--targets-file", str(targets_file),
        "--output-dir", str(trawler_dir),
        "--scope", scope if scope in ("int", "ext") else "int",
        "--client", client,
    ]
    if include_internal:
        cmd.append("--include-internal")

    started = datetime.now().astimezone()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired as exc:
        result["skipped_reason"] = f"trawler timeout after {timeout}s"
        _log_err(errors_log, "trawler", result["skipped_reason"])
        _emit_run_log(trawler_dir, cmd, started, datetime.now().astimezone(),
                      None, "", str(exc))
        return result
    except OSError as exc:
        result["skipped_reason"] = f"trawler launch error: {exc}"
        _log_err(errors_log, "trawler", result["skipped_reason"])
        return result
    ended = datetime.now().astimezone()

    _emit_run_log(trawler_dir, cmd, started, ended, proc.returncode,
                  proc.stdout or "", proc.stderr or "", errors_log=errors_log)

    result["ran"] = True
    result["trawler_dir"] = str(trawler_dir)

    # Parse Trawler's findings and (optionally) merge them.
    findings_file = trawler_dir / "findings.json"
    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                result["findings"] = data
            elif isinstance(data, dict) and isinstance(data.get("findings"), list):
                result["findings"] = data["findings"]
        except Exception as exc:
            _log_err(errors_log, "trawler",
                     f"could not parse trawler findings.json: {exc}")

    if findings_path and result["findings"]:
        merged = _merge_findings(Path(findings_path), result["findings"],
                                  output_mgr=output_mgr, errors_log=errors_log)
        if merged:
            result["merged_into"] = str(findings_path)

    return result


# ── Internals ────────────────────────────────────────────────────────────────

def _log_err(errors_log, source: str, msg: str) -> None:
    """Append a TOOL_ERROR-style line to errors_log; fall back to stderr."""
    line = (f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] "
            f"[TOOL_ERROR] [{source}] {msg}\n")
    if not errors_log:
        sys.stderr.write(line)
        return
    try:
        Path(errors_log).parent.mkdir(parents=True, exist_ok=True)
        with Path(errors_log).open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        sys.stderr.write(line)


def _emit_run_log(out_dir: Path, cmd: list, started: datetime, ended: datetime,
                  exit_code, stdout: str, stderr: str, errors_log=None) -> None:
    """Best-effort .log sibling for the Trawler invocation itself — mirrors
    pr0t31n_tool_runner.write_tool_log() so Section 14 conventions hold."""
    try:
        import importlib
        try:
            ur = importlib.import_module("pr0t31n_tool_runner")
        except ImportError:
            if "/opt/pr0t31n/shared" not in sys.path:
                sys.path.insert(0, "/opt/pr0t31n/shared")
            ur = importlib.import_module("pr0t31n_tool_runner")
        ur.write_tool_log(
            cmd=cmd, started=started, ended=ended, exit_code=exit_code,
            stdout=stdout, stderr=stderr,
            tool_name="trawler", tool_path=str(TRAWLER_PATH),
            output_file=out_dir / "findings.json",
            errors_log=errors_log,
        )
    except Exception:
        pass


def _merge_findings(findings_path: Path, trawler_findings: list[dict],
                     *, output_mgr=None, errors_log=None) -> int:
    """Append Trawler findings to the originating tool's findings.json.

    Three cases for the destination file:
      1. File exists and is a JSON list — append, deduplicate by (catalogue_id, ip, port, title).
      2. File exists but is a JSON object with a "findings" list — append into that key.
      3. File doesn't exist — create a new list-shaped findings.json.

    When *output_mgr* is supplied AND it exposes add_finding(...) (Scattershot3
    / Fracture style), we route through that instead so the manager's
    invariants (CSV mirror, FP de-dup, in-memory cache) are honoured.

    Returns the number of findings appended.
    """
    if not trawler_findings:
        return 0

    # Preferred path: route through the originating tool's OutputManager.
    if output_mgr is not None and hasattr(output_mgr, "add_finding"):
        n = 0
        for f in trawler_findings:
            try:
                output_mgr.add_finding(
                    title       = f.get("title", "Trawler Finding"),
                    ip          = f.get("ip", ""),
                    port        = int(f.get("port", 0) or 0),
                    risk        = f.get("risk", "INFO"),
                    description = f.get("description", ""),
                    sources     = (f.get("sources") or "trawler"),
                    affected    = f.get("affected", f.get("ip", "")),
                    output_file = f.get("output_file", ""),
                    cves        = f.get("cves", ""),
                    remediation = f.get("remediation", ""),
                )
                n += 1
            except TypeError:
                # OutputManager.add_finding signatures vary slightly across
                # tools; fall back to direct file append rather than crashing.
                output_mgr = None
                break
            except Exception as exc:
                _log_err(errors_log, "trawler",
                         f"merge via OutputManager.add_finding failed: {exc}")
                output_mgr = None
                break
        if output_mgr is not None:
            return n

    # Direct file merge (fallback or no output_mgr).
    try:
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        existing: list = []
        wrapper: dict | None = None
        if findings_path.exists():
            try:
                raw = json.loads(findings_path.read_text(encoding="utf-8"))
            except Exception:
                raw = None
            if isinstance(raw, list):
                existing = raw
            elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
                wrapper = raw
                existing = raw["findings"]

        seen: set[tuple] = set()
        def _key(f: dict) -> tuple:
            return (f.get("catalogue_id", ""), f.get("ip", ""),
                    int(f.get("port", 0) or 0), f.get("title", ""))
        for f in existing:
            if isinstance(f, dict):
                seen.add(_key(f))

        appended = 0
        for f in trawler_findings:
            if not isinstance(f, dict):
                continue
            k = _key(f)
            if k in seen:
                continue
            # Tag the source so a reader can trace it back to Trawler post-merge.
            if "source_tools" in f and isinstance(f["source_tools"], list):
                if "trawler" not in f["source_tools"]:
                    f["source_tools"].append("trawler")
            else:
                f["source_tools"] = ["trawler"]
            existing.append(f)
            seen.add(k)
            appended += 1

        if wrapper is not None:
            wrapper["findings"] = existing
            findings_path.write_text(json.dumps(wrapper, indent=2),
                                     encoding="utf-8")
        else:
            findings_path.write_text(json.dumps(existing, indent=2),
                                     encoding="utf-8")
        return appended
    except Exception as exc:
        _log_err(errors_log, "trawler",
                 f"direct findings merge failed: {exc}")
        return 0


__all__ = [
    "SCHEMA_VERSION",
    "TRAWLER_PATH",
    "run_trawler_on_pcap",
]
