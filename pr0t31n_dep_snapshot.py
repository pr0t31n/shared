#!/usr/bin/env python3
"""pr0t31n dependency snapshot — record installed dependency versions at scan start.

Usage (in any pr0t31n tool, at scan startup):

    try:
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_dep_snapshot as _ds
        _ds.write_snapshot(run_dir, TOOL_NAME, VERSION,
                           binaries=["nmap", "nuclei", "sslscan", ...],
                           pip_packages=["requests", "flask", "scapy", ...])
    except ImportError:
        pass  # degrade gracefully

Produces <run_dir>/dependencies.json with:
  - tool name, version, python version
  - timestamp
  - each binary's path + version
  - each pip package's installed version
  - system info (OS, kernel, arch)
"""
from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from threading import Lock

__all__ = ["write_snapshot", "collect_snapshot"]

_VERSION_TIMEOUT = 4
_VERSION_CACHE: dict[str, str] = {}
_CACHE_LOCK = Lock()

_VERSION_FLAGS: dict[str, list[list[str]]] = {
    "nmap":          [["--version"]],
    "nuclei":        [["-version"]],
    "nikto":         [["-Version"]],
    "gobuster":      [["version"]],
    "ffuf":          [["-V"]],
    "feroxbuster":   [["--version"]],
    "wpscan":        [["--version"]],
    "whatweb":       [["--version"]],
    "sslscan":       [["--version"]],
    "testssl.sh":    [["--version"]],
    "testssl":       [["--version"]],
    "shcheck":       [["--help"]],
    "shcheck.py":    [["--help"]],
    "curl":          [["--version"]],
    "wget":          [["--version"]],
    "hydra":         [["-h"]],
    "msfconsole":    [["--version"]],
    "searchsploit":  [["--version"]],
    "smbmap":        [["--version"]],
    "smbclient":     [["--version"]],
    "enum4linux":    [["--version"], ["-h"]],
    "enum4linux-ng": [["--version"], ["-h"]],
    "rpcclient":     [["--version"]],
    "dig":           [["-v"]],
    "dnsx":          [["-version"]],
    "subfinder":     [["-version"]],
    "amass":         [["--version"], ["-version"]],
    "katana":        [["-version"]],
    "httpx":         [["-version"]],
    "trufflehog":    [["--version"]],
    "gitleaks":      [["version"]],
    "sqlmap":        [["--version"]],
    "openssl":       [["version"]],
    "ssh-audit":     [["--version"], ["-h"]],
    "snmpwalk":      [["-V"]],
    "ipmitool":      [["-V"]],
    "responder":     [["--version"], ["-h"]],
    "gowitness":     [["version"]],
    "webanalyze":    [["-version"]],
    "tcpdump":       [["--version"]],
    "nc":            [["-h"]],
    "ncat":          [["--version"]],
    "go":            [["version"]],
    "aircrack-ng":   [["--help"]],
    "airodump-ng":   [["--help"]],
    "kismet":        [["--version"]],
    "wifite":        [["--help"]],
    "odat":          [["--version"], ["-h"]],
    "xsstrike":      [["--help"]],
    "dirsearch":     [["--version"]],
    "kiterunner":    [["--version"]],
    "kr":            [["--version"]],
    "git":           [["--version"]],
    "rustscan":      [["--version"]],
    "nbtscan":       [["-V"]],
    "kerbrute":      [["--help"]],
    "ike-scan":      [["--version"]],
    "showmount":     [["--version"]],
    "o365spray":     [["--version"], ["-h"]],
    "dnstwist":      [["--version"]],
    "whois":         [["--version"]],
    "theHarvester":  [["--version"], ["-h"]],
    "sublist3r":     [["--version"], ["-h"]],
    "chromium":      [["--version"]],
    "google-chrome": [["--version"]],
    "geckodriver":   [["--version"]],
    "chromedriver":  [["--version"]],
    "tshark":        [["--version"]],
    "hcxdumptool":   [["--version"]],
    "hcxpcapngtool": [["--version"]],
    "hashcat":       [["--version"]],
    "john":          [["--version"]],
}

_GENERIC_FLAGS = [["--version"], ["-version"], ["-V"], ["version"]]

_VER_RE = None  # lazy-compiled


def _ver_regex():
    global _VER_RE
    if _VER_RE is None:
        import re
        _VER_RE = re.compile(r'(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.+-]*))')
    return _VER_RE


def _detect_version(tool_path: str, basename: str) -> str:
    with _CACHE_LOCK:
        if basename in _VERSION_CACHE:
            return _VERSION_CACHE[basename]
    candidates = _VERSION_FLAGS.get(basename) or _GENERIC_FLAGS
    result = "unknown"
    for argv in candidates:
        try:
            proc = subprocess.run(
                [tool_path, *argv],
                capture_output=True, text=True,
                timeout=_VERSION_TIMEOUT,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            m = _ver_regex().search(out)
            if m:
                result = m.group(1)
                break
        except Exception:
            continue
    with _CACHE_LOCK:
        _VERSION_CACHE[basename] = result
    return result


def _pip_version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except Exception:
        pass
    try:
        mod = __import__(package.replace("-", "_"))
        return getattr(mod, "__version__", getattr(mod, "VERSION", "installed"))
    except Exception:
        return "not installed"


def _dpkg_version(package: str) -> str:
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f", "${Version}", package],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return "not installed"


def _collect_runtimes() -> dict:
    """Always-checked language runtimes and core tooling."""
    runtimes: dict = {
        "python": {
            "version": platform.python_version(),
            "path": sys.executable,
        },
    }
    # pip itself
    try:
        runtimes["pip"] = {
            "version": importlib.metadata.version("pip"),
            "path": shutil.which("pip3") or shutil.which("pip") or "",
        }
    except Exception:
        runtimes["pip"] = {"version": "unknown", "path": ""}

    # Go, Ruby, Node — include only if present on the system
    for rt, bn in [("go", "go"), ("ruby", "ruby"), ("node", "node"),
                   ("npm", "npm"), ("gem", "gem")]:
        path = shutil.which(bn)
        if path:
            runtimes[rt] = {
                "version": _detect_version(path, bn),
                "path": path,
            }
    return runtimes


def collect_snapshot(
    tool_name: str,
    tool_version: str,
    *,
    binaries: list[str] | None = None,
    pip_packages: list[str] | None = None,
    apt_packages: list[str] | None = None,
) -> dict:
    """Collect dependency versions without writing to disk."""
    snap: dict = {
        "snapshot_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": tool_name,
        "tool_version": tool_version,
        "runtimes": _collect_runtimes(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "node": platform.node(),
        },
        "binaries": {},
        "pip_packages": {},
    }

    if apt_packages and platform.system() == "Linux":
        snap["apt_packages"] = {}
        for pkg in apt_packages:
            snap["apt_packages"][pkg] = _dpkg_version(pkg)

    for bn in (binaries or []):
        path = shutil.which(bn)
        if path:
            ver = _detect_version(path, bn)
            snap["binaries"][bn] = {"path": path, "version": ver}
        else:
            snap["binaries"][bn] = {"path": None, "version": "not found"}

    for pkg in (pip_packages or []):
        snap["pip_packages"][pkg] = _pip_version(pkg)

    return snap


def write_snapshot(
    run_dir: str | Path,
    tool_name: str,
    tool_version: str,
    *,
    binaries: list[str] | None = None,
    pip_packages: list[str] | None = None,
    apt_packages: list[str] | None = None,
    filename: str = "dependencies.json",
) -> Path:
    """Collect and write dependency snapshot to <run_dir>/dependencies.json."""
    snap = collect_snapshot(
        tool_name, tool_version,
        binaries=binaries, pip_packages=pip_packages,
        apt_packages=apt_packages,
    )
    out = Path(run_dir) / filename
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    return out
