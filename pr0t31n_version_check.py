"""pr0t31n_version_check.py — Startup version checker for pr0t31n Flask apps.

Call ``check_versions_at_startup()`` early in app startup to compare local
versions of the app, its tool dependencies, and the shared modules against
the latest versions on GitHub.  Prints a coloured console alert if any
updates are available.

Usage (in any Flask app's app.py)::

    try:
        import sys
        if "/opt/pr0t31n/shared" not in sys.path:
            sys.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_version_check as _vc
        _vc.check_versions_at_startup(
            app_name="Crucible",
            app_dir="/opt/pr0t31n/Crucible",
            tools=["Scattershot3", "Fracture", "Siphon", "AuthProbe"],
        )
    except Exception:
        pass
"""
from __future__ import annotations

VERSION = "1.0.0"

import os
import re
import subprocess
import sys
from pathlib import Path

_INSTALL_BASE = Path("/opt/pr0t31n")

_TOOL_REPOS: dict[str, str] = {
    "Arsenal":      "/opt/Arsenal",
    "Crucible":     "/opt/pr0t31n/Crucible",
    "Vantage":      "/opt/pr0t31n/Vantage",
    "Spectre":      "/opt/pr0t31n/Spectre",
    "Gauntlet":     "/opt/pr0t31n/Gauntlet",
    "Nexus":        "/opt/pr0t31n/Nexus",
    "Quiver":       "/opt/pr0t31n/Quiver",
    "Scattershot3": "/opt/pr0t31n/Scattershot3",
    "OSift":        "/opt/pr0t31n/OSift",
    "Fracture":     "/opt/pr0t31n/Fracture",
    "Siphon":       "/opt/pr0t31n/Siphon",
    "AuthProbe":    "/opt/pr0t31n/AuthProbe",
    "Aether":       "/opt/pr0t31n/Aether",
    "Aether-B":     "/opt/pr0t31n/Aether-B",
    "Aether-Z":     "/opt/pr0t31n/Aether-Z",
    "Aether-U":     "/opt/pr0t31n/Aether-U",
    "Gearbox":      "/opt/pr0t31n/Gearbox",
    "Bastion":      "/opt/pr0t31n/Bastion",
    "Forge":        "/opt/pr0t31n/Forge",
    "Quill":        "/opt/pr0t31n/Quill",
    "Isotope":      "/opt/pr0t31n/Isotope",
    "Arbiter":      "/opt/pr0t31n/Arbiter",
    "Phalanx":      "/opt/pr0t31n/Phalanx",
    "pAIn":         "/opt/pr0t31n/pAIn",
    "Auger":        "/opt/pr0t31n/Auger",
    "Prometheus":   "/Users/pr0t31n/Prometheus",
    "VulnManager":  "/opt/pr0t31n/VulnManager",
    "Helm":         "/opt/pr0t31n/Helm",
    "Shared":       "/opt/pr0t31n/shared",
    "Trawler":      "/opt/pr0t31n/Trawler",
    "Anvil":        "/opt/pr0t31n/Anvil",
    "Vault":        "/opt/pr0t31n/Vault",
    "Architect":    "/opt/pr0t31n/Architect",
    "LandNav":      "/opt/pr0t31n/LandNav",
    "Mole":         "/opt/pr0t31n/Mole",
    "Mole-Client":  "/opt/pr0t31n/Mole-Client",
    "Mole-Server":  "/opt/pr0t31n/Mole-Server",
    "Pivot":        "/opt/pr0t31n/Pivot",
}

_ANSI_YELLOW = "\033[33m"
_ANSI_GREEN  = "\033[32m"
_ANSI_CYAN   = "\033[36m"
_ANSI_RESET  = "\033[0m"
_ANSI_BOLD   = "\033[1m"
_ANSI_DIM    = "\033[2m"


def get_local_version(tool_dir: str) -> str | None:
    d = Path(tool_dir)
    vf = d / "VERSION"
    if vf.exists():
        v = vf.read_text().strip()
        if v:
            return v
    for candidate in d.glob("*.py"):
        try:
            txt = candidate.read_text(errors="ignore")
            m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', txt, re.MULTILINE)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


def get_remote_version(tool_dir: str, timeout: int = 5) -> str | None:
    d = Path(tool_dir)
    if not (d / ".git").is_dir():
        return None
    try:
        r = subprocess.run(
            ["git", "-C", str(d), "ls-remote", "--tags", "origin"],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0 and r.stdout.strip():
            tags = []
            for line in r.stdout.strip().splitlines():
                ref = line.split("\t")[-1]
                tag = ref.replace("refs/tags/", "").rstrip("^{}")
                tag = tag.lstrip("v")
                if re.match(r"^\d+\.\d+", tag):
                    tags.append(tag)
            if tags:
                tags.sort(key=lambda t: [int(x) for x in re.findall(r"\d+", t)])
                return tags[-1]
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "-C", str(d), "fetch", "--dry-run"],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode == 0 and r.stderr.strip():
            return "(remote has changes)"
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "-C", str(d), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=timeout,
        )
        local_head = r.stdout.strip() if r.returncode == 0 else None
        r2 = subprocess.run(
            ["git", "-C", str(d), "ls-remote", "origin", "HEAD"],
            capture_output=True, text=True, timeout=timeout,
        )
        if r2.returncode == 0 and r2.stdout.strip():
            remote_head = r2.stdout.split()[0]
            if local_head and remote_head and local_head != remote_head:
                return "(remote ahead)"
    except Exception:
        pass
    return None


def _compare_versions(local: str, remote: str) -> bool:
    if remote.startswith("("):
        return True
    try:
        lp = [int(x) for x in re.findall(r"\d+", local)]
        rp = [int(x) for x in re.findall(r"\d+", remote)]
        return rp > lp
    except Exception:
        return local != remote


def check_versions(app_name: str, app_dir: str,
                   tools: list[str] | None = None,
                   timeout: int = 5) -> list[dict]:
    """Check local vs remote versions. Returns list of update-available dicts."""
    checks = [(app_name, app_dir)]
    checks.append(("Shared", str(_INSTALL_BASE / "shared")))
    for t in (tools or []):
        td = _TOOL_REPOS.get(t)
        if td and td != app_dir:
            checks.append((t, td))
    updates = []
    for name, tdir in checks:
        if not Path(tdir).is_dir():
            continue
        local = get_local_version(tdir)
        if not local:
            continue
        remote = get_remote_version(tdir, timeout=timeout)
        if remote and _compare_versions(local, remote):
            updates.append({
                "tool": name,
                "local": local,
                "remote": remote,
                "path": tdir,
            })
    return updates


def check_versions_at_startup(app_name: str, app_dir: str,
                              tools: list[str] | None = None,
                              timeout: int = 5) -> None:
    """Run version checks and print coloured console alert if updates exist."""
    try:
        updates = check_versions(app_name, app_dir, tools=tools, timeout=timeout)
    except Exception:
        return
    if not updates:
        return
    print(f"\n{_ANSI_BOLD}{_ANSI_YELLOW}  Updates available:{_ANSI_RESET}")
    for u in updates:
        remote_str = u["remote"]
        if remote_str.startswith("("):
            remote_str = f"{_ANSI_DIM}{remote_str}{_ANSI_RESET}"
        else:
            remote_str = f"{_ANSI_GREEN}{remote_str}{_ANSI_RESET}"
        print(
            f"    {_ANSI_CYAN}{u['tool']:20s}{_ANSI_RESET}  "
            f"{u['local']:>10s}  →  {remote_str}"
        )
    print(f"  {_ANSI_DIM}Run: sudo arsenal  →  Upgrade All{_ANSI_RESET}\n")
