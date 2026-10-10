"""pr0t31n_installer — shared dependency validation and installation helpers.

Every pr0t31n tool installer should import this module to validate whether
dependencies already exist before attempting to install them.  This avoids
wasted time, broken builds (e.g. pyarrow source-compiling on ARM), and
conflicts with system-managed packages.

Usage in an install.py::

    import sys
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    try:
        import pr0t31n_installer as _inst
    except ImportError:
        _inst = None

    # Then use _inst.pip_check_install(PIP_PKGS) etc.
    # Falls back to raw pip install if the module is not available.
"""

import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

__all__ = [
    "pip_is_installed", "pip_check_install", "pip_check_install_list",
    "apt_is_installed", "go_bin_exists", "bin_exists",
    "gem_is_installed", "git_clone_or_update",
]

# ── pip name → importable module mapping ─────────────────────────────────────

_IMPORT_MAP = {
    "python-whois": "whois",
    "beautifulsoup4": "bs4",
    "python-docx": "docx",
    "pyOpenSSL": "OpenSSL",
    "dnspython": "dns",
    "pyyaml": "yaml",
    "Pillow": "PIL",
    "charset-normalizer": "charset_normalizer",
    "webdriver-manager": "webdriver_manager",
    "edgartools": "edgar",
    "cloud-enum": "cloud_enum",
    "EmailHarvester": "EmailHarvester",
    "flask-cors": "flask_cors",
    "flask-socketio": "flask_socketio",
    "flask-login": "flask_login",
    "python-engineio": "engineio",
    "python-socketio": "socketio",
    "service_identity": "service_identity",
    "python-dotenv": "dotenv",
    "scikit-learn": "sklearn",
    "google-auth": "google.auth",
    "google-api-python-client": "googleapiclient",
    "azure-identity": "azure.identity",
    "azure-mgmt-resource": "azure.mgmt.resource",
    "python-nmap": "nmap",
    "python-pptx": "pptx",
    "python-dateutil": "dateutil",
    "ruamel.yaml": "ruamel.yaml",
}


def _pkg_name(spec: str) -> str:
    """Extract package name from a pip specifier like 'requests>=2.31.0'."""
    for sep in (">=", "==", "<=", "!=", "~=", "<", ">", "[", ";"):
        spec = spec.split(sep)[0]
    return spec.strip()


def _import_name(pkg: str) -> str:
    """Map pip package name to importable module name."""
    return _IMPORT_MAP.get(pkg, pkg.replace("-", "_").lower())


# ── pip checks ───────────────────────────────────────────────────────────────

def pip_is_installed(pkg_spec: str) -> bool:
    """Check whether a pip package is already importable.

    Accepts full specifiers like 'requests>=2.31.0' — strips the version
    constraint and checks whether the package is importable via
    importlib.util.find_spec().
    """
    name = _pkg_name(pkg_spec)
    mod = _import_name(name)
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def pip_check_install(pkg_spec: str, *, pip_cmd: list | None = None,
                      extra_flags: list | None = None,
                      timeout: int = 300, quiet: bool = False) -> bool:
    """Install a pip package only if not already present.

    Returns True if the package was already installed or installed
    successfully, False on failure.
    """
    if pip_is_installed(pkg_spec):
        if not quiet:
            print(f"  [+]   ✓ {pkg_spec} already installed")
        return True

    if pip_cmd is None:
        pip_cmd = [sys.executable, "-m", "pip"]
    cmd = pip_cmd + ["install", "--break-system-packages"]
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.append(pkg_spec)

    if not quiet:
        print(f"  [*] pip install {pkg_spec} …")
    try:
        result = subprocess.run(cmd, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        if not quiet:
            print(f"  [!] pip install timed out for {pkg_spec}")
        return False
    except Exception as exc:
        if not quiet:
            print(f"  [!] pip install failed for {pkg_spec}: {exc}")
        return False


def pip_check_install_list(pkg_specs: list, *, pip_cmd: list | None = None,
                           extra_flags: list | None = None,
                           timeout: int = 300, quiet: bool = False) -> dict:
    """Check and install a list of pip packages, skipping those already present.

    Returns a dict mapping package name → status:
      'skipped' (already installed), 'installed', 'failed'
    """
    results = {}
    for spec in pkg_specs:
        name = _pkg_name(spec)
        if pip_is_installed(spec):
            if not quiet:
                print(f"  [+]   ✓ {spec} already installed")
            results[name] = "skipped"
        else:
            ok = pip_check_install(spec, pip_cmd=pip_cmd,
                                   extra_flags=extra_flags,
                                   timeout=timeout, quiet=quiet)
            results[name] = "installed" if ok else "failed"
    return results


# ── apt/dpkg checks ──────────────────────────────────────────────────────────

def apt_is_installed(pkg: str) -> bool:
    """Check whether an apt package is installed via dpkg-query."""
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True, timeout=10,
        )
        return "install ok installed" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def apt_check_install_list(pkgs: list, *, quiet: bool = False) -> dict:
    """Check and install apt packages, reporting which were already present.

    Returns dict mapping package → 'skipped' | 'installed' | 'failed'.
    Note: apt-get install -y is inherently idempotent, but this avoids
    the overhead of invoking apt for already-installed packages and
    gives clear output about what was already there.
    """
    missing = []
    results = {}
    for pkg in pkgs:
        if apt_is_installed(pkg):
            if not quiet:
                print(f"  [+]   ✓ {pkg} already installed")
            results[pkg] = "skipped"
        else:
            missing.append(pkg)

    if missing:
        if not quiet:
            print(f"  [*] Installing {len(missing)} missing packages: "
                  f"{' '.join(missing)}")
        try:
            rc = subprocess.run(
                ["apt-get", "install", "-y"] + missing
            ).returncode
            status = "installed" if rc == 0 else "failed"
            for pkg in missing:
                results[pkg] = status
        except Exception as exc:
            if not quiet:
                print(f"  [-] apt-get install failed: {exc}")
            for pkg in missing:
                results[pkg] = "failed"
    return results


# ── binary / go / gem checks ────────────────────────────────────────────────

def bin_exists(name: str) -> bool:
    """Check whether a binary is on PATH."""
    return shutil.which(name) is not None


def go_bin_exists(module_path: str) -> bool:
    """Check whether a Go binary (from its module path) is already installed.

    Extracts the binary name from the module path:
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest → subfinder
    """
    parts = module_path.split("/")
    name = parts[-1].split("@")[0]
    return bin_exists(name)


def go_check_install_list(modules: list, *, quiet: bool = False) -> dict:
    """Check and install Go modules, skipping those whose binary already exists."""
    results = {}
    go = shutil.which("go")
    if not go:
        if not quiet:
            print("  [!] go not found on PATH — skipping Go installs")
        for mod in modules:
            results[mod] = "skipped_no_go"
        return results

    for mod in modules:
        parts = mod.split("/")
        name = parts[-1].split("@")[0]
        if bin_exists(name):
            if not quiet:
                print(f"  [+]   ✓ {name} already installed")
            results[mod] = "skipped"
        else:
            if not quiet:
                print(f"  [*] go install {name} …")
            try:
                rc = subprocess.run(
                    [go, "install", mod],
                    env={**os.environ,
                         "GOPATH": os.environ.get("GOPATH", "/root/go"),
                         "GOBIN": "/usr/local/bin"},
                    timeout=300,
                ).returncode
                results[mod] = "installed" if rc == 0 else "failed"
            except subprocess.TimeoutExpired:
                if not quiet:
                    print(f"  [!] go install timed out for {name}")
                results[mod] = "failed"
    return results


def gem_is_installed(name: str) -> bool:
    """Check whether a Ruby gem is installed."""
    try:
        result = subprocess.run(
            ["gem", "list", "--exact", name],
            capture_output=True, text=True, timeout=10,
        )
        return name in result.stdout and "(" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── git clone helpers ────────────────────────────────────────────────────────

def git_clone_or_update(url: str, dest: str, *, depth: int = 1,
                        quiet: bool = False) -> bool:
    """Clone a repo if not present, or pull if it exists.

    Returns True if the repo is available after the operation.
    """
    dest_path = Path(dest)
    if dest_path.exists():
        if not quiet:
            print(f"  [*] {dest_path.name}: directory exists — pulling latest...")
        rc = subprocess.run(
            ["git", "-C", dest, "pull", "--ff-only"],
            timeout=120,
        ).returncode
        if rc != 0 and not quiet:
            print(f"  [!] {dest_path.name}: git pull failed — using existing clone.")
        return True
    else:
        if not quiet:
            print(f"  [*] Cloning {url} → {dest}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone"]
        if depth:
            cmd.extend(["--depth", str(depth)])
        cmd.extend([url, dest])
        try:
            rc = subprocess.run(cmd, timeout=300).returncode
            return rc == 0
        except subprocess.TimeoutExpired:
            if not quiet:
                print(f"  [!] git clone timed out for {url}")
            return False


# ── requirements.txt helpers ─────────────────────────────────────────────────

def pip_check_install_requirements(req_path: str, *,
                                   pip_cmd: list | None = None,
                                   exclude: set | None = None,
                                   timeout: int = 300,
                                   quiet: bool = False) -> dict:
    """Parse a requirements.txt and install only missing packages.

    Optionally exclude certain package names (lowercase) from installation.
    """
    req_file = Path(req_path)
    if not req_file.exists():
        if not quiet:
            print(f"  [!] requirements.txt not found: {req_path}")
        return {}

    results = {}
    exclude = {e.lower() for e in (exclude or set())}

    for line in req_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name = _pkg_name(line).lower()
        if name in exclude:
            if not quiet:
                print(f"  [*]   filtered out: {line}")
            results[name] = "excluded"
            continue
        ok = pip_check_install(line, pip_cmd=pip_cmd, timeout=timeout,
                               quiet=quiet)
        results[name] = "installed" if ok else "failed"
    return results


# ── platform helpers ─────────────────────────────────────────────────────────

def is_arm() -> bool:
    """Check if running on ARM architecture."""
    machine = platform.machine().lower()
    return any(arm in machine for arm in ("arm", "aarch64"))


def detect_os() -> str:
    """Detect OS type: apt | dnf | zypper | macos | windows | unknown."""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        for rf in ("/etc/os-release", "/usr/lib/os-release"):
            if os.path.exists(rf):
                with open(rf) as fh:
                    content = fh.read().lower()
                if "kali" in content or "debian" in content or "ubuntu" in content:
                    return "apt"
                if "rhel" in content or "centos" in content or "fedora" in content:
                    return "dnf"
                if "suse" in content:
                    return "zypper"
                return "apt"
    return "unknown"


def summary(results: dict, label: str = "Dependencies") -> None:
    """Print a summary of install results."""
    skipped = sum(1 for v in results.values() if v == "skipped")
    installed = sum(1 for v in results.values() if v == "installed")
    failed = sum(1 for v in results.values() if v == "failed")
    total = len(results)
    parts = []
    if skipped:
        parts.append(f"{skipped} already present")
    if installed:
        parts.append(f"{installed} newly installed")
    if failed:
        parts.append(f"{failed} FAILED")
    print(f"  [{'+' if not failed else '!'}] {label}: "
          f"{total} total — {', '.join(parts)}")
