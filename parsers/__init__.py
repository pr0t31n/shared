"""Shared dependency-tool output parsers.

Auto-detect which parser handles a file and produce universal-schema
v1.1 findings from raw tool output.  Content-driven — the parser
sniffs format from file contents, not from flags or extensions.

    from shared.parsers import auto_parse, auto_parse_dir

    findings = auto_parse(Path("nuclei_results.jsonl"))
    findings = auto_parse_dir(Path("/run/deps/o365spray_20261015/"))
"""

import logging
import sys
from pathlib import Path

_pkg_dir = str(Path(__file__).resolve().parent)
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

log = logging.getLogger("pr0t31n.parsers")

# ── Parser registry (lazy-populated on first use) ───────────────

_PARSER_CLASSES = [
    ("o365spray", "O365SprayParser"),
    # Future:
    # ("nmap",     "NmapParser"),
    # ("nuclei",   "NucleiParser"),
    # ("testssl",  "TestSSLParser"),
    # ("sslscan",  "SSLScanParser"),
    # ("nikto",    "NiktoParser"),
    # ("gobuster", "GobusterParser"),
    # ("hydra",    "HydraParser"),
    # ("wpscan",   "WPScanParser"),
]

_parsers = None


def _ensure_parsers():
    global _parsers
    if _parsers is not None:
        return
    _parsers = []
    for mod_path, cls_name in _PARSER_CLASSES:
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            _parsers.append(cls())
        except Exception as exc:
            log.debug("Could not load parser %s.%s: %s", mod_path, cls_name, exc)


def auto_detect(path):
    """Return the first parser that can handle *path*, or None."""
    _ensure_parsers()
    path = Path(path)
    for p in _parsers:
        try:
            if p.detect(path):
                return p
        except Exception:
            continue
    return None


def auto_parse(path, **kwargs):
    """Auto-detect parser for *path* and return findings list.

    Returns an empty list when no parser matches.
    """
    path = Path(path)
    parser = auto_detect(path)
    if parser:
        return parser.parse(path, **kwargs)
    return []


def auto_parse_dir(dir_path, **kwargs):
    """Walk *dir_path*, auto-detect parsers, and return all findings.

    Skips ``.log`` files and already-parsed universal ``findings.json``.
    Deduplicates by (tool, title, target, affected) tuple.
    """
    _ensure_parsers()
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        return auto_parse(dir_path, **kwargs)

    findings = []
    seen = set()

    for f in sorted(dir_path.rglob("*")):
        if not f.is_file():
            continue
        name = f.name.lower()
        if name.endswith(".log"):
            continue
        if name == "findings.json" or name == "meta.json":
            continue

        parser = auto_detect(f)
        if not parser:
            continue

        try:
            batch = parser.parse(f, **kwargs)
            for finding in batch:
                dedup_key = (
                    finding.get("tool", ""),
                    finding.get("title", ""),
                    finding.get("hostname", "") or finding.get("ip", ""),
                    finding.get("affected", ""),
                )
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(finding)
        except Exception as exc:
            log.warning("Parser %s failed on %s: %s",
                        parser.tool_name, f, exc)

    return findings
