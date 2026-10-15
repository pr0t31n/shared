"""Base class for shared dependency-tool output parsers.

Every parser in this package takes raw output from an external tool
(nmap, nuclei, testssl, o365spray, etc.) and produces a list of
universal-schema v1.1 finding dicts via ``pr0t31n_schema.make_finding``.

Parsers are content-driven, not flag-driven.  The same parser handles
every output format a tool can produce (XML, JSON, CSV, plain text)
by sniffing the file content.  An optional ``tool_flags`` hint is a
fast-path shortcut — the parser never *requires* it.

Usage
-----
    from shared.parsers import auto_parse, auto_parse_dir

    findings = auto_parse(Path("testssl_192.168.1.1.json"))
    findings = auto_parse_dir(Path("/run/deps/o365spray_20261015/"))
"""

import logging
import sys
from pathlib import Path

if "/opt/pr0t31n/shared" not in sys.path:
    sys.path.insert(0, "/opt/pr0t31n/shared")

try:
    import pr0t31n_schema as _schema
except ImportError:
    _schema = None

log = logging.getLogger("pr0t31n.parsers")


def _make_finding(**kwargs):
    """Wrapper around pr0t31n_schema.make_finding with graceful fallback."""
    if _schema:
        return _schema.make_finding(**kwargs)
    from datetime import datetime
    import uuid
    finding = {
        "id": str(uuid.uuid4()),
        "datetime": datetime.now().isoformat(),
    }
    finding.update(kwargs)
    return finding


class ToolParser:
    """Base class for all dependency-tool output parsers.

    Subclasses MUST set ``tool_name`` and implement ``detect`` + ``parse``.
    Subclasses SHOULD implement ``detect_format`` and per-format parse
    methods (``_parse_xml``, ``_parse_json``, etc.) when the tool
    produces multiple output formats.
    """

    tool_name: str = ""

    # Known output formats this parser handles.
    # Subclass sets this so auto_parse_dir can log what it tried.
    supported_formats: "list[str]" = []

    def detect(self, path: Path) -> bool:
        """Return True if *path* is output from this tool.

        Detection is content-based: sniff magic bytes, file structure,
        or characteristic strings.  File extension is a hint, never
        the sole criterion.
        """
        raise NotImplementedError

    def detect_format(self, path: Path) -> str:
        """Determine which output format variant *path* contains.

        Returns a short string like ``"xml"``, ``"json"``, ``"jsonl"``,
        ``"csv"``, ``"gnmap"``, ``"text"``.  Falls back to ``"text"``
        when undetermined.
        """
        return "text"

    def parse(self, path: Path, *,
              target: str = "",
              scope: "str | None" = None,
              phase: str = "",
              tool_flags: "str | None" = None,
              ) -> "list[dict]":
        """Parse *path* and return universal-schema v1.1 findings.

        Parameters
        ----------
        path : Path
            File or directory to parse.
        target : str
            Target hostname / IP / domain if known by the caller.
        scope : str | None
            Scope label (``"external"``, ``"internal"``, etc.).
        phase : str
            Phase label for the findings.
        tool_flags : str | None
            Optional hint of flags used (e.g. ``"-sV -oX"``).  The
            parser MUST work without this — it's a fast-path shortcut.

        Returns
        -------
        list[dict]
            Universal v1.1 finding dicts (from ``make_finding``).
        """
        raise NotImplementedError

    def _sniff_head(self, path: Path, n: int = 2048) -> str:
        """Read the first *n* bytes of a file as text (best-effort)."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(n)
        except OSError:
            return ""

    def _read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _read_json(self, path: Path):
        import json
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
