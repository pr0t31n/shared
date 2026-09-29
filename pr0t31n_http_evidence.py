"""pr0t31n_http_evidence — per-request evidence triplet for built-in-Python HTTP.

Companion to pr0t31n_tool_runner (which logs third-party tools). This module
captures EVERY request/response made through a requests.Session as a triplet:

    <run_dir>/evidence/<phase>/<METHOD>__<safe_path>/req_<NNNN>_<ts>_request.txt
    <run_dir>/evidence/<phase>/<METHOD>__<safe_path>/req_<NNNN>_<ts>_response.txt
    <run_dir>/evidence/<phase>/<METHOD>__<safe_path>/req_<NNNN>_<ts>.log

The .log is a transcript (method/url/status/timing/headers) of the in-process
exchange. Paths are run-dir-relative (CLAUDE.md §13c). Adoption is one call:

    import pr0t31n_http_evidence as he
    rec = he.attach_http_evidence(session, run_dir, phase_getter=lambda: cur_phase())

`phase_getter` returns the current phase label; requests issued for a finding
should additionally have their triplet paths attached to the finding's
output_file / log references (rec.last_paths()).
"""
from __future__ import annotations
import os, re, threading
from datetime import datetime
from urllib.parse import urlparse

_MAX_BODY = 524288


def _safe(s: str) -> str:
    return (re.sub(r"[^\w.-]", "_", str(s))[:80]) or "root"


class HttpEvidenceRecorder:
    def __init__(self, run_dir, phase_getter=None, subdir: str = "evidence"):
        self._run_dir_raw = run_dir
        self.subdir = subdir
        self.phase_getter = phase_getter or (lambda: "http")
        self._counts: dict = {}
        self._lock = threading.Lock()
        self._last = {}

    # registered as a requests `response` hook → called per request
    def __call__(self, resp, *args, **kwargs):
        try:
            self._record(resp)
        except Exception:
            pass
        return resp

    def last_paths(self) -> dict:
        """Triplet paths (run-dir-relative) for the most recent request on this thread."""
        return dict(self._last.get(threading.get_ident(), {}))

    def _record(self, resp) -> None:
        req = getattr(resp, "request", None)
        if req is None:
            return
        run_dir = self._run_dir_raw() if callable(self._run_dir_raw) else str(self._run_dir_raw)
        if not run_dir:
            return
        try:
            u = urlparse(req.url)
        except Exception:
            return
        phase = _safe(self.phase_getter() or "http")
        epdir = f"{_safe(req.method or 'GET')}__{_safe(u.path or '/')}"
        with self._lock:
            key = (phase, epdir)
            n = self._counts.get(key, 0) + 1
            self._counts[key] = n
        reldir = os.path.join(self.subdir, phase, epdir)
        absdir = os.path.join(str(run_dir), reldir)
        os.makedirs(absdir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = f"req_{n:04d}_{ts}"
        relbase = os.path.join(reldir, stem)
        absbase = os.path.join(absdir, stem)

        rl = [f"{req.method} {req.url}"]
        for hk, hv in (getattr(req, "headers", {}) or {}).items():
            rl.append(f"{hk}: {hv}")
        rl.append("")
        body = getattr(req, "body", None)
        if body is not None:
            rl.append(body if isinstance(body, str) else body.decode("utf-8", "replace"))
        with open(absbase + "_request.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(rl)[:_MAX_BODY])

        sl = [f"HTTP {resp.status_code} {getattr(resp, 'reason', '') or ''}"]
        for hk, hv in (resp.headers or {}).items():
            sl.append(f"{hk}: {hv}")
        sl.append("")
        try:
            sl.append((resp.text or "")[:_MAX_BODY])
        except Exception:
            pass
        with open(absbase + "_response.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(sl))

        try:
            el = resp.elapsed.total_seconds()
        except Exception:
            el = 0.0
        with open(absbase + ".log", "w", encoding="utf-8") as f:
            f.write(
                f"# in-process HTTP request (pr0t31n_http_evidence)\n"
                f"# phase:    {phase}\n# method:   {req.method}\n# url:      {req.url}\n"
                f"# status:   {resp.status_code}\n# elapsed_s:{el:.3f}\n"
                f"# request:  {stem}_request.txt\n# response: {stem}_response.txt\n"
            )
        self._last[threading.get_ident()] = {
            "request": relbase + "_request.txt",
            "response": relbase + "_response.txt",
            "log": relbase + ".log",
        }


def attach_http_evidence(session, run_dir, phase_getter=None, subdir: str = "evidence"):
    """Register the per-request evidence recorder on a requests.Session. One call."""
    rec = HttpEvidenceRecorder(run_dir, phase_getter, subdir)
    hooks = session.hooks.get("response") or []
    if not isinstance(hooks, list):
        hooks = [hooks]
    hooks.append(rec)
    session.hooks["response"] = hooks
    return rec
