#!/usr/bin/env python3
"""
pr0t31n integration test harness.

Exercises every cross-tool link from the interaction map:
  Layer A — shared module imports
  Layer B — dummy data generation (schema-compliant)
  Layer C — schema validation round-trip
  Layer D — Prometheus UniversalParser routing
  Layer E — Flask app /api/nexus-status probes (only if app is running)
  Layer F — FP add/load/remove cycle (incl. backward-compat snake_case read)
  Layer G — Arbiter ZIP universal fast-path (synthetic ZIP)
  Layer H — Tier-3 synthesis (Gearbox jsonl → universal findings.json)
  Layer I — v1.1 enrichment renderer (Node check; skipped if node absent)

Exit code: 0 if every non-skipped test passed, 1 otherwise.

Usage:
  python3 /tmp/pr0t31n_integration_test.py            # full run
  python3 /tmp/pr0t31n_integration_test.py --layers ABCDFH   # subset
  python3 /tmp/pr0t31n_integration_test.py --quiet     # only summary
"""
from __future__ import annotations

import argparse
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ── Add shared modules to path (Phase 0 deployed location) ──────────────
SHARED = "/opt/pr0t31n/shared"
if SHARED not in sys.path:
    sys.path.insert(0, SHARED)


# ── Test result accumulator ────────────────────────────────────────────
class Results:
    def __init__(self, quiet=False):
        self.passed: list = []
        self.failed: list = []
        self.skipped: list = []
        self.quiet = quiet

    def ok(self, label, detail=""):
        self.passed.append((label, detail))
        if not self.quiet:
            print(f"  \033[32m✓\033[0m {label}" + (f"  {detail}" if detail else ""))

    def fail(self, label, detail):
        self.failed.append((label, detail))
        print(f"  \033[31m✗\033[0m {label}: {detail}")

    def skip(self, label, reason):
        self.skipped.append((label, reason))
        if not self.quiet:
            print(f"  \033[33m⊘\033[0m {label} (skipped: {reason})")

    def section(self, name):
        if not self.quiet:
            print(f"\n\033[36m[{name}]\033[0m")

    def summary(self):
        total = len(self.passed) + len(self.failed) + len(self.skipped)
        print(f"\n{'=' * 60}")
        print(f"Results: \033[32m{len(self.passed)} passed\033[0m, "
              f"\033[31m{len(self.failed)} failed\033[0m, "
              f"\033[33m{len(self.skipped)} skipped\033[0m  (of {total})")
        if self.failed:
            print(f"\nFailures:")
            for label, detail in self.failed:
                print(f"  \033[31m✗\033[0m {label}: {detail}")
        return len(self.failed) == 0


# ───────────────────────────────────────────────────────────────────────────
# Layer A — Shared module imports
# ───────────────────────────────────────────────────────────────────────────
def layer_a(r):
    r.section("Layer A — shared module imports")
    try:
        import pr0t31n_schema
        r.ok(f"pr0t31n_schema  v{pr0t31n_schema.SCHEMA_VERSION}")
        assert pr0t31n_schema.SCHEMA_VERSION == "1.1", f"expected 1.1, got {pr0t31n_schema.SCHEMA_VERSION}"
        r.ok("pr0t31n_schema  SCHEMA_VERSION == 1.1")
        # All required helpers present
        for fn in ("make_meta", "make_finding", "make_summary",
                   "augment_finding", "augment_findings_file",
                   "write_universal_findings", "validate_run_dir",
                   "init_run_dir", "write_meta", "write_summary",
                   "append_finding", "universal_run_dir", "clients_base",
                   "to_relative_output_file"):
            assert callable(getattr(pr0t31n_schema, fn, None)), f"missing helper: {fn}"
        r.ok("pr0t31n_schema  all 14 helpers callable")
    except Exception as e:
        r.fail("pr0t31n_schema", str(e))
    try:
        import pr0t31n_false_positives as fp
        for fn in ("load_false_positives", "add_false_positive",
                   "remove_false_positive", "find_false_positive",
                   "fp_paths", "content_key"):
            assert callable(getattr(fp, fn, None)), f"missing FP helper: {fn}"
        r.ok("pr0t31n_false_positives  all 6 helpers callable")
        # Verify camelCase canonical
        jp, cp = fp.fp_paths("/tmp")
        assert jp.name == "falsePositives.json", f"expected falsePositives.json, got {jp.name}"
        r.ok("pr0t31n_false_positives  camelCase canonical name")
    except Exception as e:
        r.fail("pr0t31n_false_positives", str(e))
    # v1.1 enrichment JS — vendored copy in each app's static/js/
    for app in ("Crucible", "Vantage", "Gauntlet", "Spectre", "Bastion"):
        p = Path(f"/opt/pr0t31n/{app}/static/js/pr0t31n_v11_enrichment.js")
        if p.exists():
            sz = p.stat().st_size
            r.ok(f"{app}  v11_enrichment.js vendored ({sz} bytes)")
        else:
            r.fail(f"{app}  v11_enrichment.js vendored", "file missing")


# ───────────────────────────────────────────────────────────────────────────
# Layer B + C — Dummy data generation + schema validation
# ───────────────────────────────────────────────────────────────────────────
TOOLS = {
    "scattershot3": {"scope": "int", "phase": "p3_ssl",      "service": "https"},
    "fracture":     {"scope": None,  "phase": "p5_xss",       "service": "https"},
    "siphon":       {"scope": None,  "phase": "p3_auth",      "service": "https"},
    "gearbox":      {"scope": None,  "phase": "p2_audit",     "service": "ssh"},
    "aether":       {"scope": None,  "phase": "",             "service": "wifi"},
    "auger":        {"scope": None,  "phase": "p4_priv",      "service": "postgres"},
    "osift":        {"scope": None,  "phase": "p11_dns",      "service": "dns"},
    "bastion":      {"scope": None,  "phase": "",             "service": "firewall-config"},
    "authprobe":    {"scope": None,  "phase": "",             "service": "https"},
    "pain":         {"scope": None,  "phase": "",             "service": "AI Pipeline"},
}


def _dummy_finding(schema, tool: str, profile: dict) -> dict:
    """Build a v1.1-enriched dummy finding for a given tool."""
    extras = {
        "cvss_score":          7.4,
        "cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "cwe":                 ["CWE-79"],
        "nist_800_53":         ["SI-10"],
        "pci_dss_4":           ["6.2.4"],
        "iso_27001":           ["A.8.28"],
        "mitre_attack":        [{"technique": "T1059.007", "tactic": "Execution"}],
        "kev":                 False,
        "remediation_effort":  "Moderate",
        "remediation_component": "Application",
        "remediation_category":  "Input Validation",
        "owasp_api":           "API3:2023" if tool == "siphon" else "",
        "ssid":                "TestNet"          if tool == "aether" else "",
        "bssid":               "AA:BB:CC:00:00:00" if tool == "aether" else "",
        "wireless_data":       {"channel": 6, "encryption": "WPA2"} if tool == "aether" else {},
        "subdevice":           "router-01" if tool == "gearbox" else "",
        "interface":           "eth0"      if tool == "gearbox" else "",
        "instance":            "inst-A"    if tool == "gearbox" else "",
        "classification":      "Confirmed" if tool == "gearbox" else "",
        "api_endpoint_path":   "/v1/users" if tool == "siphon" else "",
        "api_method":          "GET"       if tool == "siphon" else "",
        "api_from_spec":       True        if tool == "siphon" else False,
        "is_rogue_endpoint":   False,
        "confidence":          "Firm",
        "aliases":             ["Test Finding Alias 1", "Alias 2"],
        "source_tools":        [tool],
        "cve_examples":        ["CVE-2024-0001"],
        "searchsploit_terms":  ["dummy"],
        "metasploit_modules":  [],
    }
    return schema.make_finding(
        tool=tool, title=f"Dummy {tool} XSS finding",
        ip="10.0.0.42", port=443, hostname="test.acme.local",
        risk="HIGH",
        command=f"{tool} --dummy --target test.acme.local",
        description=f"Test finding emitted by integration harness for {tool}.",
        remediation="Disregard — this is a synthetic test record.",
        sources=tool, affected="10.0.0.42:443",
        scope=profile["scope"], phase=profile["phase"],
        service=profile["service"],
        owasp="A03:2021", **extras,
    )


def layer_bc(r, base_dir: Path):
    r.section("Layer B+C — dummy data generation + schema validation")
    try:
        import pr0t31n_schema as schema
    except ImportError as e:
        r.fail("Layer B+C", f"pr0t31n_schema not importable: {e}")
        return
    for tool, profile in TOOLS.items():
        run_dir = base_dir / tool / f"dummy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            schema.init_run_dir(run_dir)
            schema.write_meta(run_dir, schema.make_meta(
                tool=tool, version="test-1.0",
                client_short="dummy", client_name="DUMMY TEST CLIENT",
                engagement_name=f"{tool} integration test",
                target="test.acme.local",
            ), legacy_filename=None)
            f = _dummy_finding(schema, tool, profile)
            schema.append_finding(run_dir, f, scope=profile["scope"])
            schema.write_summary(run_dir, schema.make_summary(
                tool=tool, version="test-1.0",
                scan_start=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                scan_end=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                target="test.acme.local", success=True,
                total_findings=1,
                risk_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            ))
            # Validate
            report = schema.validate_run_dir(run_dir)
            errs = (report["meta_errors"] +
                    list(report["finding_errors"].values()) +
                    report["summary_errors"])
            if errs:
                r.fail(f"{tool}  schema validate", str(errs[:2]))
            else:
                r.ok(f"{tool}  generate + validate run-dir")
        except Exception as e:
            r.fail(f"{tool}  generate", str(e))


# ───────────────────────────────────────────────────────────────────────────
# Layer D — Prometheus UniversalParser routing
# ───────────────────────────────────────────────────────────────────────────
def layer_d(r, base_dir: Path):
    r.section("Layer D — Prometheus UniversalParser round-trip")
    prom_parsers = Path("/Users/pr0t31n/Prometheus/parsers")
    if not (prom_parsers / "universal.py").exists():
        r.skip("UniversalParser", f"{prom_parsers}/universal.py not deployed")
        return
    import importlib.util
    def _load(name, path):
        s = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(s)
        sys.modules[name] = m
        s.loader.exec_module(m)
        return m
    try:
        base = _load("base", str(prom_parsers / "base.py"))
        sys.modules["parsers"] = type(sys)("parsers")
        sys.modules["parsers.base"] = base
        univ = _load("parsers.universal", str(prom_parsers / "universal.py"))
    except Exception as e:
        r.fail("UniversalParser  load", str(e))
        return

    for tool_dir in sorted(base_dir.iterdir()):
        if not tool_dir.is_dir():
            continue
        for run_dir in tool_dir.iterdir():
            if not run_dir.is_dir():
                continue
            try:
                if not univ.UniversalParser.detect(run_dir):
                    r.fail(f"{tool_dir.name}  detect", "False")
                    continue
                p = univ.UniversalParser(run_dir, project_id="test", project_name="test")
                findings, targets, endpoints = p.parse()
                if not findings:
                    r.fail(f"{tool_dir.name}  parse", "0 findings")
                    continue
                f = findings[0]
                checks = []
                if not f.id:                 checks.append("missing id")
                if f.source_tool != tool_dir.name: checks.append(f"source_tool={f.source_tool}")
                if f.risk != "HIGH":        checks.append(f"risk={f.risk}")
                if f.cvss_score != 7.4:     checks.append(f"cvss_score={f.cvss_score}")
                if f.cwe != ["CWE-79"]:     checks.append(f"cwe={f.cwe}")
                if checks:
                    r.fail(f"{tool_dir.name}  field mapping", "; ".join(checks))
                else:
                    r.ok(f"{tool_dir.name}  UniversalParser ({len(findings)} findings, cvss={f.cvss_score})")
            except Exception as e:
                r.fail(f"{tool_dir.name}  parse", str(e))


# ───────────────────────────────────────────────────────────────────────────
# Layer E — Flask app /api/nexus-status probes
# ───────────────────────────────────────────────────────────────────────────
FLASK_APPS = [
    # (name, default_port)
    ("Vantage", 5100), ("Quiver", 5200), ("Spectre", 5300),
    ("Nexus", 5400), ("Crucible", 5500), ("Bastion", 5600),
    ("Gauntlet", 5700),
    # Arbiter/Phalanx default to 5000 but conflict; probe both
    ("Arbiter-or-Phalanx", 5000),
]


def layer_e(r):
    r.section("Layer E — Flask app /api/nexus-status probes")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    for name, port in FLASK_APPS:
        # Port-open check first
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except (OSError, socket.timeout):
            r.skip(f"{name} :{port}", "port not open")
            continue
        # Probe both schemes
        succeeded = False
        for scheme, extra in (("https", {"context": ctx}), ("http", {})):
            url = f"{scheme}://127.0.0.1:{port}/api/nexus-status"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "pr0t31n-integration-test/1.0"})
                with urllib.request.urlopen(req, timeout=2, **extra) as resp:
                    data = json.loads(resp.read())
                    v = data.get("version", "?")
                    t = data.get("tool", data.get("name", name.lower()))
                    r.ok(f"{name} :{port} {scheme} /api/nexus-status (tool={t}, v={v})")
                    succeeded = True
                    break
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    r.ok(f"{name} :{port} {scheme}  HTTP 401 (auth required — endpoint exists)")
                    succeeded = True
                    break
            except (urllib.error.URLError, json.JSONDecodeError, ConnectionResetError) as e:
                continue
        if not succeeded:
            r.fail(f"{name} :{port}  /api/nexus-status", "no scheme responded")


# ───────────────────────────────────────────────────────────────────────────
# Layer F — FP add/load/remove cycle (incl. backward-compat snake_case read)
# ───────────────────────────────────────────────────────────────────────────
def layer_f(r):
    r.section("Layer F — false-positive cycle")
    try:
        import pr0t31n_false_positives as fp
    except ImportError as e:
        r.fail("Layer F", str(e))
        return
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        f1 = {"id": "fp-1", "title": "Test FP 1", "ip": "10.0.0.1", "port": 80, "risk": "MEDIUM"}
        f2 = {"id": "fp-2", "title": "Test FP 2", "ip": "10.0.0.2", "port": 22, "risk": "LOW"}
        fields = ["id", "title", "ip", "port", "risk"]
        # Add
        if not fp.add_false_positive(td, f1, csv_fieldnames=fields):
            r.fail("FP add 1", "returned False"); return
        if not fp.add_false_positive(td, f2, csv_fieldnames=fields):
            r.fail("FP add 2", "returned False"); return
        r.ok("FP add (camelCase canonical)")
        # Files exist?
        if (td / "falsePositives.json").exists() and (td / "falsePositives.csv").exists():
            r.ok("falsePositives.{json,csv} canonical files written")
        else:
            r.fail("FP canonical files", "missing one of json/csv")
        # Idempotent re-add
        if fp.add_false_positive(td, f1, csv_fieldnames=fields):
            r.fail("FP idempotent re-add", "returned True (duplicate)")
        else:
            r.ok("FP idempotent re-add (dedupe by id)")
        # Load
        loaded = fp.load_false_positives(td)
        if len(loaded) == 2 and {x["id"] for x in loaded} == {"fp-1", "fp-2"}:
            r.ok("FP load roundtrip (2 entries)")
        else:
            r.fail("FP load roundtrip", f"got {len(loaded)}: {[x.get('id') for x in loaded]}")
        # Find
        if fp.find_false_positive(td, "fp-1")["title"] == "Test FP 1":
            r.ok("FP find_false_positive by id")
        else:
            r.fail("FP find_false_positive", "did not return correct entry")
        # Remove
        rem = fp.remove_false_positive(td, "fp-1", csv_fieldnames=fields)
        if rem and rem["id"] == "fp-1":
            r.ok("FP remove returns removed finding")
        else:
            r.fail("FP remove", f"got {rem}")
        if len(fp.load_false_positives(td)) == 1:
            r.ok("FP remove updates store")
        else:
            r.fail("FP remove updates store", "wrong remaining count")
        # Backward-compat legacy snake_case read
        for fname in ("falsePositives.json", "falsePositives.csv"):
            (td / fname).unlink(missing_ok=True)
        (td / "false_positives.json").write_text(json.dumps([{"id": "legacy-1", "title": "Old FP"}]))
        legacy = fp.load_false_positives(td)
        if len(legacy) == 1 and legacy[0]["id"] == "legacy-1":
            r.ok("FP backward-compat snake_case read")
        else:
            r.fail("FP backward-compat snake_case read", f"got {legacy}")


# ───────────────────────────────────────────────────────────────────────────
# Layer G — Synthetic ZIP for Arbiter universal fast-path
# ───────────────────────────────────────────────────────────────────────────
def layer_g(r, base_dir: Path):
    r.section("Layer G — synthetic ZIP for Arbiter/Phalanx universal fast-path")
    # Build a ZIP containing meta.json (schema 1.1) + findings.json
    try:
        import pr0t31n_schema as schema
    except ImportError:
        r.skip("ZIP build", "pr0t31n_schema not importable")
        return
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        meta = schema.make_meta(
            tool="fracture", version="test-1.0",
            client_short="dummy", client_name="ZIP Import Test",
            engagement_name="ZIP test", target="https://test.example.com",
        )
        zf.writestr("meta.json", json.dumps(meta, indent=2))
        f = _dummy_finding(schema, "fracture", TOOLS["fracture"])
        zf.writestr("findings.json", json.dumps([f], indent=2))
    buf.seek(0)
    # Re-read to verify it parses
    try:
        with zipfile.ZipFile(buf) as zf:
            names = zf.namelist()
            if "meta.json" in names and "findings.json" in names:
                r.ok(f"Synthetic ZIP built ({sum(len(zf.read(n)) for n in names)} bytes total)")
            else:
                r.fail("Synthetic ZIP", f"missing files: {names}")
                return
            meta_loaded = json.loads(zf.read("meta.json"))
            findings_loaded = json.loads(zf.read("findings.json"))
            if meta_loaded.get("schema_version") == "1.1":
                r.ok("ZIP meta.json carries schema_version=1.1")
            else:
                r.fail("ZIP schema_version", meta_loaded.get("schema_version"))
            if len(findings_loaded) == 1 and findings_loaded[0]["cvss_score"] == 7.4:
                r.ok(f"ZIP findings.json carries v1.1 enrichment (cvss={findings_loaded[0]['cvss_score']})")
            else:
                r.fail("ZIP findings", str(findings_loaded[:1]))
    except Exception as e:
        r.fail("Synthetic ZIP parse", str(e))

    # Write the ZIP to disk so user can manually upload to Arbiter UI if desired
    zip_path = base_dir / "arbiter_universal_test.zip"
    zip_path.write_bytes(buf.getvalue())
    r.ok(f"ZIP at {zip_path} — upload to Arbiter/Phalanx /api/upload_zip to live-test")


# ───────────────────────────────────────────────────────────────────────────
# Layer H — Gearbox JSONL → universal findings.json synthesis dry-run
# ───────────────────────────────────────────────────────────────────────────
def layer_h(r, base_dir: Path):
    r.section("Layer H — Gearbox JSONL → universal synthesis dry-run")
    try:
        import pr0t31n_schema as schema
    except ImportError:
        r.skip("Layer H", "pr0t31n_schema not importable")
        return
    # Simulate Gearbox findings.jsonl
    rd = base_dir / "gearbox_jsonl_test"
    rd.mkdir(parents=True, exist_ok=True)
    jsonl = rd / "findings.jsonl"
    native_rows = [
        {"id": "gb-1", "title": "SNMPv1 default community", "affected_host": "192.168.1.1",
         "affected_port": 161, "severity": "Medium", "cvss_score": 5.0,
         "classification": "Confirmed", "subdevice": "core-switch",
         "interface": "mgmt0", "instance": "instance-1",
         "cve_ids": ["CVE-2024-1234"], "tools_used": ["snmpwalk", "nmap"]},
        {"id": "gb-2", "title": "Weak SSH cipher", "affected_host": "192.168.1.1",
         "affected_port": 22, "severity": "Low"},
    ]
    jsonl.write_text("\n".join(json.dumps(r) for r in native_rows))
    # Run the synthesis logic (matches gearbox _u_synthesize_outputs)
    raw_findings = []
    for line in jsonl.read_text().splitlines():
        if not line.strip(): continue
        obj = json.loads(line)
        mapped = dict(obj)
        if "affected_host" in mapped and not mapped.get("ip"):
            mapped["ip"] = mapped.pop("affected_host")
        if "affected_port" in mapped and not mapped.get("port"):
            mapped["port"] = int(mapped.pop("affected_port") or 0)
        if "severity" in mapped and not mapped.get("risk"):
            mapped["risk"] = mapped.pop("severity")
        mapped.setdefault("sources", "gearbox")
        mapped.setdefault("description", mapped.get("title", ""))
        mapped.setdefault("remediation", "See module docs.")
        if "cvss_score" in mapped:
            try: mapped["cvss_score"] = float(mapped["cvss_score"])
            except: mapped["cvss_score"] = None
        if isinstance(mapped.get("cve_ids"), list) and not mapped.get("cves"):
            mapped["cves"] = ",".join(mapped["cve_ids"])
        if isinstance(mapped.get("tools_used"), list):
            mapped["source_tools"] = mapped["tools_used"]
        raw_findings.append(mapped)
    n = schema.write_universal_findings(rd, raw_findings, tool="gearbox", scope=None)
    if n == 2:
        r.ok(f"Gearbox JSONL → universal findings.json ({n} findings)")
    else:
        r.fail("Gearbox synthesis", f"got {n} findings")
    data = json.loads((rd / "findings.json").read_text())
    if data[0]["cvss_score"] == 5.0 and data[0]["classification"] == "Confirmed":
        r.ok("Gearbox v1.1 enrichment preserved (cvss_score, classification)")
    else:
        r.fail("Gearbox v1.1 mapping", f"cvss={data[0].get('cvss_score')}, class={data[0].get('classification')}")
    if "192.168.1.1" == data[0]["ip"]:
        r.ok("Gearbox affected_host → ip mapping")
    else:
        r.fail("Gearbox ip mapping", data[0].get("ip"))


# ───────────────────────────────────────────────────────────────────────────
# Layer I — v1.1 enrichment renderer (Node check; skipped if node absent)
# ───────────────────────────────────────────────────────────────────────────
def layer_i(r):
    r.section("Layer I — v1.1 enrichment JS renderer")
    js_path = Path("/opt/pr0t31n/shared/pr0t31n_v11_enrichment.js")
    if not js_path.exists():
        r.skip("v1.1 enrichment JS", f"{js_path} not deployed")
        return
    node = subprocess.run(["which", "node"], capture_output=True, text=True)
    if node.returncode != 0:
        r.skip("v1.1 enrichment JS render test", "node not installed")
        return
    # Run a small Node script that loads the helper and renders a sample finding
    test_js = """
const helperSrc = require('fs').readFileSync('%s', 'utf8');
const ctx = { window: {}, globalThis: {} };
new Function('window', helperSrc)(ctx.window);
const sample = {
  id: 'test', tool: 'fracture', title: 'XSS', risk: 'HIGH',
  cvss_score: 7.4, cvss_vector: 'CVSS:3.1/AV:N',
  cwe: ['CWE-79'], nist_800_53: ['SI-10'],
  mitre_attack: [{technique:'T1059.007'}], kev: false,
  owasp_api: 'API3:2023', remediation_effort: 'Moderate',
};
const html = ctx.window.renderV11Enrichment(sample);
if (!html || html.length < 100) { console.error('FAIL: short html: ' + html); process.exit(1); }
const need = ['CVSS', '7.4', 'CWE-79', 'SI-10', 'T1059.007', 'API3:2023', 'Moderate'];
const miss = need.filter(k => !html.includes(k));
if (miss.length) { console.error('FAIL: missing in render: ' + miss.join(', ')); process.exit(1); }
console.log('OK ' + html.length + ' chars rendered');
""" % str(js_path)
    p = subprocess.run(["node", "-e", test_js], capture_output=True, text=True, timeout=10)
    if p.returncode == 0:
        r.ok(f"v1.1 enrichment renderer  {p.stdout.strip()}")
    else:
        r.fail("v1.1 enrichment renderer", (p.stderr or p.stdout).strip()[:200])


# ───────────────────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layers", default="ABCDEFGHI",
                    help="Subset of layers to run (e.g. ABCDF). Default: all.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print(f"\n\033[1mpr0t31n integration test harness\033[0m")
    print(f"Layers: {args.layers}\n" + "=" * 60)

    r = Results(quiet=args.quiet)

    if "A" in args.layers: layer_a(r)
    base_dir = None
    if any(c in args.layers for c in "BCDGH"):
        base_dir = Path(tempfile.mkdtemp(prefix="pr0t31n_test_"))
    if "B" in args.layers or "C" in args.layers:
        layer_bc(r, base_dir)
    if "D" in args.layers and base_dir:
        layer_d(r, base_dir)
    if "E" in args.layers: layer_e(r)
    if "F" in args.layers: layer_f(r)
    if "G" in args.layers and base_dir:
        layer_g(r, base_dir)
    if "H" in args.layers and base_dir:
        layer_h(r, base_dir)
    if "I" in args.layers: layer_i(r)

    ok = r.summary()
    if base_dir:
        print(f"\nDummy data left at: {base_dir} (you may delete with: rm -rf {base_dir})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
