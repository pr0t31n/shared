"""
pr0t31n_topology.py — Shared Mermaid diagram generator for pr0t31n Flask apps.

Generalises Bastion's architecture-diagram pattern. Each manager calls the
appropriate generator with its findings + inventory data and gets back a
Mermaid string ready to render in the UI via mermaid.js.

Generators:
  network_topology(hosts, services, findings, scope_label) → Mermaid 'graph TD'
      Renders hosts grouped by subnet, with risk badges per host and port labels
  wireless_mesh(findings) → Mermaid 'graph LR'
      Renders APs (BSSIDs) with their SSIDs and any associated client findings
  api_service_map(endpoints, findings) → Mermaid 'graph LR'
      Renders APIs grouped by base_url with endpoint nodes per path

Mermaid syntax kept simple (graph + subgraph + node styling); compatible with
mermaid.js 9.x and 10.x. Style classes use the universal v1.1 risk palette.

stdlib only.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

__all__ = [
    "network_topology",
    "wireless_mesh",
    "api_service_map",
    "MERMAID_THEME",
]


# Universal risk palette — matches v1.1 enrichment renderer
MERMAID_THEME = """
classDef crit  fill:#a02020,stroke:#fff,color:#fff;
classDef high  fill:#c04030,stroke:#fff,color:#fff;
classDef med   fill:#806020,stroke:#fff,color:#fff;
classDef low   fill:#406020,stroke:#fff,color:#fff;
classDef info  fill:#444,stroke:#888,color:#ddd;
classDef host  fill:#222,stroke:#4a8,color:#eee;
classDef ap    fill:#2a3a3a,stroke:#4a8,color:#eee;
classDef api   fill:#2a2a3a,stroke:#4a8,color:#eee;
"""


_RISK_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_RISK_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
               "LOW": "low", "INFO": "info"}


def _safe_id(s, prefix="n"):
    """Mermaid-safe node id — alphanumeric + underscores, prefixed."""
    return prefix + "_" + re.sub(r'[^A-Za-z0-9_]', "_", str(s))[:40]


def _top_risk_for(findings_for_target):
    if not findings_for_target:
        return "INFO"
    return max(
        (f.get("risk", "INFO").upper() for f in findings_for_target),
        key=lambda r: _RISK_RANK.get(r, 0),
        default="INFO",
    )


def _subnet_of(ip_str, prefixlen=24):
    try:
        return str(ipaddress.IPv4Network(f"{ip_str}/{prefixlen}", strict=False))
    except (ValueError, ipaddress.AddressValueError):
        return "external"


# ─── Network topology (Vantage) ─────────────────────────────────────────────
def network_topology(hosts, services, findings,
                     scope_label="network", group_by_subnet=True):
    """Generate Mermaid graph TD from host/service inventory + findings."""
    services = services or []
    findings = findings or []
    hosts    = hosts or []
    # Group by IP for fast lookup
    by_ip_services = defaultdict(list)
    for s in services:
        if isinstance(s, dict) and s.get("ip"):
            by_ip_services[s["ip"]].append(s)
    by_ip_findings = defaultdict(list)
    for f in findings:
        if isinstance(f, dict) and f.get("ip"):
            by_ip_findings[f["ip"]].append(f)
    # Get unique IPs from hosts + services + findings
    all_ips = sorted({
        *(h.get("ip", "") for h in hosts if isinstance(h, dict)),
        *by_ip_services.keys(),
        *by_ip_findings.keys(),
    } - {""})

    lines = ["graph TD"]
    lines.append(MERMAID_THEME)
    lines.append(f'  ROOT["{scope_label}"]:::host')

    if group_by_subnet:
        ips_by_subnet = defaultdict(list)
        for ip in all_ips:
            ips_by_subnet[_subnet_of(ip)].append(ip)
        for subnet, ips in sorted(ips_by_subnet.items()):
            sub_id = _safe_id(subnet, "subnet")
            lines.append(f'  subgraph {sub_id}["{subnet}"]')
            for ip in sorted(ips):
                _emit_host_node(ip, by_ip_services, by_ip_findings, lines)
            lines.append("  end")
            lines.append(f'  ROOT --> {sub_id}')
    else:
        for ip in all_ips:
            _emit_host_node(ip, by_ip_services, by_ip_findings, lines)
            lines.append(f'  ROOT --> {_safe_id(ip, "h")}')

    return "\n".join(lines)


def _emit_host_node(ip, by_ip_services, by_ip_findings, lines):
    svcs = by_ip_services.get(ip, [])
    finds = by_ip_findings.get(ip, [])
    top = _top_risk_for(finds)
    cls = _RISK_CLASS.get(top, "host")
    n_finds = len(finds)
    ports = sorted({s.get("port") for s in svcs if s.get("port")})
    port_label = ",".join(str(p) for p in ports[:5])
    if len(ports) > 5:
        port_label += f",+{len(ports)-5}"
    label_parts = [ip]
    if port_label:
        label_parts.append(f":{port_label}")
    if n_finds:
        label_parts.append(f"[{n_finds} {top}]")
    label = " ".join(label_parts)
    node_id = _safe_id(ip, "h")
    lines.append(f'    {node_id}["{label}"]:::{cls}')


# ─── Wireless mesh (Spectre) ────────────────────────────────────────────────
def wireless_mesh(findings):
    """Mermaid graph LR for wireless findings — groups by SSID, shows BSSIDs."""
    findings = findings or []
    by_ssid = defaultdict(list)
    for f in findings:
        if not isinstance(f, dict):
            continue
        ssid = f.get("ssid") or "(hidden)"
        by_ssid[ssid].append(f)

    lines = ["graph LR"]
    lines.append(MERMAID_THEME)
    lines.append('  ROOT["wireless"]:::host')
    if not by_ssid:
        lines.append('  EMPTY["(no wireless findings)"]:::info')
        lines.append('  ROOT --> EMPTY')
        return "\n".join(lines)

    for ssid, items in sorted(by_ssid.items()):
        ssid_id = _safe_id(ssid, "ssid")
        ssid_top = _top_risk_for(items)
        ssid_cls = _RISK_CLASS.get(ssid_top, "ap")
        lines.append(f'  {ssid_id}["SSID: {ssid}"]:::{ssid_cls}')
        lines.append(f'  ROOT --> {ssid_id}')
        # BSSIDs under this SSID
        bssids = {}
        for f in items:
            b = f.get("bssid", "")
            if not b: continue
            bssids.setdefault(b, []).append(f)
        for bssid, bf in sorted(bssids.items()):
            bid = _safe_id(bssid, "bs")
            wd  = bf[0].get("wireless_data") or {}
            ch  = wd.get("channel", "?")
            enc = wd.get("encryption", "?")
            top = _top_risk_for(bf)
            cls = _RISK_CLASS.get(top, "ap")
            lines.append(f'    {bid}["{bssid}<br/>ch{ch} {enc}<br/>[{len(bf)} {top}]"]:::{cls}')
            lines.append(f'    {ssid_id} --> {bid}')
    return "\n".join(lines)


# ─── API service map (Crucible / Siphon) ────────────────────────────────────
def api_service_map(endpoints, findings):
    """Mermaid graph LR for API findings — groups endpoints by base path."""
    endpoints = endpoints or []
    findings  = findings or []
    # Group by base-path prefix (e.g. /v1, /api/v2)
    by_base = defaultdict(list)
    for f in findings:
        if not isinstance(f, dict):
            continue
        path = f.get("api_endpoint_path") or f.get("affected") or ""
        if not path.startswith("/"):
            continue
        parts = path.strip("/").split("/")
        base = "/" + (parts[0] if parts else "")
        by_base[base].append((path, f))
    lines = ["graph LR"]
    lines.append(MERMAID_THEME)
    lines.append('  ROOT["API"]:::api')
    if not by_base:
        lines.append('  EMPTY["(no API findings with api_endpoint_path)"]:::info')
        lines.append('  ROOT --> EMPTY')
        return "\n".join(lines)
    for base, items in sorted(by_base.items()):
        bid = _safe_id(base, "base")
        top = _top_risk_for(f for _, f in items)
        cls = _RISK_CLASS.get(top, "api")
        lines.append(f'  {bid}["{base}<br/>({len(items)} findings, top {top})"]:::{cls}')
        lines.append(f'  ROOT --> {bid}')
        # Per-path nodes (limit to 12 to avoid huge diagrams)
        path_groups = defaultdict(list)
        for path, f in items:
            path_groups[path].append(f)
        for path, pfs in sorted(path_groups.items())[:12]:
            pid = _safe_id(path, "p")
            ptop = _top_risk_for(pfs)
            pcls = _RISK_CLASS.get(ptop, "api")
            method = pfs[0].get("api_method") or ""
            label = f"{method} {path}" if method else path
            rogue = "🚨 " if any(f.get("is_rogue_endpoint") for f in pfs) else ""
            lines.append(f'    {pid}["{rogue}{label}<br/>[{len(pfs)} {ptop}]"]:::{pcls}')
            lines.append(f'    {bid} --> {pid}')
    return "\n".join(lines)


# ─── Self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.5"}, {"ip": "10.0.0.10"}]
    services = [
        {"ip": "10.0.0.1", "port": 443}, {"ip": "10.0.0.1", "port": 22},
        {"ip": "10.0.0.5", "port": 8080}, {"ip": "10.0.0.10", "port": 3306},
    ]
    findings = [
        {"ip": "10.0.0.1", "port": 443, "risk": "HIGH"},
        {"ip": "10.0.0.5", "port": 8080, "risk": "CRITICAL"},
        {"ip": "10.0.0.10", "port": 3306, "risk": "LOW"},
    ]
    nt = network_topology(hosts, services, findings, scope_label="ext")
    assert "graph TD" in nt and "10.0.0.1" in nt and "classDef crit" in nt
    print("network_topology OK")

    wf = [
        {"ssid": "Corp", "bssid": "AA:BB:CC:00:00:01",
         "wireless_data": {"channel": 6, "encryption": "WPA3"}, "risk": "LOW"},
        {"ssid": "Guest", "bssid": "AA:BB:CC:00:00:02",
         "wireless_data": {"channel": 11, "encryption": "WPA2"}, "risk": "MEDIUM"},
        {"ssid": "Open-Wifi", "bssid": "AA:BB:CC:00:00:03",
         "wireless_data": {"channel": 1, "encryption": "Open"}, "risk": "HIGH"},
    ]
    wm = wireless_mesh(wf)
    assert "graph LR" in wm and "WPA3" in wm and "Open" in wm
    print("wireless_mesh OK")

    af = [
        {"api_endpoint_path": "/v1/users",  "api_method": "GET",  "risk": "HIGH"},
        {"api_endpoint_path": "/v1/users",  "api_method": "POST", "risk": "MEDIUM"},
        {"api_endpoint_path": "/v1/admin",  "api_method": "POST", "risk": "CRITICAL",
         "is_rogue_endpoint": True},
        {"api_endpoint_path": "/api/v2/x",  "api_method": "GET",  "risk": "LOW"},
    ]
    am = api_service_map([], af)
    assert "graph LR" in am and "/v1" in am and "🚨" in am
    print("api_service_map OK")

    print("pr0t31n_topology: self-test PASS")
