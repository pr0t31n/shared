"""pr0t31n_timeouts.py — canonical subprocess timeouts.

EXTREMELY GENEROUS values based on standard and worst-case runtimes for each
tool/command. Sourced from vendor man pages, real-world engagement telemetry,
and Project Discovery / Wireshark / Aircrack-ng / Cisco / Microsoft published
benchmarks.

Design principles:
  * Never time out a legitimate scan. The cost of false-completion is much
    higher than the cost of an occasional long wait.
  * Document the rationale per entry so future tuning is informed.
  * Provide context-multipliers (slow_network, large_target_set, deep_scan).
  * Every public helper returns int seconds suitable for subprocess.run(timeout=).
"""
from __future__ import annotations

import os
from typing import Optional

VERSION = "1.0.0"


# ── Base timeouts (seconds) ─────────────────────────────────────────────
# Comments explain the upper-bound scenario. Real runs are usually < 25% of these.

_BASE = {
    # ── Network recon / discovery ──
    "nmap":              4 * 3600,   # /16 + -sC -sV + nse can run 2-4 hrs
    "nmap_quick":        15 * 60,    # -T4 -F single host
    "nmap_udp":          6 * 3600,   # -sU is the single slowest nmap mode
    "masscan":           2 * 3600,   # whole IPv4 at 10kpps
    "amass":             6 * 3600,   # passive+active enumeration of a TLD
    "subfinder":         30 * 60,
    "dnsx":              15 * 60,
    "dig":               60,
    "host":              60,
    "whois":             120,
    "rustscan":          30 * 60,
    "naabu":             45 * 60,

    # ── Web ──
    "nuclei":            6 * 3600,   # full template set vs large surface
    "nuclei_quick":      1800,
    "nikto":             2 * 3600,
    "feroxbuster":       3 * 3600,
    "gobuster":          3 * 3600,
    "ffuf":              3 * 3600,
    "dirsearch":         3 * 3600,
    "wpscan":            2 * 3600,
    "whatweb":           300,
    "shcheck":           120,
    "webanalyze":        600,
    "gowitness":         1800,
    "wayback":           1800,
    "katana":            2 * 3600,
    "hakrawler":         1800,

    # ── TLS / SSH ──
    "sslscan":           600,
    "testssl":           2 * 3600,   # --full deep TLS audit
    "ssh-audit":         300,
    "ssh2-enum-algos":   180,
    "sslyze":            1800,

    # ── Database clients ──
    "mysql_client_connect":  60,    # connect+probe single host
    "psql_connect":          60,
    "mssql_connect":         60,
    "oracle_connect":        120,   # Oracle SCAN listener can be slow
    "mongo_connect":         45,
    "redis_connect":         30,
    "memcached_connect":     30,
    "es_query":              60,
    "cassandra_connect":     90,
    "couchdb_query":         60,
    "influx_query":          60,
    "neo4j_query":           90,

    # ── Wireless ──
    "airodump":          24 * 3600,  # passive capture — runs as long as ops want
    "aircrack":          24 * 3600,  # offline crack against multi-million dict
    "hashcat":           48 * 3600,
    "hcxdumptool":       24 * 3600,
    "wifite2":           24 * 3600,
    "reaver":            12 * 3600,  # WPS PIN brute can take hours
    "bully":             12 * 3600,
    "eaphammer":         12 * 3600,
    "hostapd":           24 * 3600,  # evil-twin runs duration of engagement
    "dnsmasq":           24 * 3600,
    "aireplay":          1800,
    "kismet":            24 * 3600,
    "bettercap":         12 * 3600,

    # ── Bluetooth ──
    "ubertooth_scan":    1800,
    "btscanner":         1800,
    "hcitool":           600,
    "sdptool":           300,
    "gatttool":          600,
    "crackle":           4 * 3600,
    "gattacker":         3600,
    "bluez":             1800,

    # ── ZigBee / 802.15.4 ──
    "killerbee":         6 * 3600,
    "zbstumbler":        3 * 3600,
    "zbdump":            6 * 3600,
    "zbdsniff":          1800,
    "zbreplay":          1800,

    # ── UWB ──
    "uwb_capture":       2 * 3600,

    # ── pcap ──
    "tshark":            6 * 3600,   # multi-GB pcap field extraction
    "editcap":           1800,       # format normalisation
    "mergecap":          1800,
    "tcpdump":           24 * 3600,  # live capture

    # ── Firmware / hardware ──
    "binwalk":           2 * 3600,
    "openocd":           3 * 3600,   # JTAG halt + read
    "flashrom":          4 * 3600,   # 16+ MiB SPI flash dump at 1MHz
    "proxmark":          1800,

    # ── Cloud control plane ──
    "aws":               1800,       # `aws ec2 describe-instances --region all` slow
    "az":                1800,
    "gcloud":            1800,
    "oci":               1800,
    "boto3_op":          600,
    "kubectl":           600,
    "kube-bench":        1800,
    "kube-hunter":       1800,
    "trivy":             3600,
    "kubescape":         1800,

    # ── AD / IdP ──
    "impacket_secretsdump": 3600,
    "kerbrute":          3600,
    "bloodhound_collect": 4 * 3600,  # SharpHound full collection
    "ldapsearch":        600,
    "rpcclient":         300,
    "smbclient":         600,
    "smbmap":            1800,
    "crackmapexec":      3600,
    "nxc":               3600,

    # ── Mobile ──
    "apktool":           1800,
    "jadx":              1800,
    "mobsf_scan":        2 * 3600,
    "frida_attach":      3600,       # interactive sessions can run hours
    "objection":         3600,

    # ── Misc third-party ──
    "searchsploit":      300,
    "sqlmap":            6 * 3600,
    "dalfox":            3600,
    "jwt_tool":          300,
    "responder":         24 * 3600,
    "trufflehog":        2 * 3600,
    "gitleaks":          1800,
    "cloud_enum":        2 * 3600,

    # ── Catch-all ──
    "subprocess_default":   1800,    # 30 min — generic Popen we have no data for
    "subprocess_blocking":  60,      # any blocking-API call that must not stall
}


# ── Multipliers ─────────────────────────────────────────────────────────
# Apply via timeout_for(tool, large_target_set=True, deep_scan=True).
# Each multiplier independently doubles the base. They compose.

_LARGE_TARGET_SET   = 2.0   # >/24 of hosts
_VERY_LARGE_TARGET  = 4.0   # >/16
_DEEP_SCAN          = 2.0   # -A / --aggressive / -T2-T3 / --full
_SLOW_NETWORK       = 1.5   # high-latency or rate-limited link
_OPERATOR_EXTENDED  = 3.0   # operator explicitly OK'd 'this might run all day'


def timeout_for(tool_or_key: str,
                *,
                large_target_set: bool = False,
                very_large_target: bool = False,
                deep_scan: bool = False,
                slow_network: bool = False,
                operator_extended: bool = False,
                override: Optional[int] = None) -> int:
    """Return a generous subprocess timeout in seconds.

    `tool_or_key` is the canonical key from _BASE. Unknown keys fall back
    to subprocess_default.

    All multipliers compose. The result is clamped to a 7-day ceiling so
    even the most aggressive combination is bounded (a runaway tool past
    that point is a bug, not a long run).
    """
    if override is not None and override > 0:
        return int(override)
    base = _BASE.get(tool_or_key, _BASE["subprocess_default"])
    mult = 1.0
    if very_large_target:  mult *= _VERY_LARGE_TARGET
    elif large_target_set: mult *= _LARGE_TARGET_SET
    if deep_scan:          mult *= _DEEP_SCAN
    if slow_network:       mult *= _SLOW_NETWORK
    if operator_extended:  mult *= _OPERATOR_EXTENDED
    return min(int(base * mult), 7 * 24 * 3600)


def env_override(tool_or_key: str) -> Optional[int]:
    """Allow per-tool env override (`PR0T31N_TIMEOUT_NMAP=14400`)."""
    key = f"PR0T31N_TIMEOUT_{tool_or_key.upper().replace('-', '_').replace(' ', '_')}"
    raw = os.environ.get(key)
    if not raw: return None
    try: return int(raw)
    except ValueError: return None


def resolve(tool_or_key: str, **kwargs) -> int:
    """One-call helper: env override > kwargs override > computed."""
    o = env_override(tool_or_key)
    if o: return o
    return timeout_for(tool_or_key, **kwargs)
