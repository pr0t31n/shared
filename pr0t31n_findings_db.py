#!/usr/bin/env python3
"""pr0t31n_findings_db — SQLite-backed findings store for the pr0t31n toolkit.

Replaces flat JSON file storage with an indexed, paginated, normalised
relational database.  Designed for engagement-level data aggregation
across all pr0t31n tools.

Usage
-----
    from pr0t31n_findings_db import FindingsDB
    db = FindingsDB("/path/to/project/findings.db")
    db.insert_finding({...})
    page = db.query_findings(risk=["CRITICAL","HIGH"], page=1, per_page=100)

The database is a single SQLite file (WAL mode) that lives alongside the
engagement's other output.  It is portable — copy it between machines and
the receiving Crucible picks it up with zero reprocessing.

Tables are fully normalised: lookup tables for risks, tools, scopes,
categories, compliance frameworks, OWASP, CWE, CVE, MITRE ATT&CK;
junction tables for every many-to-many relationship; denormalised
indexes on hot query paths.
"""

import hashlib
import json
import logging
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

log = logging.getLogger("pr0t31n.findings_db")

SCHEMA_VERSION = "1.0"
DB_FILENAME = "findings.db"

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
RISK_NAMES = {v: k for k, v in RISK_ORDER.items()}

_TOOL_ALIAS = {
    "ss3": "scattershot3", "scattershot": "scattershot3",
    "fr": "fracture", "si": "siphon",
    "ae": "aether", "ae_b": "aether_b", "ae_z": "aether_z", "ae_u": "aether_u",
    "gb": "gearbox",
}

# ═══════════════════════════════════════════════════════════════
#  Schema DDL
# ═══════════════════════════════════════════════════════════════

_SCHEMA_DDL = """
-- ── Meta ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- ── Reference / Lookup ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS risks (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    sort_order  INTEGER NOT NULL,
    color       TEXT,
    bg_color    TEXT,
    border_color TEXT
);

CREATE TABLE IF NOT EXISTS tools (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    domain  TEXT,
    version TEXT
);

CREATE TABLE IF NOT EXISTS scopes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS scope_cidrs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    cidr     TEXT NOT NULL,
    UNIQUE(scope_id, cidr)
);

CREATE TABLE IF NOT EXISTS scope_domains (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    domain   TEXT NOT NULL,
    UNIQUE(scope_id, domain)
);

CREATE TABLE IF NOT EXISTS scope_urls (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    url      TEXT NOT NULL,
    UNIQUE(scope_id, url)
);

CREATE TABLE IF NOT EXISTS tool_scopes (
    tool_id  TEXT NOT NULL REFERENCES tools(id),
    scope_id INTEGER NOT NULL REFERENCES scopes(id),
    PRIMARY KEY (tool_id, scope_id)
);

CREATE TABLE IF NOT EXISTS exclusions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    value    TEXT NOT NULL UNIQUE,
    type     TEXT NOT NULL CHECK(type IN ('ip','cidr','hostname')),
    reason   TEXT,
    added_at TEXT DEFAULT (datetime('now'))
);

-- ── Categories ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    parent_id   INTEGER REFERENCES categories(id)
);
CREATE INDEX IF NOT EXISTS idx_categories_parent ON categories(parent_id);

-- ── OWASP ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS owasp_categories (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL CHECK(type IN ('web','api')),
    name        TEXT NOT NULL,
    description TEXT,
    url         TEXT
);

-- ── CWE / CVE ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cwes (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    id          TEXT PRIMARY KEY,
    description TEXT,
    cvss_score  REAL,
    cvss_vector TEXT,
    published   TEXT,
    kev         INTEGER DEFAULT 0
);

-- ── MITRE ATT&CK ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mitre_tactics (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
    technique_id TEXT NOT NULL REFERENCES mitre_techniques(id),
    tactic_id    TEXT NOT NULL REFERENCES mitre_tactics(id),
    PRIMARY KEY (technique_id, tactic_id)
);

-- ── Compliance Frameworks ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id INTEGER NOT NULL REFERENCES compliance_frameworks(id),
    control_id   TEXT NOT NULL,
    title        TEXT,
    description  TEXT,
    UNIQUE(framework_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls(framework_id);

-- ── Exploit / Validation Lookup ────────────────────────────────

CREATE TABLE IF NOT EXISTS searchsploit_terms (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS metasploit_modules (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT UNIQUE NOT NULL,
    color TEXT
);

-- ── Catalogue ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS catalogue_entries (
    id                    TEXT PRIMARY KEY,
    tool_id               TEXT REFERENCES tools(id),
    title                 TEXT NOT NULL,
    risk_id               INTEGER REFERENCES risks(id),
    description           TEXT,
    impact                TEXT,
    remediation_brief     TEXT,
    remediation_component TEXT,
    remediation_category  TEXT,
    remediation_effort    TEXT,
    cvss_v3_base          REAL,
    cvss_vector           TEXT,
    kev                   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS catalogue_aliases (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    alias        TEXT NOT NULL,
    PRIMARY KEY (catalogue_id, alias)
);
CREATE INDEX IF NOT EXISTS idx_cat_alias_lookup ON catalogue_aliases(alias);

CREATE TABLE IF NOT EXISTS catalogue_source_tools (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    tool_id      TEXT NOT NULL REFERENCES tools(id),
    PRIMARY KEY (catalogue_id, tool_id)
);

CREATE TABLE IF NOT EXISTS catalogue_cwe (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    cwe_id       TEXT NOT NULL REFERENCES cwes(id),
    PRIMARY KEY (catalogue_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS catalogue_cve_examples (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL,
    PRIMARY KEY (catalogue_id, cve_id)
);

CREATE TABLE IF NOT EXISTS catalogue_owasp (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    owasp_id     TEXT NOT NULL REFERENCES owasp_categories(id),
    PRIMARY KEY (catalogue_id, owasp_id)
);

CREATE TABLE IF NOT EXISTS catalogue_compliance (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    control_id   INTEGER NOT NULL REFERENCES compliance_controls(id),
    PRIMARY KEY (catalogue_id, control_id)
);

CREATE TABLE IF NOT EXISTS catalogue_mitre (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES mitre_techniques(id),
    PRIMARY KEY (catalogue_id, technique_id)
);

CREATE TABLE IF NOT EXISTS catalogue_searchsploit (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    term_id      INTEGER NOT NULL REFERENCES searchsploit_terms(id),
    PRIMARY KEY (catalogue_id, term_id)
);

CREATE TABLE IF NOT EXISTS catalogue_metasploit (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    module_id    INTEGER NOT NULL REFERENCES metasploit_modules(id),
    PRIMARY KEY (catalogue_id, module_id)
);

CREATE TABLE IF NOT EXISTS catalogue_nessus_plugins (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    plugin_id    INTEGER NOT NULL,
    PRIMARY KEY (catalogue_id, plugin_id)
);

CREATE TABLE IF NOT EXISTS catalogue_qualys_qids (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    qid          INTEGER NOT NULL,
    PRIMARY KEY (catalogue_id, qid)
);

CREATE TABLE IF NOT EXISTS catalogue_validation_tools (
    catalogue_id TEXT NOT NULL REFERENCES catalogue_entries(id) ON DELETE CASCADE,
    tool_name    TEXT NOT NULL,
    PRIMARY KEY (catalogue_id, tool_name)
);

-- ── Target / Asset Tables ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS hosts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ip               TEXT UNIQUE NOT NULL,
    mac              TEXT,
    os_family        TEXT,
    os_name          TEXT,
    os_accuracy      INTEGER,
    scope_id         INTEGER REFERENCES scopes(id),
    first_seen       TEXT,
    last_seen        TEXT,
    is_alive         INTEGER DEFAULT 1,
    discovery_method TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_scope ON hosts(scope_id);

CREATE TABLE IF NOT EXISTS hostnames (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS host_hostnames (
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    hostname_id INTEGER NOT NULL REFERENCES hostnames(id),
    source      TEXT,
    first_seen  TEXT,
    PRIMARY KEY (host_id, hostname_id)
);

CREATE TABLE IF NOT EXISTS ports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state    TEXT DEFAULT 'open',
    UNIQUE(host_id, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port);

CREATE TABLE IF NOT EXISTS services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id         INTEGER UNIQUE NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    name            TEXT,
    product         TEXT,
    version         TEXT,
    extra_info      TEXT,
    cpe             TEXT,
    banner          TEXT,
    tunnel          TEXT,
    discovery_tool  TEXT
);

CREATE TABLE IF NOT EXISTS software (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL,
    vendor  TEXT,
    cpe     TEXT,
    UNIQUE(product, vendor)
);

CREATE TABLE IF NOT EXISTS host_software (
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    software_id INTEGER NOT NULL REFERENCES software(id),
    version     TEXT,
    detected_by TEXT,
    first_seen  TEXT,
    PRIMARY KEY (host_id, software_id, version)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname   TEXT NOT NULL,
    rtype      TEXT NOT NULL,
    value      TEXT NOT NULL,
    ttl        INTEGER,
    source     TEXT,
    queried_at TEXT,
    UNIQUE(hostname, rtype, value)
);
CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_records(hostname);
CREATE INDEX IF NOT EXISTS idx_dns_value ON dns_records(value);

CREATE TABLE IF NOT EXISTS certificates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id        INTEGER REFERENCES ports(id) ON DELETE CASCADE,
    serial         TEXT,
    issuer         TEXT,
    subject        TEXT,
    not_before     TEXT,
    not_after      TEXT,
    sans           TEXT,
    sig_algorithm  TEXT,
    key_type       TEXT,
    key_bits       INTEGER,
    chain_depth    INTEGER,
    is_self_signed INTEGER DEFAULT 0,
    is_expired     INTEGER DEFAULT 0,
    raw_pem        TEXT
);
CREATE INDEX IF NOT EXISTS idx_certs_port ON certificates(port_id);

CREATE TABLE IF NOT EXISTS endpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER REFERENCES hosts(id),
    port_id       INTEGER REFERENCES ports(id),
    path          TEXT NOT NULL,
    method        TEXT,
    from_spec     INTEGER DEFAULT 0,
    is_rogue      INTEGER DEFAULT 0,
    auth_required INTEGER,
    content_type  TEXT,
    parameters    TEXT,
    discovered_by TEXT,
    first_seen    TEXT,
    UNIQUE(host_id, port_id, path, method)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_path ON endpoints(path);

CREATE TABLE IF NOT EXISTS wireless_networks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid       TEXT,
    bssid      TEXT UNIQUE NOT NULL,
    channel    INTEGER,
    frequency  INTEGER,
    encryption TEXT,
    cipher     TEXT,
    auth       TEXT,
    signal_dbm INTEGER,
    first_seen TEXT,
    last_seen  TEXT,
    scope_id   INTEGER REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER REFERENCES hosts(id),
    port_id         INTEGER REFERENCES ports(id),
    service         TEXT,
    username        TEXT,
    credential_type TEXT,
    source          TEXT,
    discovered_at   TEXT,
    hash_value      TEXT,
    hash_type       TEXT
);
CREATE INDEX IF NOT EXISTS idx_creds_host ON credentials(host_id);

CREATE TABLE IF NOT EXISTS host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag_id  INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (host_id, tag_id)
);

-- ── Core Findings ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS findings (
    id                    TEXT PRIMARY KEY,
    tool_id               TEXT NOT NULL REFERENCES tools(id),
    scope_id              INTEGER REFERENCES scopes(id),
    category_id           INTEGER REFERENCES categories(id),
    catalogue_id          TEXT REFERENCES catalogue_entries(id),
    risk_id               INTEGER NOT NULL REFERENCES risks(id),

    title                 TEXT NOT NULL,
    normalized_title      TEXT NOT NULL,
    dedup_key             TEXT NOT NULL UNIQUE,

    phase                 TEXT,
    description           TEXT NOT NULL DEFAULT '',
    impact                TEXT,
    remediation           TEXT NOT NULL DEFAULT '',
    output                TEXT,
    command               TEXT,
    sources               TEXT,

    cvss_score            REAL,
    cvss_vector           TEXT,
    confidence            TEXT CHECK(confidence IN ('Certain','Firm','Tentative',NULL)),

    nessus_plugin_id      INTEGER,
    nessus_plugin_name    TEXT,
    qualys_qid            INTEGER,
    plugin_output         TEXT,

    exploitdb             INTEGER DEFAULT 0,
    metasploit            INTEGER DEFAULT 0,
    kev                   INTEGER DEFAULT 0,
    exploit_details       TEXT,

    remediation_effort    TEXT,
    remediation_component TEXT,
    remediation_category  TEXT,

    is_false_positive     INTEGER DEFAULT 0,
    fp_marked_at          TEXT,
    fp_reason             TEXT,
    original_risk_id      INTEGER REFERENCES risks(id),
    risk_overridden       INTEGER DEFAULT 0,
    risk_override_reason  TEXT,
    is_oos                INTEGER DEFAULT 0,
    oos_reason            TEXT,
    accepted              INTEGER DEFAULT 0,
    imported              INTEGER DEFAULT 0,

    datetime              TEXT NOT NULL,
    _original_title       TEXT,
    merged_count          INTEGER DEFAULT 1,

    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_risk       ON findings(risk_id);
CREATE INDEX IF NOT EXISTS idx_findings_tool       ON findings(tool_id);
CREATE INDEX IF NOT EXISTS idx_findings_scope      ON findings(scope_id);
CREATE INDEX IF NOT EXISTS idx_findings_category   ON findings(category_id);
CREATE INDEX IF NOT EXISTS idx_findings_catalogue  ON findings(catalogue_id);
CREATE INDEX IF NOT EXISTS idx_findings_title_norm ON findings(normalized_title);
CREATE INDEX IF NOT EXISTS idx_findings_fp         ON findings(is_false_positive);
CREATE INDEX IF NOT EXISTS idx_findings_datetime   ON findings(datetime);
CREATE INDEX IF NOT EXISTS idx_findings_cvss       ON findings(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_oos        ON findings(is_oos);

-- ── Finding Locations (many-to-many: finding ↔ affected) ──────

CREATE TABLE IF NOT EXISTS finding_locations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    host_id     INTEGER REFERENCES hosts(id),
    port_id     INTEGER REFERENCES ports(id),
    ip          TEXT,
    port        INTEGER DEFAULT 0,
    hostname    TEXT,
    service     TEXT,
    url         TEXT,
    protocol    TEXT DEFAULT 'tcp',
    output      TEXT,
    output_file TEXT,
    UNIQUE(finding_id, ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_floc_finding  ON finding_locations(finding_id);
CREATE INDEX IF NOT EXISTS idx_floc_ip       ON finding_locations(ip);
CREATE INDEX IF NOT EXISTS idx_floc_port     ON finding_locations(ip, port);
CREATE INDEX IF NOT EXISTS idx_floc_host     ON finding_locations(host_id);
CREATE INDEX IF NOT EXISTS idx_floc_hostname ON finding_locations(hostname);

-- ── Finding Junction Tables ────────────────────────────────────

CREATE TABLE IF NOT EXISTS finding_cwe (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    cwe_id     TEXT NOT NULL REFERENCES cwes(id),
    PRIMARY KEY (finding_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS finding_cve (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    cve_id     TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id)
);

CREATE TABLE IF NOT EXISTS finding_owasp (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    owasp_id   TEXT NOT NULL REFERENCES owasp_categories(id),
    PRIMARY KEY (finding_id, owasp_id)
);

CREATE TABLE IF NOT EXISTS finding_mitre (
    finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES mitre_techniques(id),
    PRIMARY KEY (finding_id, technique_id)
);

CREATE TABLE IF NOT EXISTS finding_compliance (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES compliance_controls(id),
    PRIMARY KEY (finding_id, control_id)
);

CREATE TABLE IF NOT EXISTS finding_searchsploit (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    term_id    INTEGER NOT NULL REFERENCES searchsploit_terms(id),
    PRIMARY KEY (finding_id, term_id)
);

CREATE TABLE IF NOT EXISTS finding_metasploit (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    module_id  INTEGER NOT NULL REFERENCES metasploit_modules(id),
    PRIMARY KEY (finding_id, module_id)
);

CREATE TABLE IF NOT EXISTS finding_tags (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (finding_id, tag_id)
);

CREATE TABLE IF NOT EXISTS finding_source_tools (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tool_id    TEXT NOT NULL REFERENCES tools(id),
    PRIMARY KEY (finding_id, tool_id)
);

-- ── Evidence ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    location_id INTEGER REFERENCES finding_locations(id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    file_type   TEXT,
    description TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- ── Notes ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS finding_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    note       TEXT NOT NULL,
    author     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notes_finding ON finding_notes(finding_id);

-- ── Risk Override Audit Trail ──────────────────────────────────

CREATE TABLE IF NOT EXISTS risk_override_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings(id),
    old_risk_id INTEGER NOT NULL REFERENCES risks(id),
    new_risk_id INTEGER NOT NULL REFERENCES risks(id),
    reason      TEXT,
    author      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Action Items ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS action_items (
    id                TEXT PRIMARY KEY,
    finding_id        TEXT REFERENCES findings(id),
    recommended_tool  TEXT,
    target            TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    command           TEXT,
    status            TEXT DEFAULT 'pending',
    priority          INTEGER DEFAULT 0,
    started_at        TEXT,
    ended_at          TEXT,
    pid               INTEGER,
    returncode        INTEGER,
    error             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON action_items(status);
CREATE INDEX IF NOT EXISTS idx_actions_tool   ON action_items(recommended_tool);
CREATE INDEX IF NOT EXISTS idx_actions_target ON action_items(normalized_target);

-- ── Tool Execution ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tool_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id      TEXT NOT NULL REFERENCES tools(id),
    scope_id     INTEGER REFERENCES scopes(id),
    status       TEXT DEFAULT 'idle',
    pid          INTEGER,
    returncode   INTEGER,
    command      TEXT,
    tool_version TEXT,
    started_at   TEXT,
    ended_at     TEXT,
    settings     TEXT,
    output_dir   TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_tool ON tool_runs(tool_id);

CREATE TABLE IF NOT EXISTS tool_console (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    level     TEXT,
    message   TEXT NOT NULL,
    source    TEXT
);
CREATE INDEX IF NOT EXISTS idx_console_run ON tool_console(run_id, timestamp);

CREATE TABLE IF NOT EXISTS scan_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level     TEXT NOT NULL,
    tool_id   TEXT REFERENCES tools(id),
    message   TEXT NOT NULL,
    details   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time  ON scan_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_level ON scan_events(level);

-- ── Intelligence (materialised) ────────────────────────────────

CREATE TABLE IF NOT EXISTS host_risk_profiles (
    host_id        INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count     INTEGER DEFAULT 0,
    medium_count   INTEGER DEFAULT 0,
    low_count      INTEGER DEFAULT 0,
    info_count     INTEGER DEFAULT 0,
    max_cvss       REAL,
    avg_cvss       REAL,
    risk_score     REAL,
    tools_hit      TEXT,
    computed_at    TEXT
);

CREATE TABLE IF NOT EXISTS service_risk_profiles (
    port_id        INTEGER PRIMARY KEY REFERENCES ports(id) ON DELETE CASCADE,
    finding_count  INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count     INTEGER DEFAULT 0,
    max_cvss       REAL,
    computed_at    TEXT
);

CREATE TABLE IF NOT EXISTS remediation_groups (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT NOT NULL,
    description    TEXT,
    effort         TEXT,
    component      TEXT,
    finding_count  INTEGER DEFAULT 0,
    host_count     INTEGER DEFAULT 0,
    risk_reduction REAL,
    priority       INTEGER
);

CREATE TABLE IF NOT EXISTS remediation_group_findings (
    group_id   INTEGER NOT NULL REFERENCES remediation_groups(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, finding_id)
);

CREATE TABLE IF NOT EXISTS compliance_gaps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id  INTEGER NOT NULL REFERENCES compliance_frameworks(id),
    control_id    INTEGER NOT NULL REFERENCES compliance_controls(id),
    status        TEXT DEFAULT 'gap',
    finding_count INTEGER DEFAULT 0,
    max_risk_id   INTEGER REFERENCES risks(id),
    computed_at   TEXT,
    UNIQUE(framework_id, control_id)
);

CREATE TABLE IF NOT EXISTS trend_snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_at    TEXT NOT NULL,
    total_findings INTEGER,
    critical_count INTEGER,
    high_count     INTEGER,
    medium_count   INTEGER,
    low_count      INTEGER,
    info_count     INTEGER,
    total_hosts    INTEGER,
    total_services INTEGER,
    fp_count       INTEGER,
    risk_score     REAL
);

CREATE TABLE IF NOT EXISTS attack_surface (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port_id       INTEGER REFERENCES ports(id) ON DELETE CASCADE,
    exposure      TEXT,
    tools_count   INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    has_critical  INTEGER DEFAULT 0,
    has_high      INTEGER DEFAULT 0,
    computed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_atksurf_host ON attack_surface(host_id);

CREATE TABLE IF NOT EXISTS correlations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id          INTEGER NOT NULL REFERENCES hosts(id),
    port_id          INTEGER REFERENCES ports(id),
    finding_a_id     TEXT NOT NULL REFERENCES findings(id),
    finding_b_id     TEXT NOT NULL REFERENCES findings(id),
    correlation_type TEXT,
    confidence       REAL,
    description      TEXT,
    computed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_corr_host ON correlations(host_id);

-- ── OSINT Intelligence ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS osint_emails (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    name       TEXT,
    source     TEXT,
    breached   INTEGER DEFAULT 0,
    first_seen TEXT
);

CREATE TABLE IF NOT EXISTS osint_breaches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id      INTEGER REFERENCES osint_emails(id) ON DELETE CASCADE,
    breach_name   TEXT NOT NULL,
    breach_date   TEXT,
    data_classes  TEXT,
    source        TEXT
);
CREATE INDEX IF NOT EXISTS idx_breaches_email ON osint_breaches(email_id);

CREATE TABLE IF NOT EXISTS osint_people (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    title      TEXT,
    company    TEXT,
    email      TEXT,
    phone      TEXT,
    source     TEXT,
    first_seen TEXT
);

CREATE TABLE IF NOT EXISTS osint_subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname_id INTEGER REFERENCES hostnames(id),
    subdomain   TEXT UNIQUE NOT NULL,
    source      TEXT,
    first_seen  TEXT,
    is_alive    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_subdomains_alive ON osint_subdomains(is_alive);

-- ── Full-Text Search ───────────────────────────────────────────

CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, description, remediation, affected_text, output,
    content='findings_fts_content',
    content_rowid='rowid'
);

CREATE TABLE IF NOT EXISTS findings_fts_content (
    rowid         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL,
    title         TEXT,
    description   TEXT,
    remediation   TEXT,
    affected_text TEXT,
    output        TEXT
);
CREATE INDEX IF NOT EXISTS idx_fts_content_fid ON findings_fts_content(finding_id);
"""

# ═══════════════════════════════════════════════════════════════
#  Seed Data
# ═══════════════════════════════════════════════════════════════

_SEED_RISKS = [
    (1, "CRITICAL", 0, "#FF00FF", "rgba(255,0,255,.15)", "rgba(255,0,255,.35)"),
    (2, "HIGH",     1, "#E7716F", "rgba(231,113,111,.15)", "rgba(231,113,111,.35)"),
    (3, "MEDIUM",   2, "#FFC000", "rgba(255,192,0,.15)", "rgba(255,192,0,.35)"),
    (4, "LOW",      3, "#92D050", "rgba(146,208,80,.15)", "rgba(146,208,80,.35)"),
    (5, "INFO",     4, "#BDD7EC", "rgba(189,215,236,.12)", "rgba(189,215,236,.25)"),
]

_SEED_FRAMEWORKS = [
    ("nist_800_53",  "NIST SP 800-53"),
    ("nist_800_171", "NIST SP 800-171"),
    ("nist_csf2",    "NIST CSF 2.0"),
    ("pci_dss_4",    "PCI DSS v4.0"),
    ("iso_27001",    "ISO/IEC 27001"),
    ("iso_27002",    "ISO/IEC 27002"),
    ("soc2",         "SOC 2"),
    ("hitrust",      "HITRUST CSF"),
    ("gdpr",         "GDPR"),
]

_SEED_TOOLS = [
    ("ss3",       "Scattershot3", "recon"),
    ("fracture",  "Fracture",     "web"),
    ("siphon",    "Siphon",       "api"),
    ("osift",     "OSift",        "osint"),
    ("auger",     "Auger",        "database"),
    ("dredge",    "Dredge",       "config"),
    ("bastion",   "Bastion",      "config"),
    ("isotope",   "Isotope",      "firmware"),
    ("forge",     "Forge",        "cloud"),
    ("quill",     "Quill",        "mobile"),
    ("phalanx",   "Phalanx",      "firewall"),
    ("trawler",   "Trawler",      "network"),
    ("aether",    "Aether",       "wireless"),
    ("aether_b",  "Aether-B",     "wireless"),
    ("aether_z",  "Aether-Z",     "wireless"),
    ("aether_u",  "Aether-U",     "wireless"),
    ("gearbox",   "Gearbox",      "iot"),
    ("pain",      "pAIn",         "ai"),
    ("anvil",     "Anvil",        "compliance"),
    ("vault",     "Vault",        "secrets"),
    ("nessus",    "Nessus",       "scanner"),
    ("qualys",    "Qualys",       "scanner"),
]

_SEED_OWASP_WEB = [
    ("A01:2021", "web", "Broken Access Control"),
    ("A02:2021", "web", "Cryptographic Failures"),
    ("A03:2021", "web", "Injection"),
    ("A04:2021", "web", "Insecure Design"),
    ("A05:2021", "web", "Security Misconfiguration"),
    ("A06:2021", "web", "Vulnerable and Outdated Components"),
    ("A07:2021", "web", "Identification and Authentication Failures"),
    ("A08:2021", "web", "Software and Data Integrity Failures"),
    ("A09:2021", "web", "Security Logging and Monitoring Failures"),
    ("A10:2021", "web", "Server-Side Request Forgery"),
]

_SEED_OWASP_API = [
    ("API1:2023", "api", "Broken Object Level Authorization"),
    ("API2:2023", "api", "Broken Authentication"),
    ("API3:2023", "api", "Broken Object Property Level Authorization"),
    ("API4:2023", "api", "Unrestricted Resource Consumption"),
    ("API5:2023", "api", "Broken Function Level Authorization"),
    ("API6:2023", "api", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "api", "Server Side Request Forgery"),
    ("API8:2023", "api", "Security Misconfiguration"),
    ("API9:2023", "api", "Improper Inventory Management"),
    ("API10:2023", "api", "Unsafe Consumption of APIs"),
]


# ═══════════════════════════════════════════════════════════════
#  Title Normalisation (mirrors Crucible models/findings.py)
# ═══════════════════════════════════════════════════════════════

_TITLE_NORM_PATS = [
    (re.compile(r'TLS\s*v?\s*1[\s_.]?0', re.I), 'TLSv1.0'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?1', re.I), 'TLSv1.1'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?2', re.I), 'TLSv1.2'),
    (re.compile(r'TLS\s*v?\s*1[\s_.]?3', re.I), 'TLSv1.3'),
    (re.compile(r'SSLv?[\s_]?2(?:\.0)?', re.I), 'SSLv2'),
    (re.compile(r'SSLv?[\s_]?3(?:\.0)?', re.I), 'SSLv3'),
    (re.compile(r'\((\d+)\s*bits?\)', re.I), r'(\1 bit)'),
    (re.compile(r'^/[^:]*:\s+'), ''),
    (re.compile(r'\s*<hostCert#\d+>'), ''),
    (re.compile(r'^(Typosquatting Domain Detected):?\s+.*', re.I), r'\1'),
    (re.compile(r'\s+httpd\b', re.I), ''),
]


def normalize_title(title):
    t = (title or "").strip()
    for pat, repl in _TITLE_NORM_PATS:
        t = pat.sub(repl, t)
    return t.lower()


def compute_dedup_key(finding):
    ntitle = normalize_title(
        finding.get("title") or finding.get("detail") or "")
    tool = (finding.get("tool") or "").split(":")[0].lower()
    tool = _TOOL_ALIAS.get(tool, tool)
    scope = (finding.get("scope") or finding.get("_scope") or "").lower()
    oos = "oos" if finding.get("oos") else ""
    raw = f"{ntitle}|{tool}|{scope}|{oos}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _risk_id(risk_str):
    return RISK_ORDER.get((risk_str or "INFO").upper(), 4) + 1


# ═══════════════════════════════════════════════════════════════
#  FindingsDB
# ═══════════════════════════════════════════════════════════════

class FindingsDB:
    """SQLite-backed findings store."""

    def __init__(self, db_path, readonly=False):
        self.db_path = str(db_path)
        self._readonly = readonly
        flags = sqlite3.PARSE_DECLTYPES
        if readonly:
            self._conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro", uri=True, detect_types=flags)
        else:
            self._conn = sqlite3.connect(self.db_path, detect_types=flags)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA cache_size=-8000")  # 8 MB
        if not readonly:
            self._init_schema()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def _tx(self):
        self._conn.execute("BEGIN")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # ── Schema / Seed ───────────────────────────────────────────

    def _init_schema(self):
        self._conn.executescript(_SCHEMA_DDL)
        cur = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if not row:
            self._seed()
            self._conn.execute(
                "INSERT INTO meta (key,value) VALUES ('schema_version',?)",
                (SCHEMA_VERSION,))
            self._conn.commit()

    def _seed(self):
        self._conn.executemany(
            "INSERT OR IGNORE INTO risks (id,name,sort_order,color,bg_color,border_color) "
            "VALUES (?,?,?,?,?,?)", _SEED_RISKS)
        self._conn.executemany(
            "INSERT OR IGNORE INTO compliance_frameworks (code,name) VALUES (?,?)",
            _SEED_FRAMEWORKS)
        self._conn.executemany(
            "INSERT OR IGNORE INTO tools (id,name,domain) VALUES (?,?,?)",
            _SEED_TOOLS)
        for oid, otype, oname in _SEED_OWASP_WEB + _SEED_OWASP_API:
            self._conn.execute(
                "INSERT OR IGNORE INTO owasp_categories (id,type,name) VALUES (?,?,?)",
                (oid, otype, oname))
        self._conn.commit()

    # ── Meta ────────────────────────────────────────────────────

    def set_meta(self, key, value):
        self._conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self._conn.commit()

    def get_meta(self, key, default=None):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # ── Scope CRUD ──────────────────────────────────────────────

    def ensure_scope(self, name, description=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO scopes (name,description) VALUES (?,?)",
            (name, description))
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM scopes WHERE name=?", (name,)).fetchone()["id"]

    def get_scope_id(self, name):
        if not name:
            return None
        row = self._conn.execute(
            "SELECT id FROM scopes WHERE name=?", (name,)).fetchone()
        return row["id"] if row else None

    # ── Tool CRUD ───────────────────────────────────────────────

    def ensure_tool(self, tool_id, name=None, domain=None, version=None):
        canonical = _TOOL_ALIAS.get(tool_id, tool_id)
        self._conn.execute(
            "INSERT INTO tools (id,name,domain,version) VALUES (?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "name=COALESCE(excluded.name,tools.name),"
            "domain=COALESCE(excluded.domain,tools.domain),"
            "version=COALESCE(excluded.version,tools.version)",
            (canonical, name or canonical, domain, version))
        self._conn.commit()
        return canonical

    # ── Category CRUD ───────────────────────────────────────────

    def ensure_category(self, name, description=None, parent_name=None):
        parent_id = None
        if parent_name:
            self.ensure_category(parent_name)
            parent_id = self._conn.execute(
                "SELECT id FROM categories WHERE name=?",
                (parent_name,)).fetchone()["id"]
        self._conn.execute(
            "INSERT OR IGNORE INTO categories (name,description,parent_id) "
            "VALUES (?,?,?)", (name, description, parent_id))
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM categories WHERE name=?", (name,)).fetchone()["id"]

    def get_category_id(self, name):
        if not name:
            return None
        row = self._conn.execute(
            "SELECT id FROM categories WHERE name=?", (name,)).fetchone()
        return row["id"] if row else None

    # ── Host CRUD ───────────────────────────────────────────────

    def ensure_host(self, ip, **kwargs):
        now = datetime.now().isoformat()
        self._conn.execute(
            "INSERT INTO hosts (ip,mac,os_family,os_name,scope_id,"
            "first_seen,last_seen,is_alive,discovery_method) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "mac=COALESCE(excluded.mac,hosts.mac),"
            "os_family=COALESCE(excluded.os_family,hosts.os_family),"
            "os_name=COALESCE(excluded.os_name,hosts.os_name),"
            "last_seen=excluded.last_seen,"
            "is_alive=COALESCE(excluded.is_alive,hosts.is_alive)",
            (ip, kwargs.get("mac"), kwargs.get("os_family"),
             kwargs.get("os_name"), kwargs.get("scope_id"),
             now, now, kwargs.get("is_alive", 1),
             kwargs.get("discovery_method")))
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()["id"]

    def get_host_id(self, ip):
        if not ip:
            return None
        row = self._conn.execute(
            "SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()
        return row["id"] if row else None

    def link_hostname(self, host_id, hostname, source=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO hostnames (hostname) VALUES (?)",
            (hostname,))
        hn_id = self._conn.execute(
            "SELECT id FROM hostnames WHERE hostname=?",
            (hostname,)).fetchone()["id"]
        self._conn.execute(
            "INSERT OR IGNORE INTO host_hostnames "
            "(host_id,hostname_id,source,first_seen) VALUES (?,?,?,?)",
            (host_id, hn_id, source, datetime.now().isoformat()))
        self._conn.commit()
        return hn_id

    # ── Port / Service CRUD ─────────────────────────────────────

    def ensure_port(self, host_id, port_num, protocol="tcp", state="open"):
        self._conn.execute(
            "INSERT INTO ports (host_id,port,protocol,state) VALUES (?,?,?,?) "
            "ON CONFLICT(host_id,port,protocol) DO UPDATE SET "
            "state=COALESCE(excluded.state,ports.state)",
            (host_id, port_num, protocol, state))
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM ports WHERE host_id=? AND port=? AND protocol=?",
            (host_id, port_num, protocol)).fetchone()["id"]

    def set_service(self, port_id, **kwargs):
        self._conn.execute(
            "INSERT INTO services (port_id,name,product,version,extra_info,"
            "cpe,banner,tunnel,discovery_tool) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(port_id) DO UPDATE SET "
            "name=COALESCE(excluded.name,services.name),"
            "product=COALESCE(excluded.product,services.product),"
            "version=COALESCE(excluded.version,services.version),"
            "cpe=COALESCE(excluded.cpe,services.cpe),"
            "banner=COALESCE(excluded.banner,services.banner),"
            "tunnel=COALESCE(excluded.tunnel,services.tunnel)",
            (port_id, kwargs.get("name"), kwargs.get("product"),
             kwargs.get("version"), kwargs.get("extra_info"),
             kwargs.get("cpe"), kwargs.get("banner"),
             kwargs.get("tunnel"), kwargs.get("discovery_tool")))
        self._conn.commit()

    # ── CWE / CVE helpers ──────────────────────────────────────

    def _ensure_cwe(self, cwe_id, name=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO cwes (id,name) VALUES (?,?)",
            (cwe_id, name))

    def _ensure_cve(self, cve_id):
        self._conn.execute(
            "INSERT OR IGNORE INTO cves (id) VALUES (?)", (cve_id,))

    def _ensure_mitre(self, technique_id, name="", tactic_id=None,
                      tactic_name=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO mitre_techniques (id,name) VALUES (?,?)",
            (technique_id, name))
        if tactic_id:
            self._conn.execute(
                "INSERT OR IGNORE INTO mitre_tactics (id,name) VALUES (?,?)",
                (tactic_id, tactic_name or tactic_id))
            self._conn.execute(
                "INSERT OR IGNORE INTO mitre_technique_tactics "
                "(technique_id,tactic_id) VALUES (?,?)",
                (technique_id, tactic_id))

    def _ensure_searchsploit(self, term):
        self._conn.execute(
            "INSERT OR IGNORE INTO searchsploit_terms (term) VALUES (?)",
            (term,))
        return self._conn.execute(
            "SELECT id FROM searchsploit_terms WHERE term=?",
            (term,)).fetchone()["id"]

    def _ensure_metasploit(self, module):
        self._conn.execute(
            "INSERT OR IGNORE INTO metasploit_modules (module) VALUES (?)",
            (module,))
        return self._conn.execute(
            "SELECT id FROM metasploit_modules WHERE module=?",
            (module,)).fetchone()["id"]

    def _ensure_compliance_control(self, framework_code, control_id):
        fw = self._conn.execute(
            "SELECT id FROM compliance_frameworks WHERE code=?",
            (framework_code,)).fetchone()
        if not fw:
            return None
        self._conn.execute(
            "INSERT OR IGNORE INTO compliance_controls "
            "(framework_id,control_id) VALUES (?,?)",
            (fw["id"], control_id))
        return self._conn.execute(
            "SELECT id FROM compliance_controls "
            "WHERE framework_id=? AND control_id=?",
            (fw["id"], control_id)).fetchone()["id"]

    # ── Finding INSERT (with dedup + location) ──────────────────

    def insert_finding(self, f, commit=True):
        """Insert a single finding.  If the dedup key already exists,
        merge by adding a new location row instead of a new finding."""
        fid = f.get("id") or str(uuid.uuid4())
        tool_raw = (f.get("tool") or "").split(":")[0].lower()
        tool_id = _TOOL_ALIAS.get(tool_raw, tool_raw)
        self.ensure_tool(tool_id)

        scope_name = (f.get("scope") or f.get("_scope") or "").strip()
        scope_id = self.get_scope_id(scope_name) if scope_name else None
        if scope_name and scope_id is None:
            scope_id = self.ensure_scope(scope_name)

        risk_str = (f.get("risk") or "INFO").upper()
        rid = _risk_id(risk_str)
        dk = compute_dedup_key(f)

        existing = self._conn.execute(
            "SELECT id, merged_count FROM findings WHERE dedup_key=?",
            (dk,)).fetchone()

        ip = (f.get("ip") or "").strip()
        port = int(f.get("port") or 0)
        hostname = (f.get("hostname") or "").strip()
        service = (f.get("service") or "").strip()

        if existing:
            eid = existing["id"]
            self._add_location(eid, ip, port, hostname, service,
                               f.get("output"), f.get("output_file"))
            cur_risk = self._conn.execute(
                "SELECT risk_id FROM findings WHERE id=?", (eid,)).fetchone()
            if rid < cur_risk["risk_id"]:
                self._conn.execute(
                    "UPDATE findings SET risk_id=?, updated_at=? WHERE id=?",
                    (rid, datetime.now().isoformat(), eid))
            self._conn.execute(
                "UPDATE findings SET merged_count=merged_count+1,"
                "updated_at=? WHERE id=?",
                (datetime.now().isoformat(), eid))
            self._merge_flags(eid, f)
            if commit:
                self._conn.commit()
            return eid

        cat_name = (f.get("remediation_category") or
                    f.get("category") or "").strip()
        cat_id = self.get_category_id(cat_name)
        cat_entry_id = (f.get("catalogue_id") or "").strip() or None

        now_iso = datetime.now().isoformat()
        self._conn.execute("""
            INSERT INTO findings (
                id, tool_id, scope_id, category_id, catalogue_id, risk_id,
                title, normalized_title, dedup_key,
                phase, description, impact, remediation,
                output, command, sources,
                cvss_score, cvss_vector, confidence,
                nessus_plugin_id, nessus_plugin_name, qualys_qid,
                plugin_output,
                exploitdb, metasploit, kev, exploit_details,
                remediation_effort, remediation_component,
                remediation_category,
                is_false_positive, accepted, imported,
                datetime, _original_title, created_at, updated_at
            ) VALUES (
                ?,?,?,?,?,?,
                ?,?,?,
                ?,?,?,?,
                ?,?,?,
                ?,?,?,
                ?,?,?,
                ?,
                ?,?,?,?,
                ?,?,
                ?,
                ?,?,?,
                ?,?,?,?
            )
        """, (
            fid, tool_id, scope_id, cat_id, cat_entry_id, rid,
            f.get("title", ""), normalize_title(f.get("title", "")), dk,
            f.get("phase"), f.get("description", ""),
            f.get("impact"), f.get("remediation", ""),
            f.get("output"), f.get("command"), f.get("sources"),
            f.get("cvss_score"), f.get("cvss_vector"),
            f.get("confidence"),
            f.get("nessus_plugin_id"), f.get("nessus_plugin_name"),
            f.get("qualys_qid"), f.get("plugin_output"),
            1 if f.get("exploitdb") else 0,
            1 if f.get("metasploit") else 0,
            1 if f.get("kev") else 0,
            json.dumps(f.get("exploit_details", [])),
            f.get("remediation_effort"), f.get("remediation_component"),
            f.get("remediation_category"),
            0, 1 if f.get("accepted") else 0,
            1 if f.get("imported") else 0,
            f.get("datetime", now_iso), f.get("_original_title"),
            now_iso, now_iso,
        ))

        self._add_location(fid, ip, port, hostname, service,
                           f.get("output"), f.get("output_file"))
        self._link_junction_data(fid, f)

        if commit:
            self._conn.commit()
        return fid

    def bulk_insert(self, findings):
        """Insert many findings in one transaction."""
        ids = []
        with self._tx():
            for f in findings:
                ids.append(self.insert_finding(f, commit=False))
        return ids

    def _add_location(self, finding_id, ip, port, hostname, service,
                      output=None, output_file=None):
        if not ip and not hostname:
            return None
        host_id = None
        port_id = None
        if ip:
            host_id = self.get_host_id(ip)
            if host_id is None:
                host_id = self.ensure_host(ip)
            if port and port > 0:
                port_id = self.ensure_port(host_id, port)
                if service:
                    self.set_service(port_id, name=service)
            if hostname:
                self.link_hostname(host_id, hostname)
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_locations "
                "(finding_id,host_id,port_id,ip,port,hostname,service,"
                "output,output_file) VALUES (?,?,?,?,?,?,?,?,?)",
                (finding_id, host_id, port_id, ip, port or 0,
                 hostname, service, output, output_file))
        except sqlite3.IntegrityError:
            pass
        return host_id

    def _merge_flags(self, finding_id, source):
        updates = []
        params = []
        for flag in ("exploitdb", "metasploit", "kev"):
            if source.get(flag):
                updates.append(f"{flag}=1")
        if source.get("sources"):
            updates.append(
                "sources=CASE WHEN sources IS NULL OR sources='' "
                "THEN ? ELSE sources||char(10)||? END")
            sv = source["sources"]
            params.extend([sv, sv])
        if updates:
            params.append(finding_id)
            self._conn.execute(
                f"UPDATE findings SET {','.join(updates)} WHERE id=?",
                params)

    def _link_junction_data(self, finding_id, f):
        cwe_list = f.get("cwe") or []
        if isinstance(cwe_list, str):
            cwe_list = [c.strip() for c in cwe_list.split(",") if c.strip()]
        for cw in cwe_list:
            self._ensure_cwe(cw)
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_cwe (finding_id,cwe_id) "
                "VALUES (?,?)", (finding_id, cw))

        cves_raw = f.get("cves") or ""
        if isinstance(cves_raw, str):
            cve_list = [c.strip() for c in cves_raw.split(",") if c.strip()]
        elif isinstance(cves_raw, list):
            cve_list = cves_raw
        else:
            cve_list = []
        for cv in cve_list:
            self._ensure_cve(cv)
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_cve (finding_id,cve_id) "
                "VALUES (?,?)", (finding_id, cv))

        for ofield, otype in [("owasp", "web"), ("owasp_api", "api")]:
            oval = (f.get(ofield) or "").strip()
            if oval:
                oid = self._match_owasp(oval, otype)
                if oid:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO finding_owasp "
                        "(finding_id,owasp_id) VALUES (?,?)",
                        (finding_id, oid))

        mitre = f.get("mitre_attack") or []
        if isinstance(mitre, list):
            for m in mitre:
                if isinstance(m, dict):
                    tid = m.get("technique", "")
                    if tid:
                        self._ensure_mitre(
                            tid, m.get("name", ""),
                            m.get("tactic_id"), m.get("tactic"))
                        self._conn.execute(
                            "INSERT OR IGNORE INTO finding_mitre "
                            "(finding_id,technique_id) VALUES (?,?)",
                            (finding_id, tid))

        for fw_code in ("nist_800_53", "nist_800_171", "nist_csf2",
                        "pci_dss_4", "iso_27001", "iso_27002",
                        "soc2", "hitrust", "gdpr"):
            controls = f.get(fw_code) or []
            if isinstance(controls, str):
                controls = [c.strip() for c in controls.split(",")
                            if c.strip()]
            for ctrl in controls:
                ctrl_pk = self._ensure_compliance_control(fw_code, ctrl)
                if ctrl_pk:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO finding_compliance "
                        "(finding_id,control_id) VALUES (?,?)",
                        (finding_id, ctrl_pk))

        for term in (f.get("searchsploit_terms") or []):
            tid = self._ensure_searchsploit(term)
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_searchsploit "
                "(finding_id,term_id) VALUES (?,?)", (finding_id, tid))

        for mod in (f.get("metasploit_modules") or []):
            mid = self._ensure_metasploit(mod)
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_metasploit "
                "(finding_id,module_id) VALUES (?,?)", (finding_id, mid))

        for st in (f.get("source_tools") or []):
            canon = _TOOL_ALIAS.get(st, st)
            self.ensure_tool(canon)
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_source_tools "
                "(finding_id,tool_id) VALUES (?,?)", (finding_id, canon))

    def _match_owasp(self, text, otype):
        row = self._conn.execute(
            "SELECT id FROM owasp_categories WHERE id=? OR name=?",
            (text, text)).fetchone()
        if row:
            return row["id"]
        row = self._conn.execute(
            "SELECT id FROM owasp_categories "
            "WHERE type=? AND name LIKE ? LIMIT 1",
            (otype, f"%{text}%")).fetchone()
        return row["id"] if row else None

    # ── Finding QUERY (paginated, filtered, sorted) ─────────────

    def query_findings(self, *, page=1, per_page=100, risk=None,
                       tool=None, scope=None, ip=None, port=None,
                       hostname=None, category=None, search=None,
                       include_fp=False, include_oos=True,
                       sort="risk_id,title", order="asc"):
        """Paginated finding query with server-side filtering."""
        where = []
        params = []

        if not include_fp:
            where.append("f.is_false_positive=0")
        if not include_oos:
            where.append("f.is_oos=0")

        if risk:
            if isinstance(risk, str):
                risk = [r.strip() for r in risk.split(",")]
            placeholders = ",".join("?" * len(risk))
            where.append(f"r.name IN ({placeholders})")
            params.extend([r.upper() for r in risk])

        if tool:
            if isinstance(tool, str):
                tool = [tool]
            placeholders = ",".join("?" * len(tool))
            where.append(f"f.tool_id IN ({placeholders})")
            params.extend([_TOOL_ALIAS.get(t, t) for t in tool])

        if scope:
            where.append("s.name=?")
            params.append(scope)

        if category:
            where.append("c.name=?")
            params.append(category)

        if ip:
            where.append(
                "f.id IN (SELECT finding_id FROM finding_locations WHERE ip=?)")
            params.append(ip)

        if port:
            where.append(
                "f.id IN (SELECT finding_id FROM finding_locations WHERE port=?)")
            params.append(int(port))

        if hostname:
            where.append(
                "f.id IN (SELECT finding_id FROM finding_locations "
                "WHERE hostname=?)")
            params.append(hostname)

        if search:
            where.append(
                "f.id IN (SELECT finding_id FROM findings_fts_content "
                "WHERE rowid IN (SELECT rowid FROM findings_fts "
                "WHERE findings_fts MATCH ?))")
            params.append(search)

        where_clause = " AND ".join(where) if where else "1=1"

        allowed_sorts = {
            "risk_id": "f.risk_id", "title": "f.title",
            "datetime": "f.datetime", "tool_id": "f.tool_id",
            "cvss_score": "f.cvss_score", "merged_count": "f.merged_count",
            "category": "c.name",
        }
        sort_cols = []
        for s in sort.split(","):
            s = s.strip().lstrip("-")
            if s in allowed_sorts:
                sort_cols.append(allowed_sorts[s])
        sort_clause = ", ".join(sort_cols) if sort_cols else "f.risk_id, f.title"
        direction = "DESC" if order.lower() == "desc" else "ASC"

        count_sql = f"""
            SELECT COUNT(*) as total
            FROM findings f
            LEFT JOIN risks r ON f.risk_id=r.id
            LEFT JOIN scopes s ON f.scope_id=s.id
            LEFT JOIN categories c ON f.category_id=c.id
            WHERE {where_clause}
        """
        total = self._conn.execute(count_sql, params).fetchone()["total"]

        offset = (page - 1) * per_page
        data_sql = f"""
            SELECT f.*, r.name as risk_name, r.sort_order as risk_sort,
                   s.name as scope_name, c.name as category_name,
                   t.name as tool_name
            FROM findings f
            LEFT JOIN risks r ON f.risk_id=r.id
            LEFT JOIN scopes s ON f.scope_id=s.id
            LEFT JOIN categories c ON f.category_id=c.id
            LEFT JOIN tools t ON f.tool_id=t.id
            WHERE {where_clause}
            ORDER BY {sort_clause} {direction}
            LIMIT ? OFFSET ?
        """
        rows = self._conn.execute(
            data_sql, params + [per_page, offset]).fetchall()

        findings = []
        for row in rows:
            f = self._row_to_finding(row)
            findings.append(f)

        return {
            "findings": findings,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page if per_page else 1,
        }

    def _row_to_finding(self, row):
        """Convert a DB row to a finding dict matching legacy JSON format."""
        d = dict(row)
        d["risk"] = d.pop("risk_name", RISK_NAMES.get(d.get("risk_id", 5) - 1, "INFO"))
        d["scope"] = d.pop("scope_name", "")
        d["category"] = d.pop("category_name", "")
        d["tool_display"] = d.pop("tool_name", d.get("tool_id", ""))
        d["tool"] = d.get("tool_id", "")

        fid = d["id"]
        locs = self._conn.execute(
            "SELECT ip,port,hostname,service,url,output_file "
            "FROM finding_locations WHERE finding_id=?", (fid,)).fetchall()
        affected = []
        for loc in locs:
            lip = loc["ip"] or ""
            lport = loc["port"] or 0
            lhost = loc["hostname"] or ""
            if lip:
                entry = f"{lip}:{lport}" if lport else lip
                if entry not in affected:
                    affected.append(entry)
            if lhost and lhost not in affected:
                affected.append(lhost)
        d["affected"] = "\n".join(sorted(affected))
        d["location_count"] = len(locs)

        of_parts = []
        for loc in locs:
            if loc["output_file"]:
                of_parts.append(loc["output_file"])
        if of_parts:
            d["output_file"] = "\n".join(of_parts)

        return d

    def get_finding(self, finding_id):
        row = self._conn.execute(
            "SELECT f.*, r.name as risk_name, r.sort_order as risk_sort, "
            "s.name as scope_name, c.name as category_name, "
            "t.name as tool_name "
            "FROM findings f "
            "LEFT JOIN risks r ON f.risk_id=r.id "
            "LEFT JOIN scopes s ON f.scope_id=s.id "
            "LEFT JOIN categories c ON f.category_id=c.id "
            "LEFT JOIN tools t ON f.tool_id=t.id "
            "WHERE f.id=?", (finding_id,)).fetchone()
        if not row:
            return None
        f = self._row_to_finding(row)

        f["cwe"] = [r["cwe_id"] for r in self._conn.execute(
            "SELECT cwe_id FROM finding_cwe WHERE finding_id=?",
            (finding_id,)).fetchall()]
        f["cves"] = [r["cve_id"] for r in self._conn.execute(
            "SELECT cve_id FROM finding_cve WHERE finding_id=?",
            (finding_id,)).fetchall()]
        f["owasp_ids"] = [r["owasp_id"] for r in self._conn.execute(
            "SELECT owasp_id FROM finding_owasp WHERE finding_id=?",
            (finding_id,)).fetchall()]
        f["mitre_attack"] = []
        for r in self._conn.execute(
                "SELECT mt.id, mt.name FROM finding_mitre fm "
                "JOIN mitre_techniques mt ON fm.technique_id=mt.id "
                "WHERE fm.finding_id=?", (finding_id,)).fetchall():
            f["mitre_attack"].append({"technique": r["id"], "name": r["name"]})
        f["notes"] = [dict(r) for r in self._conn.execute(
            "SELECT note,author,created_at FROM finding_notes "
            "WHERE finding_id=? ORDER BY created_at",
            (finding_id,)).fetchall()]
        f["compliance"] = {}
        for r in self._conn.execute(
                "SELECT cf.code, cc.control_id "
                "FROM finding_compliance fc "
                "JOIN compliance_controls cc ON fc.control_id=cc.id "
                "JOIN compliance_frameworks cf ON cc.framework_id=cf.id "
                "WHERE fc.finding_id=?", (finding_id,)).fetchall():
            f["compliance"].setdefault(r["code"], []).append(r["control_id"])

        return f

    # ── Summary / Aggregation ───────────────────────────────────

    def get_summary(self, include_fp=False, scope=None, tool=None):
        where = []
        params = []
        if not include_fp:
            where.append("f.is_false_positive=0")
        if scope:
            where.append("s.name=?")
            params.append(scope)
        if tool:
            where.append("f.tool_id=?")
            params.append(_TOOL_ALIAS.get(tool, tool))
        wc = " AND ".join(where) if where else "1=1"
        rows = self._conn.execute(f"""
            SELECT r.name as risk, COUNT(*) as count
            FROM findings f
            JOIN risks r ON f.risk_id=r.id
            LEFT JOIN scopes s ON f.scope_id=s.id
            WHERE {wc}
            GROUP BY r.name ORDER BY r.sort_order
        """, params).fetchall()
        summary = {r: 0 for r in RISK_ORDER}
        total = 0
        for row in rows:
            summary[row["risk"]] = row["count"]
            total += row["count"]
        summary["total"] = total
        return summary

    def get_tool_summary(self, include_fp=False):
        fp = " AND f.is_false_positive=0" if not include_fp else ""
        return [dict(r) for r in self._conn.execute(f"""
            SELECT f.tool_id, t.name as tool_name, COUNT(*) as count,
                SUM(CASE WHEN r.name='CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN r.name='HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN r.name='MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN r.name='LOW' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN r.name='INFO' THEN 1 ELSE 0 END) as info
            FROM findings f
            JOIN risks r ON f.risk_id=r.id
            JOIN tools t ON f.tool_id=t.id
            WHERE 1=1 {fp}
            GROUP BY f.tool_id ORDER BY critical DESC, high DESC, count DESC
        """).fetchall()]

    def get_category_summary(self, include_fp=False):
        fp = " AND f.is_false_positive=0" if not include_fp else ""
        return [dict(r) for r in self._conn.execute(f"""
            SELECT COALESCE(c.name,'Uncategorized') as category,
                COUNT(*) as count,
                SUM(CASE WHEN r.name='CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN r.name='HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN r.name='MEDIUM' THEN 1 ELSE 0 END) as medium
            FROM findings f
            JOIN risks r ON f.risk_id=r.id
            LEFT JOIN categories c ON f.category_id=c.id
            WHERE 1=1 {fp}
            GROUP BY c.name ORDER BY critical DESC, high DESC, count DESC
        """).fetchall()]

    # ── False Positive Management ───────────────────────────────

    def mark_false_positive(self, finding_id, reason=None):
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE findings SET is_false_positive=1, fp_marked_at=?, "
            "fp_reason=?, updated_at=? WHERE id=?",
            (now, reason, now, finding_id))
        self._conn.commit()

    def recover_false_positive(self, finding_id):
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE findings SET is_false_positive=0, fp_marked_at=NULL, "
            "fp_reason=NULL, updated_at=? WHERE id=?",
            (now, finding_id))
        self._conn.commit()

    def get_false_positives(self, page=1, per_page=100):
        return self.query_findings(
            page=page, per_page=per_page, include_fp=True,
            sort="risk_id,title")

    # ── Risk Override ───────────────────────────────────────────

    def override_risk(self, finding_id, new_risk, reason=None, author=None):
        cur = self._conn.execute(
            "SELECT risk_id FROM findings WHERE id=?",
            (finding_id,)).fetchone()
        if not cur:
            return False
        old_rid = cur["risk_id"]
        new_rid = _risk_id(new_risk)
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE findings SET risk_id=?, original_risk_id=?, "
            "risk_overridden=1, risk_override_reason=?, updated_at=? "
            "WHERE id=?",
            (new_rid, old_rid, reason, now, finding_id))
        self._conn.execute(
            "INSERT INTO risk_override_log "
            "(finding_id,old_risk_id,new_risk_id,reason,author,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (finding_id, old_rid, new_rid, reason, author, now))
        self._conn.commit()
        return True

    # ── Notes ───────────────────────────────────────────────────

    def add_note(self, finding_id, note, author=None):
        self._conn.execute(
            "INSERT INTO finding_notes (finding_id,note,author) VALUES (?,?,?)",
            (finding_id, note, author))
        self._conn.commit()

    # ── Tags ────────────────────────────────────────────────────

    def ensure_tag(self, name, color=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO tags (name,color) VALUES (?,?)",
            (name, color))
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM tags WHERE name=?", (name,)).fetchone()["id"]

    def tag_finding(self, finding_id, tag_name, color=None):
        tid = self.ensure_tag(tag_name, color)
        self._conn.execute(
            "INSERT OR IGNORE INTO finding_tags (finding_id,tag_id) "
            "VALUES (?,?)", (finding_id, tid))
        self._conn.commit()

    def tag_host(self, host_id, tag_name, color=None):
        tid = self.ensure_tag(tag_name, color)
        self._conn.execute(
            "INSERT OR IGNORE INTO host_tags (host_id,tag_id) "
            "VALUES (?,?)", (host_id, tid))
        self._conn.commit()

    # ── FTS Management ──────────────────────────────────────────

    def rebuild_fts(self):
        self._conn.execute("DELETE FROM findings_fts_content")
        self._conn.execute("""
            INSERT INTO findings_fts_content
                (finding_id, title, description, remediation,
                 affected_text, output)
            SELECT f.id, f.title, f.description, f.remediation,
                GROUP_CONCAT(fl.ip || ':' || COALESCE(fl.port,0)
                    || ' ' || COALESCE(fl.hostname,''), ' '),
                f.output
            FROM findings f
            LEFT JOIN finding_locations fl ON f.id=fl.finding_id
            GROUP BY f.id
        """)
        self._conn.execute("""
            INSERT INTO findings_fts (findings_fts)
            VALUES ('rebuild')
        """)
        self._conn.commit()
        log.info("FTS index rebuilt")

    def search(self, query, page=1, per_page=100):
        count = self._conn.execute(
            "SELECT COUNT(DISTINCT finding_id) as total "
            "FROM findings_fts_content WHERE rowid IN "
            "(SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?)",
            (query,)).fetchone()["total"]
        offset = (page - 1) * per_page
        rows = self._conn.execute("""
            SELECT f.*, r.name as risk_name, r.sort_order as risk_sort,
                   s.name as scope_name, c.name as category_name,
                   t.name as tool_name
            FROM findings f
            JOIN findings_fts_content fc ON f.id=fc.finding_id
            JOIN findings_fts fts ON fc.rowid=fts.rowid
            JOIN risks r ON f.risk_id=r.id
            LEFT JOIN scopes s ON f.scope_id=s.id
            LEFT JOIN categories c ON f.category_id=c.id
            LEFT JOIN tools t ON f.tool_id=t.id
            WHERE findings_fts MATCH ?
            ORDER BY fts.rank
            LIMIT ? OFFSET ?
        """, (query, per_page, offset)).fetchall()
        return {
            "findings": [self._row_to_finding(r) for r in rows],
            "total": count,
            "page": page,
            "per_page": per_page,
            "pages": (count + per_page - 1) // per_page if per_page else 1,
        }

    # ── Intelligence: Host Profiles ─────────────────────────────

    def compute_host_profiles(self):
        self._conn.execute("DELETE FROM host_risk_profiles")
        self._conn.execute("""
            INSERT INTO host_risk_profiles
                (host_id, total_findings, critical_count, high_count,
                 medium_count, low_count, info_count, max_cvss, avg_cvss,
                 risk_score, tools_hit, computed_at)
            SELECT
                h.id,
                COUNT(DISTINCT f.id),
                SUM(CASE WHEN r.name='CRITICAL' THEN 1 ELSE 0 END),
                SUM(CASE WHEN r.name='HIGH' THEN 1 ELSE 0 END),
                SUM(CASE WHEN r.name='MEDIUM' THEN 1 ELSE 0 END),
                SUM(CASE WHEN r.name='LOW' THEN 1 ELSE 0 END),
                SUM(CASE WHEN r.name='INFO' THEN 1 ELSE 0 END),
                MAX(f.cvss_score),
                AVG(f.cvss_score),
                SUM(CASE r.name
                    WHEN 'CRITICAL' THEN 40
                    WHEN 'HIGH' THEN 10
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 1
                    ELSE 0 END),
                GROUP_CONCAT(DISTINCT f.tool_id),
                datetime('now')
            FROM hosts h
            JOIN finding_locations fl ON fl.host_id=h.id
            JOIN findings f ON fl.finding_id=f.id AND f.is_false_positive=0
            JOIN risks r ON f.risk_id=r.id
            GROUP BY h.id
        """)
        self._conn.commit()
        log.info("Host risk profiles computed")

    def get_host_profile(self, ip):
        host = self._conn.execute(
            "SELECT h.*, hrp.* FROM hosts h "
            "LEFT JOIN host_risk_profiles hrp ON h.id=hrp.host_id "
            "WHERE h.ip=?", (ip,)).fetchone()
        if not host:
            return None
        d = dict(host)
        hid = d["id"]
        d["hostnames"] = [r["hostname"] for r in self._conn.execute(
            "SELECT hn.hostname FROM host_hostnames hh "
            "JOIN hostnames hn ON hh.hostname_id=hn.id "
            "WHERE hh.host_id=?", (hid,)).fetchall()]
        d["ports"] = [dict(r) for r in self._conn.execute(
            "SELECT p.port, p.protocol, p.state, "
            "s.name as service, s.product, s.version "
            "FROM ports p LEFT JOIN services s ON p.id=s.port_id "
            "WHERE p.host_id=? ORDER BY p.port", (hid,)).fetchall()]
        d["software"] = [dict(r) for r in self._conn.execute(
            "SELECT sw.product, sw.vendor, hs.version, hs.detected_by "
            "FROM host_software hs JOIN software sw ON hs.software_id=sw.id "
            "WHERE hs.host_id=?", (hid,)).fetchall()]
        return d

    # ── Intelligence: Attack Surface ────────────────────────────

    def compute_attack_surface(self):
        self._conn.execute("DELETE FROM attack_surface")
        self._conn.execute("""
            INSERT INTO attack_surface
                (host_id, port_id, tools_count, finding_count,
                 has_critical, has_high, computed_at)
            SELECT
                fl.host_id, fl.port_id,
                COUNT(DISTINCT f.tool_id),
                COUNT(DISTINCT f.id),
                MAX(CASE WHEN r.name='CRITICAL' THEN 1 ELSE 0 END),
                MAX(CASE WHEN r.name='HIGH' THEN 1 ELSE 0 END),
                datetime('now')
            FROM finding_locations fl
            JOIN findings f ON fl.finding_id=f.id AND f.is_false_positive=0
            JOIN risks r ON f.risk_id=r.id
            WHERE fl.host_id IS NOT NULL
            GROUP BY fl.host_id, fl.port_id
        """)
        self._conn.commit()
        log.info("Attack surface computed")

    def get_attack_surface(self, page=1, per_page=100):
        total = self._conn.execute(
            "SELECT COUNT(*) as c FROM attack_surface").fetchone()["c"]
        offset = (page - 1) * per_page
        rows = self._conn.execute("""
            SELECT h.ip, p.port, p.protocol, sv.name as service,
                   a.tools_count, a.finding_count,
                   a.has_critical, a.has_high
            FROM attack_surface a
            JOIN hosts h ON a.host_id=h.id
            LEFT JOIN ports p ON a.port_id=p.id
            LEFT JOIN services sv ON p.id=sv.port_id
            ORDER BY a.has_critical DESC, a.has_high DESC,
                     a.finding_count DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset)).fetchall()
        return {
            "entries": [dict(r) for r in rows],
            "total": total, "page": page, "per_page": per_page,
        }

    # ── Intelligence: Compliance Gaps ───────────────────────────

    def compute_compliance_gaps(self):
        self._conn.execute("DELETE FROM compliance_gaps")
        self._conn.execute("""
            INSERT INTO compliance_gaps
                (framework_id, control_id, status, finding_count,
                 max_risk_id, computed_at)
            SELECT
                cc.framework_id, fc.control_id,
                'gap',
                COUNT(DISTINCT fc.finding_id),
                MIN(f.risk_id),
                datetime('now')
            FROM finding_compliance fc
            JOIN findings f ON fc.finding_id=f.id AND f.is_false_positive=0
            JOIN compliance_controls cc ON fc.control_id=cc.id
            GROUP BY cc.framework_id, fc.control_id
        """)
        self._conn.commit()

    def get_compliance_gaps(self, framework_code=None):
        where = ""
        params = []
        if framework_code:
            where = "WHERE cf.code=?"
            params = [framework_code]
        return [dict(r) for r in self._conn.execute(f"""
            SELECT cf.code as framework, cf.name as framework_name,
                   cc.control_id, cc.title as control_title,
                   cg.finding_count, r.name as max_risk
            FROM compliance_gaps cg
            JOIN compliance_controls cc ON cg.control_id=cc.id
            JOIN compliance_frameworks cf ON cg.framework_id=cf.id
            LEFT JOIN risks r ON cg.max_risk_id=r.id
            {where}
            ORDER BY cg.max_risk_id, cg.finding_count DESC
        """, params).fetchall()]

    # ── Intelligence: Cross-Tool Correlation ────────────────────

    def get_cross_tool_findings(self, ip, port=None):
        where = "fl.ip=?"
        params = [ip]
        if port:
            where += " AND fl.port=?"
            params.append(int(port))
        return [dict(r) for r in self._conn.execute(f"""
            SELECT DISTINCT f.id, f.title, f.tool_id, t.name as tool_name,
                   r.name as risk, fl.port, fl.service,
                   f.cvss_score, f.datetime
            FROM findings f
            JOIN finding_locations fl ON f.id=fl.finding_id
            JOIN risks r ON f.risk_id=r.id
            JOIN tools t ON f.tool_id=t.id
            WHERE {where} AND f.is_false_positive=0
            ORDER BY f.risk_id, f.title
        """, params).fetchall()]

    def get_multi_tool_hosts(self, min_tools=2):
        return [dict(r) for r in self._conn.execute("""
            SELECT h.ip, MAX(hn.hostname) as hostname,
                COUNT(DISTINCT f.tool_id) as tools,
                GROUP_CONCAT(DISTINCT f.tool_id) as which_tools,
                COUNT(DISTINCT f.id) as total_findings,
                SUM(CASE WHEN r.name='CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN r.name='HIGH' THEN 1 ELSE 0 END) as high
            FROM hosts h
            JOIN finding_locations fl ON fl.host_id=h.id
            JOIN findings f ON fl.finding_id=f.id AND f.is_false_positive=0
            JOIN risks r ON f.risk_id=r.id
            LEFT JOIN host_hostnames hh ON h.id=hh.host_id
            LEFT JOIN hostnames hn ON hh.hostname_id=hn.id
            GROUP BY h.id
            HAVING tools >= ?
            ORDER BY critical DESC, high DESC, total_findings DESC
        """, (min_tools,)).fetchall()]

    # ── Intelligence: Trend Snapshots ───────────────────────────

    def take_trend_snapshot(self):
        summary = self.get_summary()
        host_count = self._conn.execute(
            "SELECT COUNT(*) as c FROM hosts").fetchone()["c"]
        svc_count = self._conn.execute(
            "SELECT COUNT(*) as c FROM services").fetchone()["c"]
        fp_count = self._conn.execute(
            "SELECT COUNT(*) as c FROM findings "
            "WHERE is_false_positive=1").fetchone()["c"]
        self._conn.execute("""
            INSERT INTO trend_snapshots
                (snapshot_at, total_findings, critical_count, high_count,
                 medium_count, low_count, info_count, total_hosts,
                 total_services, fp_count)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (datetime.now().isoformat(), summary["total"],
              summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"],
              summary["LOW"], summary["INFO"],
              host_count, svc_count, fp_count))
        self._conn.commit()

    def get_trend(self, hours=24):
        return [dict(r) for r in self._conn.execute("""
            SELECT * FROM trend_snapshots
            WHERE snapshot_at > datetime('now', ?)
            ORDER BY snapshot_at
        """, (f"-{hours} hours",)).fetchall()]

    # ── Intelligence: Recompute All ─────────────────────────────

    def recompute_intelligence(self):
        self.compute_host_profiles()
        self.compute_attack_surface()
        self.compute_compliance_gaps()
        self.rebuild_fts()
        self.take_trend_snapshot()
        log.info("All intelligence tables recomputed")

    # ── Exclusions ──────────────────────────────────────────────

    def add_exclusion(self, value, exc_type="ip", reason=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO exclusions (value,type,reason) "
            "VALUES (?,?,?)", (value, exc_type, reason))
        self._conn.commit()

    def get_exclusions(self):
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM exclusions ORDER BY value").fetchall()]

    def apply_exclusions(self):
        excl = self.get_exclusions()
        if not excl:
            return 0
        count = 0
        for ex in excl:
            if ex["type"] == "ip":
                n = self._conn.execute(
                    "UPDATE findings SET is_oos=1, oos_reason='excluded' "
                    "WHERE id IN (SELECT finding_id FROM finding_locations "
                    "WHERE ip=?) AND is_oos=0",
                    (ex["value"],)).rowcount
                count += n
        self._conn.commit()
        return count

    # ── Action Items ────────────────────────────────────────────

    def insert_action_item(self, item):
        aid = item.get("id") or str(uuid.uuid4())
        self._conn.execute("""
            INSERT OR IGNORE INTO action_items
                (id, finding_id, recommended_tool, target,
                 normalized_target, command, status, priority)
            VALUES (?,?,?,?,?,?,?,?)
        """, (aid, item.get("finding_id"), item.get("recommended_tool"),
              item.get("target", ""), item.get("normalized_target", ""),
              item.get("command"), item.get("status", "pending"),
              item.get("priority", 0)))
        self._conn.commit()
        return aid

    def get_action_items(self, status=None, tool=None, page=1, per_page=100):
        where = []
        params = []
        if status:
            where.append("status=?")
            params.append(status)
        if tool:
            where.append("recommended_tool=?")
            params.append(tool)
        wc = " AND ".join(where) if where else "1=1"
        total = self._conn.execute(
            f"SELECT COUNT(*) as c FROM action_items WHERE {wc}",
            params).fetchone()["c"]
        offset = (page - 1) * per_page
        rows = self._conn.execute(
            f"SELECT * FROM action_items WHERE {wc} "
            f"ORDER BY priority DESC, created_at LIMIT ? OFFSET ?",
            params + [per_page, offset]).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "total": total, "page": page, "per_page": per_page,
        }

    def update_action_item(self, item_id, **kwargs):
        sets = []
        params = []
        for k in ("status", "started_at", "ended_at", "pid",
                   "returncode", "error"):
            if k in kwargs:
                sets.append(f"{k}=?")
                params.append(kwargs[k])
        if not sets:
            return
        sets.append("updated_at=?")
        params.append(datetime.now().isoformat())
        params.append(item_id)
        self._conn.execute(
            f"UPDATE action_items SET {','.join(sets)} WHERE id=?", params)
        self._conn.commit()

    # ── Tool Runs ───────────────────────────────────────────────

    def record_tool_run(self, tool_id, **kwargs):
        self._conn.execute("""
            INSERT INTO tool_runs
                (tool_id, scope_id, status, pid, command, tool_version,
                 started_at, settings, output_dir)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (_TOOL_ALIAS.get(tool_id, tool_id),
              kwargs.get("scope_id"), kwargs.get("status", "running"),
              kwargs.get("pid"), kwargs.get("command"),
              kwargs.get("tool_version"), kwargs.get("started_at"),
              json.dumps(kwargs.get("settings")) if kwargs.get("settings") else None,
              kwargs.get("output_dir")))
        self._conn.commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def update_tool_run(self, run_id, **kwargs):
        sets = []
        params = []
        for k in ("status", "returncode", "ended_at", "pid"):
            if k in kwargs:
                sets.append(f"{k}=?")
                params.append(kwargs[k])
        if sets:
            params.append(run_id)
            self._conn.execute(
                f"UPDATE tool_runs SET {','.join(sets)} WHERE id=?", params)
            self._conn.commit()

    def append_console(self, run_id, message, level=None, source=None):
        self._conn.execute(
            "INSERT INTO tool_console (run_id,timestamp,level,message,source) "
            "VALUES (?,?,?,?,?)",
            (run_id, datetime.now().isoformat(), level, message, source))
        self._conn.commit()

    # ── Scan Events ─────────────────────────────────────────────

    def log_event(self, level, message, tool_id=None, details=None):
        self._conn.execute(
            "INSERT INTO scan_events (timestamp,level,tool_id,message,details) "
            "VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), level, tool_id, message,
             json.dumps(details) if details else None))
        self._conn.commit()

    # ── OSINT ───────────────────────────────────────────────────

    def add_email(self, email, name=None, source=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO osint_emails (email,name,source,first_seen) "
            "VALUES (?,?,?,?)",
            (email, name, source, datetime.now().isoformat()))
        self._conn.commit()

    def add_subdomain(self, subdomain, source=None, is_alive=False):
        hn_row = self._conn.execute(
            "SELECT id FROM hostnames WHERE hostname=?",
            (subdomain,)).fetchone()
        hn_id = hn_row["id"] if hn_row else None
        self._conn.execute(
            "INSERT OR IGNORE INTO osint_subdomains "
            "(hostname_id,subdomain,source,first_seen,is_alive) "
            "VALUES (?,?,?,?,?)",
            (hn_id, subdomain, source, datetime.now().isoformat(),
             1 if is_alive else 0))
        self._conn.commit()

    def add_dns_record(self, hostname, rtype, value, ttl=None, source=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO dns_records "
            "(hostname,rtype,value,ttl,source,queried_at) VALUES (?,?,?,?,?,?)",
            (hostname, rtype, value, ttl, source,
             datetime.now().isoformat()))
        self._conn.commit()

    def add_certificate(self, port_id, **kwargs):
        self._conn.execute("""
            INSERT INTO certificates
                (port_id, serial, issuer, subject, not_before, not_after,
                 sans, sig_algorithm, key_type, key_bits, chain_depth,
                 is_self_signed, is_expired, raw_pem)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (port_id, kwargs.get("serial"), kwargs.get("issuer"),
              kwargs.get("subject"), kwargs.get("not_before"),
              kwargs.get("not_after"),
              json.dumps(kwargs.get("sans", [])),
              kwargs.get("sig_algorithm"), kwargs.get("key_type"),
              kwargs.get("key_bits"), kwargs.get("chain_depth"),
              1 if kwargs.get("is_self_signed") else 0,
              1 if kwargs.get("is_expired") else 0,
              kwargs.get("raw_pem")))
        self._conn.commit()

    def add_endpoint(self, host_id, port_id, path, **kwargs):
        self._conn.execute("""
            INSERT OR IGNORE INTO endpoints
                (host_id, port_id, path, method, from_spec, is_rogue,
                 auth_required, content_type, parameters, discovered_by,
                 first_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (host_id, port_id, path, kwargs.get("method"),
              1 if kwargs.get("from_spec") else 0,
              1 if kwargs.get("is_rogue") else 0,
              kwargs.get("auth_required"),
              kwargs.get("content_type"),
              json.dumps(kwargs.get("parameters")) if kwargs.get("parameters") else None,
              kwargs.get("discovered_by"),
              datetime.now().isoformat()))
        self._conn.commit()

    def add_wireless_network(self, bssid, **kwargs):
        self._conn.execute("""
            INSERT INTO wireless_networks
                (ssid, bssid, channel, frequency, encryption, cipher, auth,
                 signal_dbm, first_seen, last_seen, scope_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(bssid) DO UPDATE SET
                last_seen=excluded.last_seen,
                signal_dbm=COALESCE(excluded.signal_dbm,wireless_networks.signal_dbm)
        """, (kwargs.get("ssid"), bssid, kwargs.get("channel"),
              kwargs.get("frequency"), kwargs.get("encryption"),
              kwargs.get("cipher"), kwargs.get("auth"),
              kwargs.get("signal_dbm"),
              datetime.now().isoformat(), datetime.now().isoformat(),
              kwargs.get("scope_id")))
        self._conn.commit()

    # ── Migration: JSON → DB ────────────────────────────────────

    def ingest_findings_json(self, json_path, tool_id=None, scope=None):
        """Read a findings.json and bulk-insert into the database."""
        p = Path(json_path)
        if not p.exists():
            log.warning("ingest: %s not found", json_path)
            return 0
        with open(p) as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else data.get("findings", [])
        for f in items:
            if tool_id and not f.get("tool"):
                f["tool"] = tool_id
            if scope and not f.get("scope"):
                f["scope"] = scope
        ids = self.bulk_insert(items)
        log.info("Ingested %d findings from %s", len(ids), json_path)
        return len(ids)

    def ingest_action_items_json(self, json_path):
        p = Path(json_path)
        if not p.exists():
            return 0
        with open(p) as fh:
            items = json.load(fh)
        count = 0
        with self._tx():
            for item in items:
                self.insert_action_item(item)
                count += 1
        return count

    def migrate_legacy_project(self, project_dir, project_meta=None):
        """Migrate a full legacy project from JSON files to this database."""
        pd = Path(project_dir)
        meta = project_meta
        if not meta:
            meta_file = pd / "crucible_meta.json"
            if meta_file.exists():
                with open(meta_file) as fh:
                    meta = json.load(fh)

        if meta:
            self.set_meta("project_id", meta.get("id", ""))
            self.set_meta("project_name", meta.get("name", ""))
            self.set_meta("client_name", meta.get("client_name", ""))
            self.set_meta("client_short", meta.get("client_short", ""))
            self.set_meta("engagement_id", meta.get("engagement_id", ""))

            for scope_name in (meta.get("active_scopes") or []):
                self.ensure_scope(scope_name)

            for ex in (meta.get("scope_definition", {}).get("exclusions") or []):
                if ex:
                    self.add_exclusion(ex.strip(), "ip")

        total = 0
        tool_dirs = (meta or {}).get("tool_dirs", {})
        scope_tool_dirs = (meta or {}).get("scope_tool_dirs", {})

        loaded = set()
        for scope_name, dirs in scope_tool_dirs.items():
            for tid, td in dirs.items():
                if (tid, td) in loaded:
                    continue
                loaded.add((tid, td))
                fp = Path(td) / "findings.json"
                if fp.exists():
                    total += self.ingest_findings_json(
                        str(fp), tool_id=tid, scope=scope_name)

        for tid, td in tool_dirs.items():
            if (tid, td) in loaded:
                continue
            loaded.add((tid, td))
            fp = Path(td) / "findings.json"
            if fp.exists():
                total += self.ingest_findings_json(str(fp), tool_id=tid)

        ai_path = pd / "action_items.json"
        if ai_path.exists():
            self.ingest_action_items_json(str(ai_path))

        self.recompute_intelligence()
        log.info("Legacy migration complete: %d findings ingested", total)
        return total

    # ── Export: DB → JSON ───────────────────────────────────────

    def export_findings_json(self, output_path, include_fp=False):
        """Export all findings to a legacy-format findings.json."""
        page = 1
        all_findings = []
        while True:
            result = self.query_findings(
                page=page, per_page=1000, include_fp=include_fp)
            all_findings.extend(result["findings"])
            if page >= result["pages"]:
                break
            page += 1
        with open(output_path, "w") as fh:
            json.dump(all_findings, fh, indent=2, default=str)
        log.info("Exported %d findings to %s", len(all_findings), output_path)
        return len(all_findings)

    # ── Maintenance ─────────────────────────────────────────────

    def vacuum(self):
        self._conn.execute("VACUUM")

    def integrity_check(self):
        result = self._conn.execute("PRAGMA integrity_check").fetchone()
        return result[0] if result else "unknown"

    def table_stats(self):
        tables = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'findings_fts%' "
            "ORDER BY name").fetchall()
        stats = {}
        for t in tables:
            name = t["name"]
            count = self._conn.execute(
                f"SELECT COUNT(*) as c FROM [{name}]").fetchone()["c"]
            if count > 0:
                stats[name] = count
        return stats


# ═══════════════════════════════════════════════════════════════
#  Self-Test
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import tempfile, os

    print("pr0t31n_findings_db self-test")
    print(f"Schema version: {SCHEMA_VERSION}")

    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        db = FindingsDB(db_path)

        print(f"\nCreated DB at {db_path}")
        print(f"Integrity: {db.integrity_check()}")

        sid = db.ensure_scope("internal")
        print(f"Scope 'internal' id={sid}")

        cid = db.ensure_category("SSL/TLS", description="TLS/SSL issues")
        print(f"Category 'SSL/TLS' id={cid}")

        test_findings = [
            {"title": "SSL/TLS Vulnerability: TLSv1.0 is Deprecated",
             "tool": "scattershot3", "scope": "internal",
             "risk": "MEDIUM", "ip": "10.0.0.1", "port": 443,
             "service": "https", "hostname": "web1.example.com",
             "description": "TLSv1.0 is deprecated",
             "remediation": "Disable TLSv1.0", "datetime": "2026-10-01T12:00:00",
             "cwe": ["CWE-326"], "cves": "CVE-2011-3389",
             "nist_800_53": ["SC-8", "SC-13"]},
            {"title": "SSL/TLS Vulnerability: TLSv1.0 is Deprecated",
             "tool": "scattershot3", "scope": "internal",
             "risk": "MEDIUM", "ip": "10.0.0.2", "port": 443,
             "service": "https",
             "description": "TLSv1.0 is deprecated",
             "remediation": "Disable TLSv1.0", "datetime": "2026-10-01T12:01:00"},
            {"title": "SMB Vulnerability: SMBv1 Enabled",
             "tool": "scattershot3", "scope": "internal",
             "risk": "HIGH", "ip": "10.0.0.3", "port": 445,
             "service": "smb",
             "description": "SMBv1 is enabled",
             "remediation": "Disable SMBv1", "datetime": "2026-10-01T12:02:00",
             "mitre_attack": [{"technique": "T1210", "name": "Exploitation of Remote Services",
                               "tactic_id": "TA0008", "tactic": "Lateral Movement"}]},
            {"title": "SQL Injection Found",
             "tool": "fracture", "scope": "internal",
             "risk": "CRITICAL", "ip": "10.0.0.1", "port": 8080,
             "description": "SQL injection in login form",
             "remediation": "Parameterize queries", "datetime": "2026-10-01T13:00:00",
             "cwe": ["CWE-89"], "owasp": "Injection"},
        ]

        ids = db.bulk_insert(test_findings)
        print(f"\nInserted {len(ids)} findings (2nd TLS deduped → {len(set(ids))} unique)")

        summary = db.get_summary()
        print(f"\nSummary: {summary}")

        page = db.query_findings(page=1, per_page=10)
        print(f"\nQuery: {page['total']} total, page {page['page']}/{page['pages']}")
        for f in page["findings"]:
            print(f"  [{f['risk']}] {f['title']} — {f['affected']} "
                  f"({f['location_count']} locations)")

        detail = db.get_finding(ids[0])
        print(f"\nDetail for {ids[0]}:")
        print(f"  CWE: {detail.get('cwe')}")
        print(f"  CVEs: {detail.get('cves')}")
        print(f"  Compliance: {detail.get('compliance')}")

        db.rebuild_fts()
        sr = db.search("TLS deprecated")
        print(f"\nFTS search 'TLS deprecated': {sr['total']} results")

        db.compute_host_profiles()
        profile = db.get_host_profile("10.0.0.1")
        print(f"\nHost profile 10.0.0.1: {profile['total_findings']} findings, "
              f"{len(profile['ports'])} ports, hostnames={profile['hostnames']}")

        cross = db.get_cross_tool_findings("10.0.0.1")
        print(f"\nCross-tool for 10.0.0.1: {len(cross)} findings from "
              f"{len(set(c['tool_id'] for c in cross))} tools")

        db.compute_attack_surface()
        surface = db.get_attack_surface()
        print(f"\nAttack surface: {surface['total']} entries")

        db.compute_compliance_gaps()
        gaps = db.get_compliance_gaps("nist_800_53")
        print(f"\nNIST 800-53 gaps: {len(gaps)}")

        cat_summary = db.get_category_summary()
        print(f"\nCategory summary: {len(cat_summary)} categories")
        for cs in cat_summary:
            print(f"  {cs['category']}: {cs['count']} "
                  f"(C:{cs['critical']} H:{cs['high']} M:{cs['medium']})")

        multi = db.get_multi_tool_hosts()
        print(f"\nMulti-tool hosts: {len(multi)}")
        for h in multi:
            print(f"  {h['ip']}: {h['tools']} tools ({h['which_tools']}), "
                  f"{h['total_findings']} findings")

        db.take_trend_snapshot()
        trend = db.get_trend(hours=1)
        print(f"\nTrend snapshots (1h): {len(trend)}")

        stats = db.table_stats()
        print(f"\nTable stats (non-empty):")
        for name, count in sorted(stats.items()):
            print(f"  {name}: {count}")

        db_size = os.path.getsize(db_path)
        print(f"\nDB size: {db_size:,} bytes")
        print(f"Integrity: {db.integrity_check()}")

        db.close()
        print("\nAll tests passed.")
