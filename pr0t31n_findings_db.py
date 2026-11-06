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

SCHEMA_VERSION = "1.1"
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

-- ================================================================
-- Phase 8: Intelligence tables (added in schema v1.1)
-- ================================================================

-- =============================================================================
-- Phase 8: Webapp + Cross-Tool Tables
-- FindingsDB schema extension for Fracture, Siphon, SS3, and Crucible
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Fracture — Structure Maps
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS structure_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_run_id INTEGER REFERENCES tool_runs(id),
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_type TEXT,
    content_length INTEGER,
    redirect_url TEXT,
    depth INTEGER DEFAULT 0,
    source TEXT,  -- crawl/brute/sitemap/robots
    response_time_ms INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_structure_urls_url ON structure_urls(url);
CREATE INDEX IF NOT EXISTS idx_structure_urls_status ON structure_urls(status_code);

CREATE TABLE IF NOT EXISTS structure_params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL REFERENCES structure_urls(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    param_type TEXT,  -- query/body/cookie/header
    value TEXT,
    location TEXT  -- url/body/cookie/header
);

CREATE TABLE IF NOT EXISTS structure_forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL REFERENCES structure_urls(id) ON DELETE CASCADE,
    action TEXT,
    method TEXT DEFAULT 'POST',
    enctype TEXT,
    input_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS structure_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL REFERENCES structure_urls(id) ON DELETE CASCADE,
    direction TEXT NOT NULL,  -- request/response
    name TEXT NOT NULL,
    value TEXT
);

-- ---------------------------------------------------------------------------
-- Access Matrix (Fracture + Siphon)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_matrix_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    endpoint_path TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    role TEXT NOT NULL,
    expected_status INTEGER,
    actual_status INTEGER,
    result TEXT,  -- allowed/denied/error
    auth_type TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_access_matrix_endpoint ON access_matrix_entries(endpoint_path);
CREATE INDEX IF NOT EXISTS idx_access_matrix_role ON access_matrix_entries(role);

-- ---------------------------------------------------------------------------
-- Auth Intel (Fracture + Siphon)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    session_name TEXT,
    auth_type TEXT,  -- cookie/bearer/basic/oauth/apikey
    valid INTEGER DEFAULT 1,
    username TEXT,
    role TEXT,
    token_preview TEXT,  -- first 20 chars only, never full token
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES auth_sessions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    domain TEXT,
    path TEXT DEFAULT '/',
    secure INTEGER DEFAULT 0,
    httponly INTEGER DEFAULT 0,
    samesite TEXT,
    expires_at TEXT
);

-- ---------------------------------------------------------------------------
-- Screenshots
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    url TEXT,
    ip TEXT,
    port INTEGER,
    file_path TEXT NOT NULL,  -- relative to run dir
    thumbnail_path TEXT,
    width INTEGER,
    height INTEGER,
    file_size INTEGER,
    captured_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_screenshots_ip ON screenshots(ip);

-- ---------------------------------------------------------------------------
-- Target Profiles (Fracture)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS target_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    target_url TEXT NOT NULL,
    resolved_ip TEXT,
    server_header TEXT,
    technologies_json TEXT DEFAULT '[]',
    cms TEXT,
    framework TEXT,
    language TEXT,
    waf_detected TEXT,
    cdn_detected TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- Crucible Logs + Errors
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS crucible_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level TEXT DEFAULT 'INFO',
    tool TEXT,
    message TEXT NOT NULL,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_crucible_logs_ts ON crucible_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_crucible_logs_level ON crucible_logs(level);

CREATE TABLE IF NOT EXISTS crucible_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level TEXT DEFAULT 'ERROR',
    tool TEXT,
    message TEXT NOT NULL,
    traceback TEXT,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_crucible_errors_ts ON crucible_errors(timestamp);

-- ---------------------------------------------------------------------------
-- Console Output (chunked)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS console_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    text TEXT NOT NULL,
    byte_offset INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_console_tool ON console_chunks(tool_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_console_tool_chunk ON console_chunks(tool_id, chunk_index);

-- ---------------------------------------------------------------------------
-- Output Files Index
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS output_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    extension TEXT,
    file_size INTEGER,
    mtime TEXT,
    content_type TEXT,
    UNIQUE(path)
);
CREATE INDEX IF NOT EXISTS idx_output_files_tool ON output_files(tool);
CREATE INDEX IF NOT EXISTS idx_output_files_ext ON output_files(extension);

-- ---------------------------------------------------------------------------
-- Hostname Intel + Server Roles (SS3)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hostname_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ip TEXT,
    environment_tag TEXT,  -- prod/staging/dev/test
    application_tag TEXT,
    hardware_tag TEXT,
    role_tag TEXT,
    confidence REAL DEFAULT 0.0,
    UNIQUE(hostname)
);

CREATE TABLE IF NOT EXISTS server_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    role TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    evidence TEXT,
    UNIQUE(ip, role)
);

-- ============================================================
-- OSINT Extended (OSift)
-- ============================================================

CREATE TABLE IF NOT EXISTS osint_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    registrar TEXT,
    creation_date TEXT,
    expiry_date TEXT,
    nameservers_json TEXT DEFAULT '[]',
    status TEXT,
    dnssec INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS osint_whois (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER REFERENCES osint_domains(id) ON DELETE CASCADE,
    raw_text TEXT,
    registrant_org TEXT,
    registrant_country TEXT,
    admin_email TEXT,
    tech_email TEXT,
    parsed_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS osint_phones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    person_id INTEGER REFERENCES osint_people(id),
    source TEXT,
    phone_type TEXT,
    country_code TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_osint_phones_person ON osint_phones(person_id);

CREATE TABLE IF NOT EXISTS osint_wayback_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    timestamp TEXT,
    status_code INTEGER,
    mime_type TEXT,
    length INTEGER
);
CREATE INDEX IF NOT EXISTS idx_wayback_domain ON osint_wayback_urls(domain);

CREATE TABLE IF NOT EXISTS osint_typosquats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    variant TEXT NOT NULL,
    fuzzer TEXT,
    dns_a TEXT,
    dns_aaaa TEXT,
    dns_mx TEXT,
    dns_ns TEXT,
    registered INTEGER DEFAULT 0,
    ssdeep_score INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_typosquat_domain ON osint_typosquats(domain);

-- ============================================================
-- Firewall (Bastion)
-- ============================================================

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_number INTEGER,
    policy TEXT,
    source_zone TEXT,
    dest_zone TEXT,
    source_addr TEXT,
    dest_addr TEXT,
    service TEXT,
    port TEXT,
    protocol TEXT,
    action TEXT NOT NULL,
    hits INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    comment TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_fw_rules_action ON firewall_rules(action);
CREATE INDEX IF NOT EXISTS idx_fw_rules_zones ON firewall_rules(source_zone, dest_zone);

CREATE TABLE IF NOT EXISTS firewall_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    zone_type TEXT,
    interfaces_json TEXT DEFAULT '[]',
    description TEXT
);

CREATE TABLE IF NOT EXISTS firewall_compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id TEXT NOT NULL,
    check_name TEXT NOT NULL,
    category TEXT,
    status TEXT NOT NULL,
    severity TEXT,
    details TEXT,
    remediation TEXT,
    framework TEXT,
    UNIQUE(check_id)
);

-- ============================================================
-- Cloud (Forge)
-- ============================================================

CREATE TABLE IF NOT EXISTS cloud_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arn TEXT UNIQUE,
    resource_type TEXT NOT NULL,
    region TEXT,
    name TEXT,
    state TEXT,
    public INTEGER DEFAULT 0,
    tags_json TEXT DEFAULT '{}',
    config_json TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cloud_res_type ON cloud_resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_cloud_res_region ON cloud_resources(region);
CREATE INDEX IF NOT EXISTS idx_cloud_res_public ON cloud_resources(public);

CREATE TABLE IF NOT EXISTS cloud_iam_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arn TEXT UNIQUE,
    name TEXT NOT NULL,
    policy_type TEXT,
    attached_to_json TEXT DEFAULT '[]',
    permissions_json TEXT DEFAULT '{}',
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cloud_iam_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arn TEXT UNIQUE,
    name TEXT NOT NULL,
    trust_policy_json TEXT DEFAULT '{}',
    attached_policies_json TEXT DEFAULT '[]',
    is_service_role INTEGER DEFAULT 0,
    last_used TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cloud_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL UNIQUE,
    region TEXT,
    resource_count INTEGER DEFAULT 0,
    public_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    risk_summary_json TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);

-- ============================================================
-- Traffic (Trawler)
-- ============================================================

CREATE TABLE IF NOT EXISTS traffic_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    packets INTEGER DEFAULT 0,
    start_time TEXT,
    end_time TEXT,
    flags TEXT,
    application TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic_conversations(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst ON traffic_conversations(dst_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_proto ON traffic_conversations(protocol);

CREATE TABLE IF NOT EXISTS traffic_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT,
    numeric_value REAL,
    category TEXT
);

-- =============================================================================
-- Phase 8: Specialized Tool Tables
-- Database Audit (Auger), Endpoint Security (Dredge), Mobile (Quill),
-- File Analysis (Isotope)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database Audit (Auger)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS db_schemas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    db_type TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    schema_name TEXT NOT NULL,
    table_count INTEGER DEFAULT 0,
    total_rows INTEGER,
    size_bytes INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(host, port, schema_name)
);

CREATE TABLE IF NOT EXISTS db_tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_id INTEGER REFERENCES db_schemas(id) ON DELETE CASCADE,
    table_name TEXT NOT NULL,
    row_count INTEGER,
    column_count INTEGER,
    has_pii INTEGER DEFAULT 0,
    has_sensitive INTEGER DEFAULT 0,
    engine TEXT
);
CREATE INDEX IF NOT EXISTS idx_db_tables_schema ON db_tables(schema_id);

CREATE TABLE IF NOT EXISTS db_columns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_id INTEGER REFERENCES db_tables(id) ON DELETE CASCADE,
    column_name TEXT NOT NULL,
    data_type TEXT,
    is_nullable INTEGER DEFAULT 1,
    is_primary INTEGER DEFAULT 0,
    is_indexed INTEGER DEFAULT 0,
    pii_type TEXT,
    sample_value TEXT
);

CREATE TABLE IF NOT EXISTS db_privileges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,
    port INTEGER,
    grantee TEXT NOT NULL,
    privilege TEXT NOT NULL,
    target_schema TEXT,
    target_table TEXT,
    is_grantable INTEGER DEFAULT 0,
    UNIQUE(host, port, grantee, privilege, target_schema, target_table)
);

-- ---------------------------------------------------------------------------
-- Endpoint Security (Dredge)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS endpoint_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT,
    publisher TEXT,
    install_date TEXT,
    install_path TEXT,
    is_security_tool INTEGER DEFAULT 0,
    is_outdated INTEGER DEFAULT 0,
    latest_version TEXT,
    cve_count INTEGER DEFAULT 0,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS endpoint_hardening (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id TEXT NOT NULL UNIQUE,
    category TEXT,
    description TEXT,
    status TEXT NOT NULL,
    severity TEXT,
    current_value TEXT,
    expected_value TEXT,
    remediation TEXT,
    framework TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_name TEXT,
    status TEXT NOT NULL,
    evidence TEXT,
    remediation TEXT,
    UNIQUE(framework, control_id)
);

CREATE TABLE IF NOT EXISTS endpoint_ad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_category TEXT NOT NULL,
    check_name TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT,
    details TEXT,
    affected_objects_json TEXT DEFAULT '[]',
    remediation TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_browsers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    browser_name TEXT NOT NULL,
    version TEXT,
    profile_count INTEGER DEFAULT 0,
    extensions_json TEXT DEFAULT '[]',
    saved_passwords INTEGER DEFAULT 0,
    autofill_data INTEGER DEFAULT 0,
    sync_enabled INTEGER DEFAULT 0,
    security_settings_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS endpoint_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    details_json TEXT DEFAULT '{}',
    UNIQUE(category, key)
);

-- ---------------------------------------------------------------------------
-- Mobile (Quill)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS mobile_components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_type TEXT NOT NULL,
    name TEXT NOT NULL,
    exported INTEGER DEFAULT 0,
    permission TEXT,
    description TEXT,
    risk TEXT
);
CREATE INDEX IF NOT EXISTS idx_mobile_comp_type ON mobile_components(component_type);

CREATE TABLE IF NOT EXISTS mobile_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission TEXT NOT NULL UNIQUE,
    protection_level TEXT,
    group_name TEXT,
    is_custom INTEGER DEFAULT 0,
    used_by_count INTEGER DEFAULT 0,
    description TEXT,
    risk TEXT
);

CREATE TABLE IF NOT EXISTS mobile_data_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    data_type TEXT,
    encrypted INTEGER DEFAULT 0,
    protocol TEXT,
    method TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS mobile_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    host TEXT,
    content_type TEXT,
    request_size INTEGER,
    response_size INTEGER,
    status_code INTEGER,
    encrypted INTEGER DEFAULT 1,
    certificate_valid INTEGER,
    pinning_detected INTEGER DEFAULT 0,
    timestamp TEXT
);
CREATE INDEX IF NOT EXISTS idx_mobile_traffic_host ON mobile_traffic(host);

-- ---------------------------------------------------------------------------
-- File Analysis (Isotope)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS isotope_strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    string_type TEXT,
    offset INTEGER,
    encoding TEXT DEFAULT 'ascii',
    context TEXT,
    is_interesting INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_isotope_strings_type ON isotope_strings(string_type);

CREATE TABLE IF NOT EXISTS isotope_properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT,
    category TEXT,
    UNIQUE(key)
);

CREATE TABLE IF NOT EXISTS isotope_entropy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    section_name TEXT,
    offset INTEGER,
    length INTEGER,
    entropy REAL NOT NULL,
    is_packed INTEGER DEFAULT 0,
    is_encrypted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS isotope_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_type TEXT NOT NULL,
    value_preview TEXT,
    file_path TEXT,
    line_number INTEGER,
    confidence TEXT DEFAULT 'medium',
    context TEXT
);

CREATE TABLE IF NOT EXISTS isotope_code (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    language TEXT,
    file_path TEXT,
    function_name TEXT,
    vulnerability_type TEXT,
    severity TEXT,
    line_number INTEGER,
    code_snippet TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS isotope_binary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT,
    category TEXT,
    details_json TEXT DEFAULT '{}',
    UNIQUE(category, key)
);

CREATE TABLE IF NOT EXISTS isotope_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    confidence TEXT DEFAULT 'medium',
    threat_name TEXT,
    first_seen TEXT,
    UNIQUE(ioc_type, value)
);

CREATE TABLE IF NOT EXISTS isotope_contents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    file_type TEXT,
    size INTEGER,
    modified_at TEXT,
    entropy REAL,
    is_encrypted INTEGER DEFAULT 0,
    hash_sha256 TEXT
);

CREATE TABLE IF NOT EXISTS isotope_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT,
    source TEXT,
    UNIQUE(key, source)
);
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


_FTS_SPECIAL = re.compile(r'[()":*^~{}|\\]')

def _sanitize_fts_query(raw):
    """Sanitize a user search string for FTS5 MATCH.

    Wraps each word in double-quotes so FTS5 special characters don't
    cause parse errors, then joins with implicit AND.
    """
    raw = raw.strip()
    if not raw:
        return ""
    cleaned = _FTS_SPECIAL.sub(" ", raw)
    tokens = cleaned.split()
    if not tokens:
        return ""
    return " ".join(f'"{t}"' for t in tokens if t)


# ═══════════════════════════════════════════════════════════════
#  FindingsDB
# ═══════════════════════════════════════════════════════════════

class FindingsDB:
    """SQLite-backed findings store."""

    def __init__(self, db_path, readonly=False):
        self.db_path = str(db_path)
        self._readonly = readonly
        self._in_tx = False
        flags = sqlite3.PARSE_DECLTYPES
        if readonly:
            self._conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro", uri=True, detect_types=flags,
                check_same_thread=False)
        else:
            self._conn = sqlite3.connect(
                self.db_path, detect_types=flags, check_same_thread=False)
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

    def _commit(self):
        if not self._in_tx:
            self._conn.commit()

    @contextmanager
    def _tx(self):
        self._conn.execute("BEGIN")
        self._in_tx = True
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        finally:
            self._in_tx = False

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
            self._commit()
        migrated = self._conn.execute(
            "SELECT value FROM meta WHERE key='category_backfill'").fetchone()
        if not migrated:
            n = self.backfill_categories_from_titles()
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key,value) VALUES "
                "('category_backfill',?)", (str(n),))
            self._commit()

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
        self._commit()

    # ── Meta ────────────────────────────────────────────────────

    def set_meta(self, key, value):
        self._conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self._commit()

    def get_meta(self, key, default=None):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # ── Scope CRUD ──────────────────────────────────────────────

    def ensure_scope(self, name, description=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO scopes (name,description) VALUES (?,?)",
            (name, description))
        if not self._in_tx:
            self._commit()
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
        if not self._in_tx:
            self._commit()
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
        if not self._in_tx:
            self._commit()
        return self._conn.execute(
            "SELECT id FROM categories WHERE name=?", (name,)).fetchone()["id"]

    def get_category_id(self, name):
        if not name:
            return None
        row = self._conn.execute(
            "SELECT id FROM categories WHERE name=?", (name,)).fetchone()
        return row["id"] if row else None

    def backfill_categories_from_titles(self):
        """Populate category_id for findings where it is NULL by extracting
        the prefix before the first colon in the title."""
        rows = self._conn.execute(
            "SELECT id, title FROM findings WHERE category_id IS NULL"
        ).fetchall()
        n = 0
        for row in rows:
            title = (row["title"] or "").strip()
            if ":" not in title:
                continue
            cat_name = title.split(":", 1)[0].strip()
            if not cat_name:
                continue
            cid = self.ensure_category(cat_name)
            self._conn.execute(
                "UPDATE findings SET category_id=?, updated_at=? WHERE id=?",
                (cid, datetime.now().isoformat(), row["id"]))
            n += 1
        self._commit()
        return n

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
        self._commit()
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
        self._commit()
        return hn_id

    # ── Port / Service CRUD ─────────────────────────────────────

    def ensure_port(self, host_id, port_num, protocol="tcp", state="open"):
        self._conn.execute(
            "INSERT INTO ports (host_id,port,protocol,state) VALUES (?,?,?,?) "
            "ON CONFLICT(host_id,port,protocol) DO UPDATE SET "
            "state=COALESCE(excluded.state,ports.state)",
            (host_id, port_num, protocol, state))
        self._commit()
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
        self._commit()

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
        title = (f.get("title") or "").strip()
        if not title:
            log.debug("insert_finding: rejected empty-title finding (tool=%s)",
                      f.get("tool", "?"))
            return None
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
                self._commit()
            return eid

        cat_name = (f.get("remediation_category") or
                    f.get("category") or "").strip()
        if not cat_name:
            _title = (f.get("title") or "").strip()
            if ":" in _title:
                cat_name = _title.split(":", 1)[0].strip()
        if cat_name:
            self.ensure_category(cat_name)
        cat_id = self.get_category_id(cat_name)
        cat_entry_id = (f.get("catalogue_id") or "").strip() or None
        if cat_entry_id:
            self._conn.execute(
                "INSERT OR IGNORE INTO catalogue_entries (id, tool_id, title, risk_id) "
                "VALUES (?,?,?,?)",
                (cat_entry_id, tool_id, f.get("title", ""), rid))

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
            self._commit()
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
            safe_search = _sanitize_fts_query(search)
            if safe_search:
                fts_count = self._conn.execute(
                    "SELECT COUNT(*) FROM findings_fts_content"
                ).fetchone()[0]
                if fts_count == 0:
                    self.rebuild_fts()
                where.append(
                    "f.id IN (SELECT finding_id FROM findings_fts_content "
                    "WHERE rowid IN (SELECT rowid FROM findings_fts "
                    "WHERE findings_fts MATCH ?))")
                params.append(safe_search)

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

        if locs:
            primary = locs[0]
            d.setdefault("ip", primary["ip"] or "")
            d.setdefault("port", primary["port"] or 0)
            d.setdefault("hostname", primary["hostname"] or "")
            d.setdefault("service", primary["service"] or "")

        of_parts = []
        for loc in locs:
            if loc["output_file"]:
                of_parts.append(loc["output_file"])
        if of_parts:
            d["output_file"] = "\n".join(of_parts)

        for _jf in ("exploit_details", "mitre_attack", "cwe",
                     "searchsploit_terms", "metasploit_modules"):
            raw = d.get(_jf)
            if isinstance(raw, str):
                try:
                    d[_jf] = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    d[_jf] = []

        for _bf in ("exploitdb", "metasploit", "kev", "accepted",
                     "is_false_positive", "is_oos", "api_from_spec",
                     "is_rogue_endpoint"):
            if _bf in d and isinstance(d[_bf], int):
                d[_bf] = bool(d[_bf])

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
        self._commit()

    def recover_false_positive(self, finding_id):
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE findings SET is_false_positive=0, fp_marked_at=NULL, "
            "fp_reason=NULL, updated_at=? WHERE id=?",
            (now, finding_id))
        self._commit()

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
        self._commit()
        return True

    # ── Notes ───────────────────────────────────────────────────

    def add_note(self, finding_id, note, author=None):
        self._conn.execute(
            "INSERT INTO finding_notes (finding_id,note,author) VALUES (?,?,?)",
            (finding_id, note, author))
        self._commit()

    # ── Tags ────────────────────────────────────────────────────

    def ensure_tag(self, name, color=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO tags (name,color) VALUES (?,?)",
            (name, color))
        self._commit()
        return self._conn.execute(
            "SELECT id FROM tags WHERE name=?", (name,)).fetchone()["id"]

    def tag_finding(self, finding_id, tag_name, color=None):
        tid = self.ensure_tag(tag_name, color)
        self._conn.execute(
            "INSERT OR IGNORE INTO finding_tags (finding_id,tag_id) "
            "VALUES (?,?)", (finding_id, tid))
        self._commit()

    def tag_host(self, host_id, tag_name, color=None):
        tid = self.ensure_tag(tag_name, color)
        self._conn.execute(
            "INSERT OR IGNORE INTO host_tags (host_id,tag_id) "
            "VALUES (?,?)", (host_id, tid))
        self._commit()

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
        self._commit()
        log.info("FTS index rebuilt")

    def search(self, query, page=1, per_page=100):
        safe_q = _sanitize_fts_query(query)
        if not safe_q:
            return {"findings": [], "total": 0, "page": page,
                    "per_page": per_page, "pages": 0}
        count = self._conn.execute(
            "SELECT COUNT(DISTINCT finding_id) as total "
            "FROM findings_fts_content WHERE rowid IN "
            "(SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?)",
            (safe_q,)).fetchone()["total"]
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
        """, (safe_q, per_page, offset)).fetchall()
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
        self._commit()
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
        self._commit()
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
        self._commit()

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
        self._commit()

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
        self._commit()

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
        self._commit()
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
        self._commit()
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
        self._commit()

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
        self._commit()
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
            self._commit()

    def append_console(self, run_id, message, level=None, source=None):
        self._conn.execute(
            "INSERT INTO tool_console (run_id,timestamp,level,message,source) "
            "VALUES (?,?,?,?,?)",
            (run_id, datetime.now().isoformat(), level, message, source))
        self._commit()

    # ── Scan Events ─────────────────────────────────────────────

    def log_event(self, level, message, tool_id=None, details=None):
        self._conn.execute(
            "INSERT INTO scan_events (timestamp,level,tool_id,message,details) "
            "VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), level, tool_id, message,
             json.dumps(details) if details else None))
        self._commit()

    # ── OSINT ───────────────────────────────────────────────────

    def add_email(self, email, name=None, source=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO osint_emails (email,name,source,first_seen) "
            "VALUES (?,?,?,?)",
            (email, name, source, datetime.now().isoformat()))
        self._commit()

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
        self._commit()

    def add_dns_record(self, hostname, rtype, value, ttl=None, source=None):
        self._conn.execute(
            "INSERT OR IGNORE INTO dns_records "
            "(hostname,rtype,value,ttl,source,queried_at) VALUES (?,?,?,?,?,?)",
            (hostname, rtype, value, ttl, source,
             datetime.now().isoformat()))
        self._commit()

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
        self._commit()

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
        self._commit()

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
        self._commit()

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
        self.set_meta("migration_status", "complete")
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

    # ── Phase 8: WebApp + Cross-Cutting Intelligence ──────────────

    # =========================================================================
    # Phase 8: Webapp + Cross-Tool Methods
    # =========================================================================

    # --- Column whitelists for safe ORDER BY -----------------------------------

    _STRUCTURE_URLS_COLS = frozenset({
        "id", "tool_run_id", "url", "method", "status_code", "content_type",
        "content_length", "redirect_url", "depth", "source", "response_time_ms",
        "created_at",
    })
    _STRUCTURE_PARAMS_COLS = frozenset({
        "id", "url_id", "name", "param_type", "value", "location",
    })
    _STRUCTURE_FORMS_COLS = frozenset({
        "id", "url_id", "action", "method", "enctype", "input_count",
    })
    _STRUCTURE_HEADERS_COLS = frozenset({
        "id", "url_id", "direction", "name", "value",
    })
    _ACCESS_MATRIX_COLS = frozenset({
        "id", "tool", "endpoint_path", "method", "role", "expected_status",
        "actual_status", "result", "auth_type", "notes", "created_at",
    })
    _AUTH_SESSIONS_COLS = frozenset({
        "id", "tool", "session_name", "auth_type", "valid", "username",
        "role", "token_preview", "expires_at", "created_at",
    })
    _AUTH_COOKIES_COLS = frozenset({
        "id", "session_id", "name", "domain", "path", "secure", "httponly",
        "samesite", "expires_at",
    })
    _SCREENSHOTS_COLS = frozenset({
        "id", "tool", "url", "ip", "port", "file_path", "thumbnail_path",
        "width", "height", "file_size", "captured_at",
    })
    _TARGET_PROFILES_COLS = frozenset({
        "id", "tool", "target_url", "resolved_ip", "server_header",
        "technologies_json", "cms", "framework", "language", "waf_detected",
        "cdn_detected", "created_at",
    })
    _CRUCIBLE_LOGS_COLS = frozenset({
        "id", "timestamp", "level", "tool", "message", "extra_json",
    })
    _CRUCIBLE_ERRORS_COLS = frozenset({
        "id", "timestamp", "level", "tool", "message", "traceback", "extra_json",
    })
    _CONSOLE_CHUNKS_COLS = frozenset({
        "id", "tool_id", "chunk_index", "text", "byte_offset", "created_at",
    })
    _OUTPUT_FILES_COLS = frozenset({
        "id", "tool", "path", "filename", "extension", "file_size", "mtime",
        "content_type",
    })
    _HOSTNAME_INTEL_COLS = frozenset({
        "id", "hostname", "ip", "environment_tag", "application_tag",
        "hardware_tag", "role_tag", "confidence",
    })
    _SERVER_ROLES_COLS = frozenset({
        "id", "ip", "role", "confidence", "evidence",
    })

    def _safe_sort(self, col, whitelist):
        """Return col if it is in the whitelist, else 'id'."""
        return col if col in whitelist else "id"

    # =========================================================================
    # Structure URLs
    # =========================================================================

    def add_structure_url(self, url, method="GET", status_code=None,
                          content_type=None, content_length=None,
                          redirect_url=None, depth=0, source=None,
                          response_time_ms=None, tool_run_id=None):
        self._conn.execute(
            "INSERT INTO structure_urls (tool_run_id, url, method, status_code, "
            "content_type, content_length, redirect_url, depth, source, "
            "response_time_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool_run_id, url, method, status_code, content_type,
             content_length, redirect_url, depth, source, response_time_ms))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_urls(self, page=1, per_page=50, status_code=None,
                             source=None, method=None, search=None,
                             tool_run_id=None, sort="id", order="asc"):
        where, params = [], []
        if status_code is not None:
            where.append("status_code = ?"); params.append(status_code)
        if source:
            where.append("source = ?"); params.append(source)
        if method:
            where.append("method = ?"); params.append(method)
        if tool_run_id is not None:
            where.append("tool_run_id = ?"); params.append(tool_run_id)
        if search:
            where.append("url LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._STRUCTURE_URLS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM structure_urls {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM structure_urls {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM structure_urls LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_structure_urls(self, tool_run_id=None):
        if tool_run_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_urls WHERE tool_run_id = ?",
                (tool_run_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_urls").fetchone()[0]

    # =========================================================================
    # Structure Params
    # =========================================================================

    def add_structure_param(self, url_id, name, param_type=None, value=None,
                            location=None):
        self._conn.execute(
            "INSERT INTO structure_params (url_id, name, param_type, value, "
            "location) VALUES (?, ?, ?, ?, ?)",
            (url_id, name, param_type, value, location))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_params(self, page=1, per_page=50, url_id=None,
                               param_type=None, search=None,
                               sort="id", order="asc"):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if param_type:
            where.append("param_type = ?"); params.append(param_type)
        if search:
            where.append("name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._STRUCTURE_PARAMS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM structure_params {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM structure_params {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM structure_params LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_structure_params(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_params WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_params").fetchone()[0]

    # =========================================================================
    # Structure Forms
    # =========================================================================

    def add_structure_form(self, url_id, action=None, method="POST",
                           enctype=None, input_count=0):
        self._conn.execute(
            "INSERT INTO structure_forms (url_id, action, method, enctype, "
            "input_count) VALUES (?, ?, ?, ?, ?)",
            (url_id, action, method, enctype, input_count))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_forms(self, page=1, per_page=50, url_id=None,
                              method=None, sort="id", order="asc"):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if method:
            where.append("method = ?"); params.append(method)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._STRUCTURE_FORMS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM structure_forms {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM structure_forms {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM structure_forms LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_structure_forms(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_forms WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_forms").fetchone()[0]

    # =========================================================================
    # Structure Headers
    # =========================================================================

    def add_structure_header(self, url_id, direction, name, value=None):
        self._conn.execute(
            "INSERT INTO structure_headers (url_id, direction, name, value) "
            "VALUES (?, ?, ?, ?)",
            (url_id, direction, name, value))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_structure_headers(self, page=1, per_page=50, url_id=None,
                                direction=None, search=None,
                                sort="id", order="asc"):
        where, params = [], []
        if url_id is not None:
            where.append("url_id = ?"); params.append(url_id)
        if direction:
            where.append("direction = ?"); params.append(direction)
        if search:
            where.append("name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._STRUCTURE_HEADERS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM structure_headers {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM structure_headers {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM structure_headers LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_structure_headers(self, url_id=None):
        if url_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM structure_headers WHERE url_id = ?",
                (url_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structure_headers").fetchone()[0]

    # =========================================================================
    # Access Matrix Entries
    # =========================================================================

    def add_access_matrix_entry(self, tool, endpoint_path, role,
                                method="GET", expected_status=None,
                                actual_status=None, result=None,
                                auth_type=None, notes=None):
        self._conn.execute(
            "INSERT INTO access_matrix_entries (tool, endpoint_path, method, "
            "role, expected_status, actual_status, result, auth_type, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool, endpoint_path, method, role, expected_status,
             actual_status, result, auth_type, notes))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_access_matrix_entries(self, page=1, per_page=50, tool=None,
                                    endpoint_path=None, role=None, result=None,
                                    method=None, search=None,
                                    sort="id", order="asc"):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if endpoint_path:
            where.append("endpoint_path = ?"); params.append(endpoint_path)
        if role:
            where.append("role = ?"); params.append(role)
        if result:
            where.append("result = ?"); params.append(result)
        if method:
            where.append("method = ?"); params.append(method)
        if search:
            where.append("endpoint_path LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._ACCESS_MATRIX_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM access_matrix_entries {w}",
            params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM access_matrix_entries {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM access_matrix_entries LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_access_matrix_entries(self, tool=None, role=None):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if role:
            where.append("role = ?"); params.append(role)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM access_matrix_entries {w}",
            params).fetchone()[0]

    # =========================================================================
    # Auth Sessions
    # =========================================================================

    def add_auth_session(self, tool, session_name=None, auth_type=None,
                         valid=1, username=None, role=None,
                         token_preview=None, expires_at=None):
        self._conn.execute(
            "INSERT INTO auth_sessions (tool, session_name, auth_type, valid, "
            "username, role, token_preview, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tool, session_name, auth_type, valid, username, role,
             token_preview, expires_at))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_auth_sessions(self, page=1, per_page=50, tool=None,
                            auth_type=None, valid=None, username=None,
                            role=None, sort="id", order="asc"):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if auth_type:
            where.append("auth_type = ?"); params.append(auth_type)
        if valid is not None:
            where.append("valid = ?"); params.append(valid)
        if username:
            where.append("username = ?"); params.append(username)
        if role:
            where.append("role = ?"); params.append(role)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._AUTH_SESSIONS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM auth_sessions {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM auth_sessions {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM auth_sessions LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_auth_sessions(self, tool=None):
        if tool:
            return self._conn.execute(
                "SELECT COUNT(*) FROM auth_sessions WHERE tool = ?",
                (tool,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM auth_sessions").fetchone()[0]

    # =========================================================================
    # Auth Cookies
    # =========================================================================

    def add_auth_cookie(self, session_id, name, domain=None, path="/",
                        secure=0, httponly=0, samesite=None, expires_at=None):
        self._conn.execute(
            "INSERT INTO auth_cookies (session_id, name, domain, path, "
            "secure, httponly, samesite, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, name, domain, path, secure, httponly, samesite,
             expires_at))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_auth_cookies(self, page=1, per_page=50, session_id=None,
                           name=None, domain=None, secure=None,
                           httponly=None, sort="id", order="asc"):
        where, params = [], []
        if session_id is not None:
            where.append("session_id = ?"); params.append(session_id)
        if name:
            where.append("name = ?"); params.append(name)
        if domain:
            where.append("domain = ?"); params.append(domain)
        if secure is not None:
            where.append("secure = ?"); params.append(secure)
        if httponly is not None:
            where.append("httponly = ?"); params.append(httponly)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._AUTH_COOKIES_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM auth_cookies {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM auth_cookies {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM auth_cookies LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_auth_cookies(self, session_id=None):
        if session_id is not None:
            return self._conn.execute(
                "SELECT COUNT(*) FROM auth_cookies WHERE session_id = ?",
                (session_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM auth_cookies").fetchone()[0]

    # =========================================================================
    # Screenshots
    # =========================================================================

    def add_screenshot(self, tool, file_path, url=None, ip=None, port=None,
                       thumbnail_path=None, width=None, height=None,
                       file_size=None, captured_at=None):
        self._conn.execute(
            "INSERT INTO screenshots (tool, url, ip, port, file_path, "
            "thumbnail_path, width, height, file_size, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))",
            (tool, url, ip, port, file_path, thumbnail_path, width, height,
             file_size, captured_at))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_screenshots(self, page=1, per_page=50, tool=None, ip=None,
                          port=None, search=None,
                          sort="id", order="asc"):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if ip:
            where.append("ip = ?"); params.append(ip)
        if port is not None:
            where.append("port = ?"); params.append(port)
        if search:
            where.append("(url LIKE ? OR file_path LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._SCREENSHOTS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM screenshots {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM screenshots {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM screenshots LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_screenshots(self, tool=None, ip=None):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if ip:
            where.append("ip = ?"); params.append(ip)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM screenshots {w}", params).fetchone()[0]

    # =========================================================================
    # Target Profiles
    # =========================================================================

    def add_target_profile(self, tool, target_url, resolved_ip=None,
                           server_header=None, technologies_json="[]",
                           cms=None, framework=None, language=None,
                           waf_detected=None, cdn_detected=None):
        self._conn.execute(
            "INSERT INTO target_profiles (tool, target_url, resolved_ip, "
            "server_header, technologies_json, cms, framework, language, "
            "waf_detected, cdn_detected) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool, target_url, resolved_ip, server_header, technologies_json,
             cms, framework, language, waf_detected, cdn_detected))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_target_profiles(self, page=1, per_page=50, tool=None,
                              cms=None, framework=None, waf_detected=None,
                              search=None, sort="id", order="asc"):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if cms:
            where.append("cms = ?"); params.append(cms)
        if framework:
            where.append("framework = ?"); params.append(framework)
        if waf_detected:
            where.append("waf_detected = ?"); params.append(waf_detected)
        if search:
            where.append("(target_url LIKE ? OR server_header LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._TARGET_PROFILES_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM target_profiles {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM target_profiles {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM target_profiles LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_target_profiles(self, tool=None):
        if tool:
            return self._conn.execute(
                "SELECT COUNT(*) FROM target_profiles WHERE tool = ?",
                (tool,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM target_profiles").fetchone()[0]

    # =========================================================================
    # Crucible Logs
    # =========================================================================

    def add_crucible_log(self, timestamp, message, level="INFO", tool=None,
                         extra_json=None):
        self._conn.execute(
            "INSERT INTO crucible_logs (timestamp, level, tool, message, "
            "extra_json) VALUES (?, ?, ?, ?, ?)",
            (timestamp, level, tool, message, extra_json))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_crucible_logs(self, page=1, per_page=100, level=None, tool=None,
                            from_ts=None, to_ts=None, search=None,
                            sort="id", order="desc"):
        where, params = [], []
        if level:
            where.append("level = ?"); params.append(level)
        if tool:
            where.append("tool = ?"); params.append(tool)
        if from_ts:
            where.append("timestamp >= ?"); params.append(from_ts)
        if to_ts:
            where.append("timestamp <= ?"); params.append(to_ts)
        if search:
            where.append("message LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._CRUCIBLE_LOGS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM crucible_logs {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM crucible_logs {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM crucible_logs LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_crucible_logs(self, level=None, tool=None):
        where, params = [], []
        if level:
            where.append("level = ?"); params.append(level)
        if tool:
            where.append("tool = ?"); params.append(tool)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM crucible_logs {w}", params).fetchone()[0]

    # =========================================================================
    # Crucible Errors
    # =========================================================================

    def add_crucible_error(self, timestamp, message, level="ERROR", tool=None,
                           traceback=None, extra_json=None):
        self._conn.execute(
            "INSERT INTO crucible_errors (timestamp, level, tool, message, "
            "traceback, extra_json) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, level, tool, message, traceback, extra_json))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_crucible_errors(self, page=1, per_page=100, level=None,
                              tool=None, from_ts=None, to_ts=None,
                              search=None, sort="id", order="desc"):
        where, params = [], []
        if level:
            where.append("level = ?"); params.append(level)
        if tool:
            where.append("tool = ?"); params.append(tool)
        if from_ts:
            where.append("timestamp >= ?"); params.append(from_ts)
        if to_ts:
            where.append("timestamp <= ?"); params.append(to_ts)
        if search:
            where.append("(message LIKE ? OR traceback LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._CRUCIBLE_ERRORS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM crucible_errors {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM crucible_errors {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM crucible_errors LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_crucible_errors(self, level=None, tool=None):
        where, params = [], []
        if level:
            where.append("level = ?"); params.append(level)
        if tool:
            where.append("tool = ?"); params.append(tool)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM crucible_errors {w}", params).fetchone()[0]

    # =========================================================================
    # Console Chunks
    # =========================================================================

    def add_console_chunk(self, tool_id, chunk_index, text, byte_offset=0):
        self._conn.execute(
            "INSERT OR REPLACE INTO console_chunks (tool_id, chunk_index, "
            "text, byte_offset) VALUES (?, ?, ?, ?)",
            (tool_id, chunk_index, text, byte_offset))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_console_chunks(self, tool_id, page=1, per_page=50,
                             sort="chunk_index", order="asc"):
        s = self._safe_sort(sort, self._CONSOLE_CHUNKS_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            "SELECT COUNT(*) FROM console_chunks WHERE tool_id = ?",
            (tool_id,)).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM console_chunks WHERE tool_id = ? "
            f"ORDER BY {s} {d} LIMIT ? OFFSET ?",
            (tool_id, per_page, (page - 1) * per_page)).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM console_chunks LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def get_console_text(self, tool_id):
        """Return the full concatenated console output for a tool."""
        rows = self._conn.execute(
            "SELECT text FROM console_chunks WHERE tool_id = ? "
            "ORDER BY chunk_index ASC", (tool_id,)).fetchall()
        return "".join(r[0] for r in rows)

    def count_console_chunks(self, tool_id=None):
        if tool_id:
            return self._conn.execute(
                "SELECT COUNT(*) FROM console_chunks WHERE tool_id = ?",
                (tool_id,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM console_chunks").fetchone()[0]

    # =========================================================================
    # Output Files
    # =========================================================================

    def add_output_file(self, path, filename, tool=None, extension=None,
                        file_size=None, mtime=None, content_type=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO output_files (tool, path, filename, "
            "extension, file_size, mtime, content_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tool, path, filename, extension, file_size, mtime, content_type))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_output_files(self, page=1, per_page=50, tool=None,
                           extension=None, search=None,
                           sort="id", order="asc"):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if extension:
            where.append("extension = ?"); params.append(extension)
        if search:
            where.append("(path LIKE ? OR filename LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._OUTPUT_FILES_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM output_files {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM output_files {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM output_files LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_output_files(self, tool=None, extension=None):
        where, params = [], []
        if tool:
            where.append("tool = ?"); params.append(tool)
        if extension:
            where.append("extension = ?"); params.append(extension)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return self._conn.execute(
            f"SELECT COUNT(*) FROM output_files {w}", params).fetchone()[0]

    # =========================================================================
    # Hostname Intel
    # =========================================================================

    def add_hostname_intel(self, hostname, ip=None, environment_tag=None,
                           application_tag=None, hardware_tag=None,
                           role_tag=None, confidence=0.0):
        self._conn.execute(
            "INSERT OR REPLACE INTO hostname_intel (hostname, ip, "
            "environment_tag, application_tag, hardware_tag, role_tag, "
            "confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hostname, ip, environment_tag, application_tag, hardware_tag,
             role_tag, confidence))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_hostname_intel(self, page=1, per_page=50, environment_tag=None,
                             role_tag=None, search=None,
                             sort="id", order="asc"):
        where, params = [], []
        if environment_tag:
            where.append("environment_tag = ?"); params.append(environment_tag)
        if role_tag:
            where.append("role_tag = ?"); params.append(role_tag)
        if search:
            where.append("(hostname LIKE ? OR ip LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._HOSTNAME_INTEL_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM hostname_intel {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM hostname_intel {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM hostname_intel LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_hostname_intel(self, environment_tag=None):
        if environment_tag:
            return self._conn.execute(
                "SELECT COUNT(*) FROM hostname_intel "
                "WHERE environment_tag = ?",
                (environment_tag,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM hostname_intel").fetchone()[0]

    # =========================================================================
    # Server Roles
    # =========================================================================

    def add_server_role(self, ip, role, confidence=0.0, evidence=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO server_roles (ip, role, confidence, "
            "evidence) VALUES (?, ?, ?, ?)",
            (ip, role, confidence, evidence))
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def query_server_roles(self, page=1, per_page=50, ip=None, role=None,
                           search=None, sort="id", order="asc"):
        where, params = [], []
        if ip:
            where.append("ip = ?"); params.append(ip)
        if role:
            where.append("role = ?"); params.append(role)
        if search:
            where.append("(ip LIKE ? OR role LIKE ? OR evidence LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        s = self._safe_sort(sort, self._SERVER_ROLES_COLS)
        d = "DESC" if order.lower() == "desc" else "ASC"
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM server_roles {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM server_roles {w} ORDER BY {s} {d} "
            "LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [c[0] for c in self._conn.execute(
            "SELECT * FROM server_roles LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def count_server_roles(self, ip=None):
        if ip:
            return self._conn.execute(
                "SELECT COUNT(*) FROM server_roles WHERE ip = ?",
                (ip,)).fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM server_roles").fetchone()[0]

    # ── Phase 8: OSINT + Infrastructure Intelligence ──────────────

    # ================================================================
    # OSINT Extended (OSift) — osint_domains
    # ================================================================

    def add_osint_domain(self, domain, registrar=None, creation_date=None, expiry_date=None,
                         nameservers=None, status=None, dnssec=False):
        import json
        ns_json = json.dumps(nameservers or [])
        self._conn.execute(
            "INSERT OR IGNORE INTO osint_domains (domain, registrar, creation_date, "
            "expiry_date, nameservers_json, status, dnssec) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (domain, registrar, creation_date, expiry_date, ns_json, status, int(dnssec)))

    def query_osint_domains(self, page=1, per_page=50, search=None):
        where, params = [], []
        if search:
            where.append("domain LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_domains {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_domains {w} ORDER BY domain LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM osint_domains LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_osint_domains(self, domains):
        import json
        self._conn.executemany(
            "INSERT OR IGNORE INTO osint_domains (domain, registrar, creation_date, "
            "expiry_date, nameservers_json, status, dnssec) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(d.get("domain"), d.get("registrar"), d.get("creation_date"),
              d.get("expiry_date"), json.dumps(d.get("nameservers", [])),
              d.get("status"), int(d.get("dnssec", False))) for d in domains])

    # ================================================================
    # OSINT Extended (OSift) — osint_whois
    # ================================================================

    def add_osint_whois(self, domain_id, raw_text=None, registrant_org=None,
                        registrant_country=None, admin_email=None, tech_email=None,
                        parsed=None):
        import json
        parsed_json = json.dumps(parsed or {})
        self._conn.execute(
            "INSERT INTO osint_whois (domain_id, raw_text, registrant_org, "
            "registrant_country, admin_email, tech_email, parsed_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (domain_id, raw_text, registrant_org, registrant_country,
             admin_email, tech_email, parsed_json))

    def query_osint_whois(self, page=1, per_page=50, domain_id=None, registrant_org=None):
        where, params = [], []
        if domain_id is not None:
            where.append("domain_id = ?"); params.append(domain_id)
        if registrant_org:
            where.append("registrant_org LIKE ?"); params.append(f"%{registrant_org}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_whois {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_whois {w} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM osint_whois LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_osint_whois(self, records):
        import json
        self._conn.executemany(
            "INSERT INTO osint_whois (domain_id, raw_text, registrant_org, "
            "registrant_country, admin_email, tech_email, parsed_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r.get("domain_id"), r.get("raw_text"), r.get("registrant_org"),
              r.get("registrant_country"), r.get("admin_email"), r.get("tech_email"),
              json.dumps(r.get("parsed", {}))) for r in records])

    # ================================================================
    # OSINT Extended (OSift) — osint_phones
    # ================================================================

    def add_osint_phone(self, phone, person_id=None, source=None, phone_type=None,
                        country_code=None):
        self._conn.execute(
            "INSERT INTO osint_phones (phone, person_id, source, phone_type, country_code) "
            "VALUES (?, ?, ?, ?, ?)",
            (phone, person_id, source, phone_type, country_code))

    def query_osint_phones(self, page=1, per_page=50, person_id=None, phone_type=None,
                           search=None):
        where, params = [], []
        if person_id is not None:
            where.append("person_id = ?"); params.append(person_id)
        if phone_type:
            where.append("phone_type = ?"); params.append(phone_type)
        if search:
            where.append("phone LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_phones {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_phones {w} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM osint_phones LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_osint_phones(self, phones):
        self._conn.executemany(
            "INSERT INTO osint_phones (phone, person_id, source, phone_type, country_code) "
            "VALUES (?, ?, ?, ?, ?)",
            [(p.get("phone"), p.get("person_id"), p.get("source"),
              p.get("phone_type"), p.get("country_code")) for p in phones])

    # ================================================================
    # OSINT Extended (OSift) — osint_wayback_urls
    # ================================================================

    def add_osint_wayback_url(self, domain, url, timestamp=None, status_code=None,
                              mime_type=None, length=None):
        self._conn.execute(
            "INSERT INTO osint_wayback_urls (domain, url, timestamp, status_code, "
            "mime_type, length) VALUES (?, ?, ?, ?, ?, ?)",
            (domain, url, timestamp, status_code, mime_type, length))

    def query_osint_wayback_urls(self, page=1, per_page=50, domain=None, mime_type=None,
                                 status_code=None):
        where, params = [], []
        if domain:
            where.append("domain = ?"); params.append(domain)
        if mime_type:
            where.append("mime_type LIKE ?"); params.append(f"%{mime_type}%")
        if status_code is not None:
            where.append("status_code = ?"); params.append(status_code)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_wayback_urls {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_wayback_urls {w} ORDER BY domain, timestamp LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM osint_wayback_urls LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_osint_wayback_urls(self, urls):
        self._conn.executemany(
            "INSERT INTO osint_wayback_urls (domain, url, timestamp, status_code, "
            "mime_type, length) VALUES (?, ?, ?, ?, ?, ?)",
            [(u.get("domain"), u.get("url"), u.get("timestamp"),
              u.get("status_code"), u.get("mime_type"), u.get("length")) for u in urls])

    # ================================================================
    # OSINT Extended (OSift) — osint_typosquats
    # ================================================================

    def add_osint_typosquat(self, domain, variant, fuzzer=None, dns_a=None, dns_aaaa=None,
                            dns_mx=None, dns_ns=None, registered=False, ssdeep_score=None):
        self._conn.execute(
            "INSERT INTO osint_typosquats (domain, variant, fuzzer, dns_a, dns_aaaa, "
            "dns_mx, dns_ns, registered, ssdeep_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (domain, variant, fuzzer, dns_a, dns_aaaa, dns_mx, dns_ns,
             int(registered), ssdeep_score))

    def query_osint_typosquats(self, page=1, per_page=50, domain=None, fuzzer=None,
                               registered=None):
        where, params = [], []
        if domain:
            where.append("domain = ?"); params.append(domain)
        if fuzzer:
            where.append("fuzzer = ?"); params.append(fuzzer)
        if registered is not None:
            where.append("registered = ?"); params.append(int(registered))
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM osint_typosquats {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM osint_typosquats {w} ORDER BY domain, variant LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM osint_typosquats LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_osint_typosquats(self, typosquats):
        self._conn.executemany(
            "INSERT INTO osint_typosquats (domain, variant, fuzzer, dns_a, dns_aaaa, "
            "dns_mx, dns_ns, registered, ssdeep_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(t.get("domain"), t.get("variant"), t.get("fuzzer"), t.get("dns_a"),
              t.get("dns_aaaa"), t.get("dns_mx"), t.get("dns_ns"),
              int(t.get("registered", False)), t.get("ssdeep_score")) for t in typosquats])

    # ================================================================
    # Firewall (Bastion) — firewall_rules
    # ================================================================

    def add_firewall_rule(self, action, rule_number=None, policy=None, source_zone=None,
                          dest_zone=None, source_addr=None, dest_addr=None, service=None,
                          port=None, protocol=None, hits=0, enabled=True, comment=None):
        self._conn.execute(
            "INSERT INTO firewall_rules (rule_number, policy, source_zone, dest_zone, "
            "source_addr, dest_addr, service, port, protocol, action, hits, enabled, comment) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rule_number, policy, source_zone, dest_zone, source_addr, dest_addr,
             service, port, protocol, action, hits, int(enabled), comment))

    def query_firewall_rules(self, page=1, per_page=50, action=None, source_zone=None,
                             dest_zone=None, protocol=None, enabled=None):
        where, params = [], []
        if action:
            where.append("action = ?"); params.append(action)
        if source_zone:
            where.append("source_zone = ?"); params.append(source_zone)
        if dest_zone:
            where.append("dest_zone = ?"); params.append(dest_zone)
        if protocol:
            where.append("protocol = ?"); params.append(protocol)
        if enabled is not None:
            where.append("enabled = ?"); params.append(int(enabled))
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM firewall_rules {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM firewall_rules {w} ORDER BY rule_number LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM firewall_rules LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_firewall_rules(self, rules):
        self._conn.executemany(
            "INSERT INTO firewall_rules (rule_number, policy, source_zone, dest_zone, "
            "source_addr, dest_addr, service, port, protocol, action, hits, enabled, comment) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(r.get("rule_number"), r.get("policy"), r.get("source_zone"),
              r.get("dest_zone"), r.get("source_addr"), r.get("dest_addr"),
              r.get("service"), r.get("port"), r.get("protocol"),
              r.get("action"), r.get("hits", 0), int(r.get("enabled", True)),
              r.get("comment")) for r in rules])

    # ================================================================
    # Firewall (Bastion) — firewall_zones
    # ================================================================

    def add_firewall_zone(self, name, zone_type=None, interfaces=None, description=None):
        import json
        ifaces_json = json.dumps(interfaces or [])
        self._conn.execute(
            "INSERT OR IGNORE INTO firewall_zones (name, zone_type, interfaces_json, "
            "description) VALUES (?, ?, ?, ?)",
            (name, zone_type, ifaces_json, description))

    def query_firewall_zones(self, page=1, per_page=50, zone_type=None):
        where, params = [], []
        if zone_type:
            where.append("zone_type = ?"); params.append(zone_type)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM firewall_zones {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM firewall_zones {w} ORDER BY name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM firewall_zones LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_firewall_zones(self, zones):
        import json
        self._conn.executemany(
            "INSERT OR IGNORE INTO firewall_zones (name, zone_type, interfaces_json, "
            "description) VALUES (?, ?, ?, ?)",
            [(z.get("name"), z.get("zone_type"),
              json.dumps(z.get("interfaces", [])), z.get("description")) for z in zones])

    # ================================================================
    # Firewall (Bastion) — firewall_compliance
    # ================================================================

    def add_firewall_compliance(self, check_id, check_name, status, category=None,
                                severity=None, details=None, remediation=None,
                                framework=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO firewall_compliance (check_id, check_name, category, "
            "status, severity, details, remediation, framework) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (check_id, check_name, category, status, severity, details,
             remediation, framework))

    def query_firewall_compliance(self, page=1, per_page=50, status=None, framework=None,
                                  severity=None, search=None):
        where, params = [], []
        if status:
            where.append("status = ?"); params.append(status)
        if framework:
            where.append("framework = ?"); params.append(framework)
        if severity:
            where.append("severity = ?"); params.append(severity)
        if search:
            where.append("(check_name LIKE ? OR details LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM firewall_compliance {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM firewall_compliance {w} ORDER BY check_id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM firewall_compliance LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_firewall_compliance(self, checks):
        self._conn.executemany(
            "INSERT OR REPLACE INTO firewall_compliance (check_id, check_name, category, "
            "status, severity, details, remediation, framework) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(c.get("check_id"), c.get("check_name"), c.get("category"),
              c.get("status"), c.get("severity"), c.get("details"),
              c.get("remediation"), c.get("framework")) for c in checks])

    # ================================================================
    # Cloud (Forge) — cloud_resources
    # ================================================================

    def add_cloud_resource(self, resource_type, arn=None, region=None, name=None,
                           state=None, public=False, tags=None, config=None):
        import json
        tags_json = json.dumps(tags or {})
        config_json = json.dumps(config or {})
        self._conn.execute(
            "INSERT OR IGNORE INTO cloud_resources (arn, resource_type, region, name, "
            "state, public, tags_json, config_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (arn, resource_type, region, name, state, int(public), tags_json, config_json))

    def query_cloud_resources(self, page=1, per_page=50, resource_type=None, region=None,
                              public=None, search=None):
        where, params = [], []
        if resource_type:
            where.append("resource_type = ?"); params.append(resource_type)
        if region:
            where.append("region = ?"); params.append(region)
        if public is not None:
            where.append("public = ?"); params.append(int(public))
        if search:
            where.append("(name LIKE ? OR arn LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM cloud_resources {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM cloud_resources {w} ORDER BY resource_type, name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM cloud_resources LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_cloud_resources(self, resources):
        import json
        self._conn.executemany(
            "INSERT OR IGNORE INTO cloud_resources (arn, resource_type, region, name, "
            "state, public, tags_json, config_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(r.get("arn"), r.get("resource_type"), r.get("region"), r.get("name"),
              r.get("state"), int(r.get("public", False)),
              json.dumps(r.get("tags", {})), json.dumps(r.get("config", {}))) for r in resources])

    # ================================================================
    # Cloud (Forge) — cloud_iam_policies
    # ================================================================

    def add_cloud_iam_policy(self, name, arn=None, policy_type=None, attached_to=None,
                             permissions=None, is_admin=False):
        import json
        attached_json = json.dumps(attached_to or [])
        perms_json = json.dumps(permissions or {})
        self._conn.execute(
            "INSERT OR IGNORE INTO cloud_iam_policies (arn, name, policy_type, "
            "attached_to_json, permissions_json, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (arn, name, policy_type, attached_json, perms_json, int(is_admin)))

    def query_cloud_iam_policies(self, page=1, per_page=50, policy_type=None,
                                 is_admin=None, search=None):
        where, params = [], []
        if policy_type:
            where.append("policy_type = ?"); params.append(policy_type)
        if is_admin is not None:
            where.append("is_admin = ?"); params.append(int(is_admin))
        if search:
            where.append("(name LIKE ? OR arn LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM cloud_iam_policies {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM cloud_iam_policies {w} ORDER BY name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM cloud_iam_policies LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_cloud_iam_policies(self, policies):
        import json
        self._conn.executemany(
            "INSERT OR IGNORE INTO cloud_iam_policies (arn, name, policy_type, "
            "attached_to_json, permissions_json, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            [(p.get("arn"), p.get("name"), p.get("policy_type"),
              json.dumps(p.get("attached_to", [])),
              json.dumps(p.get("permissions", {})),
              int(p.get("is_admin", False))) for p in policies])

    # ================================================================
    # Cloud (Forge) — cloud_iam_roles
    # ================================================================

    def add_cloud_iam_role(self, name, arn=None, trust_policy=None, attached_policies=None,
                           is_service_role=False, last_used=None):
        import json
        trust_json = json.dumps(trust_policy or {})
        attached_json = json.dumps(attached_policies or [])
        self._conn.execute(
            "INSERT OR IGNORE INTO cloud_iam_roles (arn, name, trust_policy_json, "
            "attached_policies_json, is_service_role, last_used) VALUES (?, ?, ?, ?, ?, ?)",
            (arn, name, trust_json, attached_json, int(is_service_role), last_used))

    def query_cloud_iam_roles(self, page=1, per_page=50, is_service_role=None, search=None):
        where, params = [], []
        if is_service_role is not None:
            where.append("is_service_role = ?"); params.append(int(is_service_role))
        if search:
            where.append("(name LIKE ? OR arn LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM cloud_iam_roles {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM cloud_iam_roles {w} ORDER BY name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM cloud_iam_roles LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_cloud_iam_roles(self, roles):
        import json
        self._conn.executemany(
            "INSERT OR IGNORE INTO cloud_iam_roles (arn, name, trust_policy_json, "
            "attached_policies_json, is_service_role, last_used) VALUES (?, ?, ?, ?, ?, ?)",
            [(r.get("arn"), r.get("name"), json.dumps(r.get("trust_policy", {})),
              json.dumps(r.get("attached_policies", [])),
              int(r.get("is_service_role", False)), r.get("last_used")) for r in roles])

    # ================================================================
    # Cloud (Forge) — cloud_services
    # ================================================================

    def add_cloud_service(self, service_name, region=None, resource_count=0, public_count=0,
                          finding_count=0, risk_summary=None):
        import json
        risk_json = json.dumps(risk_summary or {})
        self._conn.execute(
            "INSERT OR REPLACE INTO cloud_services (service_name, region, resource_count, "
            "public_count, finding_count, risk_summary_json) VALUES (?, ?, ?, ?, ?, ?)",
            (service_name, region, resource_count, public_count, finding_count, risk_json))

    def query_cloud_services(self, page=1, per_page=50, search=None):
        where, params = [], []
        if search:
            where.append("service_name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM cloud_services {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM cloud_services {w} ORDER BY service_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM cloud_services LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_cloud_services(self, services):
        import json
        self._conn.executemany(
            "INSERT OR REPLACE INTO cloud_services (service_name, region, resource_count, "
            "public_count, finding_count, risk_summary_json) VALUES (?, ?, ?, ?, ?, ?)",
            [(s.get("service_name"), s.get("region"), s.get("resource_count", 0),
              s.get("public_count", 0), s.get("finding_count", 0),
              json.dumps(s.get("risk_summary", {}))) for s in services])

    # ================================================================
    # Traffic (Trawler) — traffic_conversations
    # ================================================================

    def add_traffic_conversation(self, src_ip, dst_ip, src_port=None, dst_port=None,
                                 protocol=None, bytes_sent=0, bytes_recv=0, packets=0,
                                 start_time=None, end_time=None, flags=None, application=None):
        self._conn.execute(
            "INSERT INTO traffic_conversations (src_ip, src_port, dst_ip, dst_port, "
            "protocol, bytes_sent, bytes_recv, packets, start_time, end_time, flags, "
            "application) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_recv,
             packets, start_time, end_time, flags, application))

    def query_traffic_conversations(self, page=1, per_page=50, src_ip=None, dst_ip=None,
                                    protocol=None, application=None):
        where, params = [], []
        if src_ip:
            where.append("src_ip = ?"); params.append(src_ip)
        if dst_ip:
            where.append("dst_ip = ?"); params.append(dst_ip)
        if protocol:
            where.append("protocol = ?"); params.append(protocol)
        if application:
            where.append("application LIKE ?"); params.append(f"%{application}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM traffic_conversations {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM traffic_conversations {w} ORDER BY start_time DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM traffic_conversations LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_traffic_conversations(self, conversations):
        self._conn.executemany(
            "INSERT INTO traffic_conversations (src_ip, src_port, dst_ip, dst_port, "
            "protocol, bytes_sent, bytes_recv, packets, start_time, end_time, flags, "
            "application) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(c.get("src_ip"), c.get("src_port"), c.get("dst_ip"), c.get("dst_port"),
              c.get("protocol"), c.get("bytes_sent", 0), c.get("bytes_recv", 0),
              c.get("packets", 0), c.get("start_time"), c.get("end_time"),
              c.get("flags"), c.get("application")) for c in conversations])

    # ================================================================
    # Traffic (Trawler) — traffic_summary
    # ================================================================

    def add_traffic_summary(self, key, value=None, numeric_value=None, category=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO traffic_summary (key, value, numeric_value, category) "
            "VALUES (?, ?, ?, ?)",
            (key, value, numeric_value, category))

    def query_traffic_summary(self, page=1, per_page=50, category=None, search=None):
        where, params = [], []
        if category:
            where.append("category = ?"); params.append(category)
        if search:
            where.append("(key LIKE ? OR value LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM traffic_summary {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM traffic_summary {w} ORDER BY key LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM traffic_summary LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def bulk_insert_traffic_summary(self, summaries):
        self._conn.executemany(
            "INSERT OR REPLACE INTO traffic_summary (key, value, numeric_value, category) "
            "VALUES (?, ?, ?, ?)",
            [(s.get("key"), s.get("value"), s.get("numeric_value"),
              s.get("category")) for s in summaries])

    # ── Phase 8: Specialized Tool Intelligence ────────────────────

    # =========================================================================
    # Database Audit (Auger)
    # =========================================================================

    def add_db_schema(self, db_type, schema_name, host=None, port=None,
                      table_count=0, total_rows=None, size_bytes=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO db_schemas "
            "(db_type, host, port, schema_name, table_count, total_rows, size_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (db_type, host, port, schema_name, table_count, total_rows, size_bytes))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_db_table(self, schema_id, table_name, row_count=None,
                     column_count=None, has_pii=0, has_sensitive=0, engine=None):
        self._conn.execute(
            "INSERT INTO db_tables "
            "(schema_id, table_name, row_count, column_count, has_pii, has_sensitive, engine) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (schema_id, table_name, row_count, column_count, has_pii, has_sensitive, engine))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_db_column(self, table_id, column_name, data_type=None,
                      is_nullable=1, is_primary=0, is_indexed=0,
                      pii_type=None, sample_value=None):
        self._conn.execute(
            "INSERT INTO db_columns "
            "(table_id, column_name, data_type, is_nullable, is_primary, "
            "is_indexed, pii_type, sample_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (table_id, column_name, data_type, is_nullable, is_primary,
             is_indexed, pii_type, sample_value))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_db_privilege(self, grantee, privilege, host=None, port=None,
                         target_schema=None, target_table=None, is_grantable=0):
        self._conn.execute(
            "INSERT OR REPLACE INTO db_privileges "
            "(host, port, grantee, privilege, target_schema, target_table, is_grantable) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host, port, grantee, privilege, target_schema, target_table, is_grantable))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def bulk_insert_db_schemas(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO db_schemas "
            "(db_type, host, port, schema_name, table_count, total_rows, size_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r.get("db_type"), r.get("host"), r.get("port"), r.get("schema_name"),
              r.get("table_count", 0), r.get("total_rows"), r.get("size_bytes"))
             for r in rows])
        self._commit()

    def bulk_insert_db_tables(self, rows):
        self._conn.executemany(
            "INSERT INTO db_tables "
            "(schema_id, table_name, row_count, column_count, has_pii, has_sensitive, engine) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r["schema_id"], r["table_name"], r.get("row_count"),
              r.get("column_count"), r.get("has_pii", 0),
              r.get("has_sensitive", 0), r.get("engine"))
             for r in rows])
        self._commit()

    def bulk_insert_db_columns(self, rows):
        self._conn.executemany(
            "INSERT INTO db_columns "
            "(table_id, column_name, data_type, is_nullable, is_primary, "
            "is_indexed, pii_type, sample_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(r["table_id"], r["column_name"], r.get("data_type"),
              r.get("is_nullable", 1), r.get("is_primary", 0),
              r.get("is_indexed", 0), r.get("pii_type"), r.get("sample_value"))
             for r in rows])
        self._commit()

    def bulk_insert_db_privileges(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO db_privileges "
            "(host, port, grantee, privilege, target_schema, target_table, is_grantable) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r.get("host"), r.get("port"), r["grantee"], r["privilege"],
              r.get("target_schema"), r.get("target_table"), r.get("is_grantable", 0))
             for r in rows])
        self._commit()

    def query_db_schemas(self, page=1, per_page=50, db_type=None, host=None, search=None):
        where, params = [], []
        if db_type:
            where.append("db_type = ?"); params.append(db_type)
        if host:
            where.append("host = ?"); params.append(host)
        if search:
            where.append("schema_name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM db_schemas {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM db_schemas {w} ORDER BY schema_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM db_schemas LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_db_tables(self, page=1, per_page=50, schema_id=None,
                        pii_only=False, search=None):
        where, params = [], []
        if schema_id is not None:
            where.append("schema_id = ?"); params.append(schema_id)
        if pii_only:
            where.append("(has_pii = 1 OR has_sensitive = 1)")
        if search:
            where.append("table_name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM db_tables {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM db_tables {w} ORDER BY table_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM db_tables LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_db_columns(self, page=1, per_page=100, table_id=None,
                         pii_type=None, search=None):
        where, params = [], []
        if table_id is not None:
            where.append("table_id = ?"); params.append(table_id)
        if pii_type:
            where.append("pii_type = ?"); params.append(pii_type)
        if search:
            where.append("column_name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM db_columns {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM db_columns {w} ORDER BY column_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM db_columns LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_db_privileges(self, page=1, per_page=50, grantee=None,
                            host=None, search=None):
        where, params = [], []
        if grantee:
            where.append("grantee = ?"); params.append(grantee)
        if host:
            where.append("host = ?"); params.append(host)
        if search:
            where.append("(grantee LIKE ? OR privilege LIKE ? OR target_schema LIKE ?)");
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM db_privileges {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM db_privileges {w} ORDER BY grantee, privilege LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM db_privileges LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    # =========================================================================
    # Endpoint Security (Dredge)
    # =========================================================================

    def add_endpoint_software(self, name, version=None, publisher=None,
                              install_date=None, install_path=None,
                              is_security_tool=0, is_outdated=0,
                              latest_version=None, cve_count=0):
        self._conn.execute(
            "INSERT OR REPLACE INTO endpoint_software "
            "(name, version, publisher, install_date, install_path, "
            "is_security_tool, is_outdated, latest_version, cve_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, version, publisher, install_date, install_path,
             is_security_tool, is_outdated, latest_version, cve_count))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_endpoint_hardening(self, check_id, status, category=None,
                               description=None, severity=None,
                               current_value=None, expected_value=None,
                               remediation=None, framework=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO endpoint_hardening "
            "(check_id, category, description, status, severity, "
            "current_value, expected_value, remediation, framework) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (check_id, category, description, status, severity,
             current_value, expected_value, remediation, framework))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_endpoint_compliance(self, framework, control_id, status,
                                control_name=None, evidence=None,
                                remediation=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO endpoint_compliance "
            "(framework, control_id, control_name, status, evidence, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (framework, control_id, control_name, status, evidence, remediation))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_endpoint_ad(self, check_category, check_name, status,
                        severity=None, details=None,
                        affected_objects_json='[]', remediation=None):
        self._conn.execute(
            "INSERT INTO endpoint_ad "
            "(check_category, check_name, status, severity, details, "
            "affected_objects_json, remediation) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (check_category, check_name, status, severity, details,
             affected_objects_json, remediation))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_endpoint_browser(self, browser_name, version=None,
                             profile_count=0, extensions_json='[]',
                             saved_passwords=0, autofill_data=0,
                             sync_enabled=0, security_settings_json='{}'):
        self._conn.execute(
            "INSERT INTO endpoint_browsers "
            "(browser_name, version, profile_count, extensions_json, "
            "saved_passwords, autofill_data, sync_enabled, security_settings_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (browser_name, version, profile_count, extensions_json,
             saved_passwords, autofill_data, sync_enabled, security_settings_json))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_endpoint_inventory(self, category, key, value=None, details_json='{}'):
        self._conn.execute(
            "INSERT OR REPLACE INTO endpoint_inventory "
            "(category, key, value, details_json) VALUES (?, ?, ?, ?)",
            (category, key, value, details_json))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def bulk_insert_endpoint_software(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO endpoint_software "
            "(name, version, publisher, install_date, install_path, "
            "is_security_tool, is_outdated, latest_version, cve_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(r["name"], r.get("version"), r.get("publisher"),
              r.get("install_date"), r.get("install_path"),
              r.get("is_security_tool", 0), r.get("is_outdated", 0),
              r.get("latest_version"), r.get("cve_count", 0))
             for r in rows])
        self._commit()

    def bulk_insert_endpoint_hardening(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO endpoint_hardening "
            "(check_id, category, description, status, severity, "
            "current_value, expected_value, remediation, framework) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(r["check_id"], r.get("category"), r.get("description"),
              r["status"], r.get("severity"), r.get("current_value"),
              r.get("expected_value"), r.get("remediation"), r.get("framework"))
             for r in rows])
        self._commit()

    def bulk_insert_endpoint_compliance(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO endpoint_compliance "
            "(framework, control_id, control_name, status, evidence, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["framework"], r["control_id"], r.get("control_name"),
              r["status"], r.get("evidence"), r.get("remediation"))
             for r in rows])
        self._commit()

    def bulk_insert_endpoint_ad(self, rows):
        self._conn.executemany(
            "INSERT INTO endpoint_ad "
            "(check_category, check_name, status, severity, details, "
            "affected_objects_json, remediation) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r["check_category"], r["check_name"], r["status"],
              r.get("severity"), r.get("details"),
              r.get("affected_objects_json", "[]"), r.get("remediation"))
             for r in rows])
        self._commit()

    def bulk_insert_endpoint_browsers(self, rows):
        self._conn.executemany(
            "INSERT INTO endpoint_browsers "
            "(browser_name, version, profile_count, extensions_json, "
            "saved_passwords, autofill_data, sync_enabled, security_settings_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(r["browser_name"], r.get("version"), r.get("profile_count", 0),
              r.get("extensions_json", "[]"), r.get("saved_passwords", 0),
              r.get("autofill_data", 0), r.get("sync_enabled", 0),
              r.get("security_settings_json", "{}"))
             for r in rows])
        self._commit()

    def bulk_insert_endpoint_inventory(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO endpoint_inventory "
            "(category, key, value, details_json) VALUES (?, ?, ?, ?)",
            [(r["category"], r["key"], r.get("value"),
              r.get("details_json", "{}"))
             for r in rows])
        self._commit()

    def query_endpoint_software(self, page=1, per_page=50, search=None,
                                outdated_only=False, security_only=False):
        where, params = [], []
        if search:
            where.append("(name LIKE ? OR publisher LIKE ?)"); params.extend([f"%{search}%"] * 2)
        if outdated_only:
            where.append("is_outdated = 1")
        if security_only:
            where.append("is_security_tool = 1")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_software {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_software {w} ORDER BY name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_software LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_endpoint_hardening(self, page=1, per_page=50, status=None,
                                 category=None, framework=None, search=None):
        where, params = [], []
        if status:
            where.append("status = ?"); params.append(status)
        if category:
            where.append("category = ?"); params.append(category)
        if framework:
            where.append("framework = ?"); params.append(framework)
        if search:
            where.append("(check_id LIKE ? OR description LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_hardening {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_hardening {w} ORDER BY check_id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_hardening LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_endpoint_compliance(self, page=1, per_page=50, framework=None,
                                  status=None, search=None):
        where, params = [], []
        if framework:
            where.append("framework = ?"); params.append(framework)
        if status:
            where.append("status = ?"); params.append(status)
        if search:
            where.append("(control_id LIKE ? OR control_name LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_compliance {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_compliance {w} ORDER BY framework, control_id LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_compliance LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_endpoint_ad(self, page=1, per_page=50, check_category=None,
                          status=None, severity=None, search=None):
        where, params = [], []
        if check_category:
            where.append("check_category = ?"); params.append(check_category)
        if status:
            where.append("status = ?"); params.append(status)
        if severity:
            where.append("severity = ?"); params.append(severity)
        if search:
            where.append("(check_name LIKE ? OR details LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_ad {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_ad {w} ORDER BY check_category, check_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_ad LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_endpoint_browsers(self, page=1, per_page=50, search=None):
        where, params = [], []
        if search:
            where.append("browser_name LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_browsers {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_browsers {w} ORDER BY browser_name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_browsers LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_endpoint_inventory(self, page=1, per_page=50, category=None, search=None):
        where, params = [], []
        if category:
            where.append("category = ?"); params.append(category)
        if search:
            where.append("(key LIKE ? OR value LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM endpoint_inventory {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM endpoint_inventory {w} ORDER BY category, key LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM endpoint_inventory LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    # =========================================================================
    # Mobile (Quill)
    # =========================================================================

    def add_mobile_component(self, component_type, name, exported=0,
                             permission=None, description=None, risk=None):
        self._conn.execute(
            "INSERT INTO mobile_components "
            "(component_type, name, exported, permission, description, risk) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (component_type, name, exported, permission, description, risk))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_mobile_permission(self, permission, protection_level=None,
                              group_name=None, is_custom=0, used_by_count=0,
                              description=None, risk=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO mobile_permissions "
            "(permission, protection_level, group_name, is_custom, "
            "used_by_count, description, risk) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (permission, protection_level, group_name, is_custom,
             used_by_count, description, risk))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_mobile_data_flow(self, source, destination, data_type=None,
                             encrypted=0, protocol=None, method=None, notes=None):
        self._conn.execute(
            "INSERT INTO mobile_data_flows "
            "(source, destination, data_type, encrypted, protocol, method, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source, destination, data_type, encrypted, protocol, method, notes))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_mobile_traffic(self, url, method='GET', host=None,
                           content_type=None, request_size=None,
                           response_size=None, status_code=None,
                           encrypted=1, certificate_valid=None,
                           pinning_detected=0, timestamp=None):
        self._conn.execute(
            "INSERT INTO mobile_traffic "
            "(url, method, host, content_type, request_size, response_size, "
            "status_code, encrypted, certificate_valid, pinning_detected, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (url, method, host, content_type, request_size, response_size,
             status_code, encrypted, certificate_valid, pinning_detected, timestamp))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def bulk_insert_mobile_components(self, rows):
        self._conn.executemany(
            "INSERT INTO mobile_components "
            "(component_type, name, exported, permission, description, risk) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["component_type"], r["name"], r.get("exported", 0),
              r.get("permission"), r.get("description"), r.get("risk"))
             for r in rows])
        self._commit()

    def bulk_insert_mobile_permissions(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO mobile_permissions "
            "(permission, protection_level, group_name, is_custom, "
            "used_by_count, description, risk) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r["permission"], r.get("protection_level"), r.get("group_name"),
              r.get("is_custom", 0), r.get("used_by_count", 0),
              r.get("description"), r.get("risk"))
             for r in rows])
        self._commit()

    def bulk_insert_mobile_data_flows(self, rows):
        self._conn.executemany(
            "INSERT INTO mobile_data_flows "
            "(source, destination, data_type, encrypted, protocol, method, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r["source"], r["destination"], r.get("data_type"),
              r.get("encrypted", 0), r.get("protocol"), r.get("method"),
              r.get("notes"))
             for r in rows])
        self._commit()

    def bulk_insert_mobile_traffic(self, rows):
        self._conn.executemany(
            "INSERT INTO mobile_traffic "
            "(url, method, host, content_type, request_size, response_size, "
            "status_code, encrypted, certificate_valid, pinning_detected, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(r["url"], r.get("method", "GET"), r.get("host"),
              r.get("content_type"), r.get("request_size"),
              r.get("response_size"), r.get("status_code"),
              r.get("encrypted", 1), r.get("certificate_valid"),
              r.get("pinning_detected", 0), r.get("timestamp"))
             for r in rows])
        self._commit()

    def query_mobile_components(self, page=1, per_page=50, component_type=None,
                                exported_only=False, search=None):
        where, params = [], []
        if component_type:
            where.append("component_type = ?"); params.append(component_type)
        if exported_only:
            where.append("exported = 1")
        if search:
            where.append("(name LIKE ? OR description LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM mobile_components {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM mobile_components {w} ORDER BY component_type, name LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM mobile_components LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_mobile_permissions(self, page=1, per_page=50,
                                 protection_level=None, custom_only=False,
                                 search=None):
        where, params = [], []
        if protection_level:
            where.append("protection_level = ?"); params.append(protection_level)
        if custom_only:
            where.append("is_custom = 1")
        if search:
            where.append("(permission LIKE ? OR description LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM mobile_permissions {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM mobile_permissions {w} ORDER BY permission LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM mobile_permissions LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_mobile_data_flows(self, page=1, per_page=50, encrypted=None,
                                protocol=None, search=None):
        where, params = [], []
        if encrypted is not None:
            where.append("encrypted = ?"); params.append(int(encrypted))
        if protocol:
            where.append("protocol = ?"); params.append(protocol)
        if search:
            where.append("(source LIKE ? OR destination LIKE ? OR data_type LIKE ?)");
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM mobile_data_flows {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM mobile_data_flows {w} ORDER BY source, destination LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM mobile_data_flows LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_mobile_traffic(self, page=1, per_page=50, host=None,
                             encrypted=None, search=None):
        where, params = [], []
        if host:
            where.append("host = ?"); params.append(host)
        if encrypted is not None:
            where.append("encrypted = ?"); params.append(int(encrypted))
        if search:
            where.append("(url LIKE ? OR host LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM mobile_traffic {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM mobile_traffic {w} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM mobile_traffic LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    # =========================================================================
    # File Analysis (Isotope)
    # =========================================================================

    def add_isotope_string(self, value, string_type=None, offset=None,
                           encoding='ascii', context=None, is_interesting=0):
        self._conn.execute(
            "INSERT INTO isotope_strings "
            "(value, string_type, offset, encoding, context, is_interesting) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (value, string_type, offset, encoding, context, is_interesting))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_property(self, key, value=None, category=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO isotope_properties (key, value, category) "
            "VALUES (?, ?, ?)", (key, value, category))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_entropy(self, entropy, section_name=None, offset=None,
                            length=None, is_packed=0, is_encrypted=0):
        self._conn.execute(
            "INSERT INTO isotope_entropy "
            "(section_name, offset, length, entropy, is_packed, is_encrypted) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (section_name, offset, length, entropy, is_packed, is_encrypted))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_secret(self, secret_type, value_preview=None,
                           file_path=None, line_number=None,
                           confidence='medium', context=None):
        self._conn.execute(
            "INSERT INTO isotope_secrets "
            "(secret_type, value_preview, file_path, line_number, confidence, context) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (secret_type, value_preview, file_path, line_number, confidence, context))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_code(self, language=None, file_path=None,
                         function_name=None, vulnerability_type=None,
                         severity=None, line_number=None,
                         code_snippet=None, description=None):
        self._conn.execute(
            "INSERT INTO isotope_code "
            "(language, file_path, function_name, vulnerability_type, "
            "severity, line_number, code_snippet, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (language, file_path, function_name, vulnerability_type,
             severity, line_number, code_snippet, description))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_binary(self, key, value=None, category=None, details_json='{}'):
        self._conn.execute(
            "INSERT OR REPLACE INTO isotope_binary "
            "(key, value, category, details_json) VALUES (?, ?, ?, ?)",
            (key, value, category, details_json))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_ioc(self, ioc_type, value, source=None,
                        confidence='medium', threat_name=None, first_seen=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO isotope_iocs "
            "(ioc_type, value, source, confidence, threat_name, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ioc_type, value, source, confidence, threat_name, first_seen))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_content(self, path, file_type=None, size=None,
                            modified_at=None, entropy=None,
                            is_encrypted=0, hash_sha256=None):
        self._conn.execute(
            "INSERT INTO isotope_contents "
            "(path, file_type, size, modified_at, entropy, is_encrypted, hash_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (path, file_type, size, modified_at, entropy, is_encrypted, hash_sha256))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_isotope_metadata(self, key, value=None, source=None):
        self._conn.execute(
            "INSERT OR REPLACE INTO isotope_metadata (key, value, source) "
            "VALUES (?, ?, ?)", (key, value, source))
        self._commit()
        return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def bulk_insert_isotope_strings(self, rows):
        self._conn.executemany(
            "INSERT INTO isotope_strings "
            "(value, string_type, offset, encoding, context, is_interesting) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["value"], r.get("string_type"), r.get("offset"),
              r.get("encoding", "ascii"), r.get("context"),
              r.get("is_interesting", 0))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_properties(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO isotope_properties (key, value, category) "
            "VALUES (?, ?, ?)",
            [(r["key"], r.get("value"), r.get("category")) for r in rows])
        self._commit()

    def bulk_insert_isotope_entropy(self, rows):
        self._conn.executemany(
            "INSERT INTO isotope_entropy "
            "(section_name, offset, length, entropy, is_packed, is_encrypted) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r.get("section_name"), r.get("offset"), r.get("length"),
              r["entropy"], r.get("is_packed", 0), r.get("is_encrypted", 0))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_secrets(self, rows):
        self._conn.executemany(
            "INSERT INTO isotope_secrets "
            "(secret_type, value_preview, file_path, line_number, confidence, context) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["secret_type"], r.get("value_preview"), r.get("file_path"),
              r.get("line_number"), r.get("confidence", "medium"),
              r.get("context"))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_code(self, rows):
        self._conn.executemany(
            "INSERT INTO isotope_code "
            "(language, file_path, function_name, vulnerability_type, "
            "severity, line_number, code_snippet, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(r.get("language"), r.get("file_path"), r.get("function_name"),
              r.get("vulnerability_type"), r.get("severity"),
              r.get("line_number"), r.get("code_snippet"), r.get("description"))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_binary(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO isotope_binary "
            "(key, value, category, details_json) VALUES (?, ?, ?, ?)",
            [(r["key"], r.get("value"), r.get("category"),
              r.get("details_json", "{}"))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_iocs(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO isotope_iocs "
            "(ioc_type, value, source, confidence, threat_name, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(r["ioc_type"], r["value"], r.get("source"),
              r.get("confidence", "medium"), r.get("threat_name"),
              r.get("first_seen"))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_contents(self, rows):
        self._conn.executemany(
            "INSERT INTO isotope_contents "
            "(path, file_type, size, modified_at, entropy, is_encrypted, hash_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(r["path"], r.get("file_type"), r.get("size"),
              r.get("modified_at"), r.get("entropy"),
              r.get("is_encrypted", 0), r.get("hash_sha256"))
             for r in rows])
        self._commit()

    def bulk_insert_isotope_metadata(self, rows):
        self._conn.executemany(
            "INSERT OR REPLACE INTO isotope_metadata (key, value, source) "
            "VALUES (?, ?, ?)",
            [(r["key"], r.get("value"), r.get("source")) for r in rows])
        self._commit()

    def query_isotope_strings(self, page=1, per_page=100, string_type=None,
                              interesting_only=False, search=None):
        where, params = [], []
        if string_type:
            where.append("string_type = ?"); params.append(string_type)
        if interesting_only:
            where.append("is_interesting = 1")
        if search:
            where.append("value LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_strings {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_strings {w} ORDER BY offset LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_strings LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_properties(self, page=1, per_page=50, category=None, search=None):
        where, params = [], []
        if category:
            where.append("category = ?"); params.append(category)
        if search:
            where.append("(key LIKE ? OR value LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_properties {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_properties {w} ORDER BY key LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_properties LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_entropy(self, page=1, per_page=50, packed_only=False,
                              encrypted_only=False):
        where, params = [], []
        if packed_only:
            where.append("is_packed = 1")
        if encrypted_only:
            where.append("is_encrypted = 1")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_entropy {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_entropy {w} ORDER BY offset LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_entropy LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_secrets(self, page=1, per_page=50, secret_type=None,
                              confidence=None, search=None):
        where, params = [], []
        if secret_type:
            where.append("secret_type = ?"); params.append(secret_type)
        if confidence:
            where.append("confidence = ?"); params.append(confidence)
        if search:
            where.append("(value_preview LIKE ? OR file_path LIKE ? OR context LIKE ?)");
            params.extend([f"%{search}%"] * 3)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_secrets {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_secrets {w} ORDER BY secret_type LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_secrets LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_code(self, page=1, per_page=50, language=None,
                           severity=None, vulnerability_type=None, search=None):
        where, params = [], []
        if language:
            where.append("language = ?"); params.append(language)
        if severity:
            where.append("severity = ?"); params.append(severity)
        if vulnerability_type:
            where.append("vulnerability_type = ?"); params.append(vulnerability_type)
        if search:
            where.append("(function_name LIKE ? OR description LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_code {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_code {w} ORDER BY severity, language LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_code LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_binary(self, page=1, per_page=50, category=None, search=None):
        where, params = [], []
        if category:
            where.append("category = ?"); params.append(category)
        if search:
            where.append("(key LIKE ? OR value LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_binary {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_binary {w} ORDER BY category, key LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_binary LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_iocs(self, page=1, per_page=50, ioc_type=None,
                           confidence=None, search=None):
        where, params = [], []
        if ioc_type:
            where.append("ioc_type = ?"); params.append(ioc_type)
        if confidence:
            where.append("confidence = ?"); params.append(confidence)
        if search:
            where.append("(value LIKE ? OR threat_name LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_iocs {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_iocs {w} ORDER BY ioc_type, value LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_iocs LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_contents(self, page=1, per_page=50, file_type=None,
                               encrypted_only=False, search=None):
        where, params = [], []
        if file_type:
            where.append("file_type = ?"); params.append(file_type)
        if encrypted_only:
            where.append("is_encrypted = 1")
        if search:
            where.append("path LIKE ?"); params.append(f"%{search}%")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_contents {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_contents {w} ORDER BY path LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_contents LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}

    def query_isotope_metadata(self, page=1, per_page=50, source=None, search=None):
        where, params = [], []
        if source:
            where.append("source = ?"); params.append(source)
        if search:
            where.append("(key LIKE ? OR value LIKE ?)"); params.extend([f"%{search}%"] * 2)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self._conn.execute(f"SELECT COUNT(*) FROM isotope_metadata {w}", params).fetchone()[0]
        rows = self._conn.execute(
            f"SELECT * FROM isotope_metadata {w} ORDER BY source, key LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page]).fetchall()
        cols = [d[0] for d in self._conn.execute("SELECT * FROM isotope_metadata LIMIT 0").description]
        return {"items": [dict(zip(cols, r)) for r in rows], "total": total,
                "page": page, "pages": (total + per_page - 1) // per_page}


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
