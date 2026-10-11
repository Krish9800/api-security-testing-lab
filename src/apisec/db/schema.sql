-- SQLite Schema for API Security Testing Lab with WAL mode

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id TEXT PRIMARY KEY,
    target_base_url TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    total_endpoints INTEGER DEFAULT 0,
    total_checks INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    verdict TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    cwe_id TEXT,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS http_transactions (
    request_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    request_body TEXT,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL,
    response_body TEXT,
    response_time_ms REAL NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES scan_findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON scan_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON scan_findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity);
CREATE INDEX IF NOT EXISTS idx_tx_finding ON http_transactions(finding_id);
