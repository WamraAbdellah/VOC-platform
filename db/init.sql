-- ════════════════════════════════════════════════════════
--  VOC Platform - Database Schema
-- ════════════════════════════════════════════════════════

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- full text search

-- ─── ENUM TYPES ─────────────────────────────────────────
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE vuln_status AS ENUM ('NEW', 'QUALIFIED', 'IN_REMEDIATION', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE');
CREATE TYPE asset_type AS ENUM ('SERVER', 'WORKSTATION', 'NETWORK_DEVICE', 'WEB_APP', 'CONTAINER', 'DATABASE', 'CLOUD');
CREATE TYPE environment_type AS ENUM ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST');
CREATE TYPE scan_type AS ENUM ('NMAP', 'NUCLEI', 'TRIVY', 'OPENVAS', 'NIKTO', 'MANUAL');
CREATE TYPE scan_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');
CREATE TYPE ticket_status AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED');

-- ─── ORGANIZATIONS ──────────────────────────────────────
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ─── USERS ──────────────────────────────────────────────
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'analyst',  -- admin, manager, analyst, viewer
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ─── ASSETS ─────────────────────────────────────────────
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    asset_type asset_type NOT NULL,
    environment environment_type DEFAULT 'PRODUCTION',
    business_criticality INTEGER DEFAULT 3 CHECK (business_criticality BETWEEN 1 AND 5),
    -- 5=Mission Critical, 4=High, 3=Medium, 2=Low, 1=Minimal
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    is_internet_exposed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_assets_org ON assets(org_id);

-- ─── CVE CACHE ──────────────────────────────────────────
CREATE TABLE cve_cache (
    cve_id VARCHAR(50) PRIMARY KEY,  -- e.g. CVE-2021-44228
    description TEXT,
    cvss_v2_score FLOAT,
    cvss_v3_score FLOAT,
    cvss_v3_vector VARCHAR(255),
    severity severity_level,
    cwe_ids JSONB DEFAULT '[]',
    references JSONB DEFAULT '[]',
    -- Enrichissement
    epss_score FLOAT,          -- Exploit Prediction Scoring System (0-1)
    epss_percentile FLOAT,
    is_in_kev BOOLEAN DEFAULT FALSE,  -- CISA Known Exploited Vulnerabilities
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(50),  -- POC, FUNCTIONAL, HIGH
    greynoise_noise BOOLEAN,       -- Exploité massivement sur internet
    greynoise_riot BOOLEAN,
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,
    cached_at TIMESTAMP DEFAULT NOW(),
    raw_nvd_data JSONB
);

-- ─── SCANS ──────────────────────────────────────────────
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    name VARCHAR(255),
    scan_type scan_type NOT NULL,
    status scan_status DEFAULT 'PENDING',
    target TEXT NOT NULL,  -- IP, range, URL
    options JSONB DEFAULT '{}',
    started_by UUID REFERENCES users(id),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    raw_output_path VARCHAR(500),
    vulnerabilities_found INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scans_org ON scans(org_id);
CREATE INDEX idx_scans_status ON scans(status);

-- ─── VULNERABILITIES ────────────────────────────────────
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    asset_id UUID REFERENCES assets(id),
    scan_id UUID REFERENCES scans(id),
    cve_id VARCHAR(50) REFERENCES cve_cache(cve_id),
    
    -- Détection
    title VARCHAR(500) NOT NULL,
    description TEXT,
    affected_component VARCHAR(255),
    port INTEGER,
    protocol VARCHAR(20),
    
    -- Scoring
    cvss_score FLOAT,
    cvss_vector VARCHAR(255),
    severity severity_level NOT NULL,
    
    -- Scoring contextualisé VOC (au-delà du CVSS)
    voc_score FLOAT,  -- Score final calculé
    exposure_score FLOAT,       -- Exposition internet
    business_impact_score FLOAT, -- Criticité métier
    exploitability_score FLOAT, -- Exploitabilité réelle
    environment_factor FLOAT,   -- Prod vs préprod
    
    -- Statut
    status vuln_status DEFAULT 'NEW',
    first_detected TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    
    -- Remédiation
    remediation_advice TEXT,
    remediation_deadline TIMESTAMP,
    assigned_to UUID REFERENCES users(id),
    
    -- Métadonnées
    is_false_positive BOOLEAN DEFAULT FALSE,
    false_positive_reason TEXT,
    risk_accepted BOOLEAN DEFAULT FALSE,
    risk_accepted_reason TEXT,
    risk_accepted_until TIMESTAMP,
    
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_vulns_org ON vulnerabilities(org_id);
CREATE INDEX idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_voc_score ON vulnerabilities(voc_score DESC);

-- ─── REMEDIATION TICKETS ────────────────────────────────
CREATE TABLE tickets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    status ticket_status DEFAULT 'OPEN',
    priority VARCHAR(20) DEFAULT 'MEDIUM',
    assigned_to UUID REFERENCES users(id),
    created_by UUID REFERENCES users(id),
    due_date TIMESTAMP,
    resolved_at TIMESTAMP,
    comments JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ─── AUDIT LOG ──────────────────────────────────────────
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- ─── KPI SNAPSHOTS (pour les dashboards) ────────────────
CREATE TABLE kpi_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    snapshot_date DATE NOT NULL,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    resolved_count INTEGER DEFAULT 0,
    mttr_days FLOAT,  -- Mean Time To Remediate
    kev_unpatched INTEGER DEFAULT 0,  -- CVEs CISA KEV non patchées
    backlog_age_avg FLOAT,  -- âge moyen du backlog en jours
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(org_id, snapshot_date)
);

-- ─── NOTIFICATIONS ──────────────────────────────────────
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    title VARCHAR(255) NOT NULL,
    message TEXT,
    type VARCHAR(50) DEFAULT 'info',  -- info, warning, critical, success
    is_read BOOLEAN DEFAULT FALSE,
    related_resource_type VARCHAR(100),
    related_resource_id UUID,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ─── DEFAULT DATA ────────────────────────────────────────
INSERT INTO organizations (id, name, description) VALUES 
(uuid_generate_v4(), 'Default Organization', 'Default VOC organization');

-- Vue pour les statistiques rapides
CREATE VIEW vuln_stats AS
SELECT 
    org_id,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
    COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
    COUNT(*) FILTER (WHERE severity = 'LOW') as low,
    COUNT(*) FILTER (WHERE status = 'RESOLVED') as resolved,
    COUNT(*) FILTER (WHERE status = 'NEW') as new_vulns,
    AVG(voc_score) as avg_voc_score
FROM vulnerabilities
WHERE is_false_positive = FALSE
GROUP BY org_id;

-- Vue MTTR (Mean Time To Remediate)
CREATE VIEW mttr_view AS
SELECT 
    org_id,
    severity,
    AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected)) / 86400) as avg_days,
    COUNT(*) as count
FROM vulnerabilities
WHERE status = 'RESOLVED' AND resolved_at IS NOT NULL
GROUP BY org_id, severity;
