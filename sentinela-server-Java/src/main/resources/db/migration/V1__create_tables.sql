-- =============================================================
-- Sentinela DevSecOps — Initial Schema
-- V1__create_tables.sql
-- =============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Agents
CREATE TABLE IF NOT EXISTS agents (
    id             VARCHAR(36)   PRIMARY KEY,
    agent_id       VARCHAR(100)  NOT NULL UNIQUE,
    name           VARCHAR(255)  NOT NULL,
    token_hash     VARCHAR(64)   NOT NULL UNIQUE,
    public_key     TEXT,
    active         BOOLEAN       NOT NULL DEFAULT TRUE,
    environment    VARCHAR(20)   NOT NULL DEFAULT 'PRODUCTION',
    last_seen      TIMESTAMPTZ,
    cpu_usage_pct  DOUBLE PRECISION,
    buffer_pending INTEGER       NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Users (dashboard)
CREATE TABLE IF NOT EXISTS users (
    id          VARCHAR(36)  PRIMARY KEY,
    username    VARCHAR(100) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'ANALYST',
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id              VARCHAR(36)  PRIMARY KEY,
    agent_id        VARCHAR(100) NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'OPEN',
    rule_id         VARCHAR(100) NOT NULL,
    file_path       VARCHAR(500) NOT NULL,
    secret_preview  VARCHAR(200) NOT NULL,
    line_number     INTEGER,
    checksum        VARCHAR(64)  NOT NULL UNIQUE,
    event_time      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolution_note TEXT,
    resolved_at     TIMESTAMPTZ,
    resolved_by     VARCHAR(100)
);

-- Audit logs — IMMUTABLE, no UPDATE/DELETE permissions should be granted
CREATE TABLE IF NOT EXISTS audit_logs (
    id           VARCHAR(36)  PRIMARY KEY,
    action       VARCHAR(100) NOT NULL,
    entity_type  VARCHAR(100) NOT NULL,
    entity_id    VARCHAR(36),
    agent_id     VARCHAR(100),
    user_id      VARCHAR(36),
    details      TEXT,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_checksum    ON alerts (checksum);
CREATE INDEX IF NOT EXISTS idx_alert_severity           ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alert_agent_id           ON alerts (agent_id);
CREATE INDEX IF NOT EXISTS idx_alert_event_time         ON alerts (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alert_status             ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_agent_token_hash         ON agents (token_hash);
CREATE INDEX IF NOT EXISTS idx_audit_entity             ON audit_logs (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at         ON audit_logs (created_at DESC);

-- Revoke dangerous permissions on audit_logs (PostgreSQL — run as superuser in prod)
-- REVOKE UPDATE, DELETE ON audit_logs FROM sentinela_user;
