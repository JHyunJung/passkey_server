-- ============================================================
-- V7__create_audit_log.sql
-- Append-only audit log. Range-partitioned by created_at (monthly) for hot-write isolation and
-- cheap retention pruning. Per-tenant hash chain (prev_hash → row_hash).
--
-- Operational note: this migration creates the parent table and *two* initial partitions covering
-- 2026-05 and 2026-06. Future-month partitions must be created by a scheduled job before traffic
-- writes into them (a typical "create_partition_if_needed" maintenance task). Out of scope for M3
-- automation but designed for it.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE audit_log (
    id           uuid        NOT NULL,
    tenant_id    uuid        NOT NULL REFERENCES tenant(id),
    event_type   text        NOT NULL,
    actor_type   text        NOT NULL,                -- 'END_USER' | 'RP_API' | 'ADMIN' | 'SYSTEM'
    actor_id     text,
    subject_type text,                                 -- 'CREDENTIAL' | 'TENANT_USER' | 'API_KEY' | ...
    subject_id   text,
    payload      jsonb,
    prev_hash    text,                                 -- base64url of previous row's row_hash within this tenant chain
    row_hash     text        NOT NULL,                 -- SHA-256(prev_hash || canonical(payload))
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX ix_audit_log__tenant_created ON audit_log(tenant_id, created_at);

CREATE TABLE audit_log_2026_05 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_log_2026_06 PARTITION OF audit_log
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT ON audit_log TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_log TO app_admin;
