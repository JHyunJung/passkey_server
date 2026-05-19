-- ============================================================
-- V5__create_attestation_policy.sql
-- Per-tenant AAGUID allowlist/denylist. M2 ships static lists; MDS BLOB integration is deferred
-- to v1.1.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE tenant_attestation_policy (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenant(id),
    mode            text        NOT NULL DEFAULT 'ANY',
    allowed_aaguids text,
    denied_aaguids  text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_tenant_attestation_policy__tenant UNIQUE (tenant_id),
    CONSTRAINT ck_tenant_attestation_policy__mode CHECK (mode IN ('ANY','ALLOWLIST','DENYLIST'))
);

ALTER TABLE tenant_attestation_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_attestation_policy FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_attestation_policy TO app_runtime, app_admin;
