-- ============================================================
-- V3__create_webauthn_config.sql
-- Per-tenant WebAuthn Relying Party configuration: RP ID, RP name, origins (CSV),
-- ceremony timeout, user verification policy.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE tenant_webauthn_config (
    id                       uuid        PRIMARY KEY,
    tenant_id                uuid        NOT NULL REFERENCES tenant(id),
    rp_id                    text        NOT NULL,
    rp_name                  text        NOT NULL,
    origins                  text        NOT NULL,
    timeout_ms               integer     NOT NULL DEFAULT 60000,
    user_verification        text        NOT NULL DEFAULT 'PREFERRED',
    attestation_conveyance   text        NOT NULL DEFAULT 'NONE',
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_tenant_webauthn_config__tenant UNIQUE (tenant_id),
    CONSTRAINT ck_tenant_webauthn_config__user_verification
        CHECK (user_verification IN ('REQUIRED','PREFERRED','DISCOURAGED')),
    CONSTRAINT ck_tenant_webauthn_config__attestation_conveyance
        CHECK (attestation_conveyance IN ('NONE','INDIRECT','DIRECT','ENTERPRISE'))
);

CREATE INDEX ix_tenant_webauthn_config__tenant ON tenant_webauthn_config(tenant_id);

ALTER TABLE tenant_webauthn_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webauthn_config FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_webauthn_config TO app_runtime, app_admin;
