-- ============================================================
-- V14__webauthn_config_resident_key.sql
-- Tenant-level resident-key requirement. Default PREFERRED preserves prior hard-coded behaviour.
-- Set REQUIRED for usernameless / discoverable-credential first deployments — this becomes
-- requireResidentKey=true in the registration options the SDK sends to the browser.
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE tenant_webauthn_config
    ADD COLUMN resident_key TEXT NOT NULL DEFAULT 'PREFERRED';

ALTER TABLE tenant_webauthn_config
    ADD CONSTRAINT ck_tenant_webauthn_config__resident_key
        CHECK (resident_key IN ('REQUIRED','PREFERRED','DISCOURAGED'));
