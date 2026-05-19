-- ============================================================
-- V16__webauthn_config_cred_protect.sql
-- Tenant-level credProtect requirement embedded in registration options.
-- NONE                    — extension not sent (legacy / discoverability allowed)
-- UV_OPTIONAL             — credProtect=1, no enforcement
-- UV_OPTIONAL_WITH_CREDID — credProtect=2, list-by-credentialId still works
-- UV_REQUIRED             — credProtect=3, every read requires user verification (금융권 권장)
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE tenant_webauthn_config
    ADD COLUMN cred_protect TEXT NOT NULL DEFAULT 'NONE';

ALTER TABLE tenant_webauthn_config
    ADD CONSTRAINT ck_tenant_webauthn_config__cred_protect
        CHECK (cred_protect IN ('NONE', 'UV_OPTIONAL', 'UV_OPTIONAL_WITH_CREDID', 'UV_REQUIRED'));
