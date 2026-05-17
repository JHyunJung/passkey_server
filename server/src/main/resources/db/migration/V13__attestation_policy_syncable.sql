-- ============================================================
-- V13__attestation_policy_syncable.sql
-- Per-tenant opt-out for syncable / backup-eligible authenticators (iCloud Keychain, Google
-- Password Manager, etc.). Default TRUE preserves existing behaviour. Set FALSE for tenants whose
-- compliance regime requires hardware-bound passkeys only.
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE tenant_attestation_policy
    ADD COLUMN allow_syncable BOOLEAN NOT NULL DEFAULT TRUE;
