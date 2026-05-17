-- ============================================================
-- V12__attestation_policy_allow_zero_aaguid.sql
-- Closes the AAGUID null/zero bypass: previously `accepts(null)` was true under DENYLIST/ANY.
-- This column is the explicit opt-in to allow null/zero AAGUID. Default FALSE = strict.
-- Existing tenants get strict behaviour automatically — operators can flip ON per tenant if their
-- ecosystem includes legacy authenticators that report no AAGUID.
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE tenant_attestation_policy
    ADD COLUMN allow_zero_aaguid BOOLEAN NOT NULL DEFAULT FALSE;
