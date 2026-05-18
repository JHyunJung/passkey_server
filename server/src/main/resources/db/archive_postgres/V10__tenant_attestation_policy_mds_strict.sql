-- ============================================================
-- V10__tenant_attestation_policy_mds_strict.sql
-- MDS strict toggle per tenant. When true, register flow uses the strict WebAuthnManager backed
-- by FIDO MDS3 trust anchors and rejects authenticators with REVOKED/COMPROMISED StatusReport.
-- Default false preserves existing non-strict behaviour for all current rows.
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE tenant_attestation_policy
    ADD COLUMN mds_strict BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenant_attestation_policy.mds_strict IS
    'When true, register flow uses strict WebAuthnManager backed by FIDO MDS trust anchors. '
    'Requires passkey.mds.enabled=true on the server; otherwise registration fails with MDS_UNAVAILABLE.';
