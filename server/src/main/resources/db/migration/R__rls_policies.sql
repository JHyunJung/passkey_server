-- ============================================================
-- R__rls_policies.sql  (repeatable — re-applied when this file's hash changes)
-- Desired state for all Row-Level Security policies in schema `passkey`.
-- Adding a tenant-scoped table requires updating this file in the same PR.
-- ============================================================

SET LOCAL search_path TO passkey;

-- tenant_user ----------------------------------------------------------------
DROP POLICY IF EXISTS tenant_user_isolation ON tenant_user;
CREATE POLICY tenant_user_isolation ON tenant_user
    USING       (tenant_id = passkey.current_tenant_id())
    WITH CHECK  (tenant_id = passkey.current_tenant_id());

-- tenant_webauthn_config (M2) ------------------------------------------------
DROP POLICY IF EXISTS tenant_webauthn_config_isolation ON tenant_webauthn_config;
CREATE POLICY tenant_webauthn_config_isolation ON tenant_webauthn_config
    USING       (tenant_id = passkey.current_tenant_id())
    WITH CHECK  (tenant_id = passkey.current_tenant_id());

-- credential (M2) ------------------------------------------------------------
DROP POLICY IF EXISTS credential_isolation ON credential;
CREATE POLICY credential_isolation ON credential
    USING       (tenant_id = passkey.current_tenant_id())
    WITH CHECK  (tenant_id = passkey.current_tenant_id());

-- tenant_attestation_policy (M2) ---------------------------------------------
DROP POLICY IF EXISTS tenant_attestation_policy_isolation ON tenant_attestation_policy;
CREATE POLICY tenant_attestation_policy_isolation ON tenant_attestation_policy
    USING       (tenant_id = passkey.current_tenant_id())
    WITH CHECK  (tenant_id = passkey.current_tenant_id());

-- audit_log (M3) -------------------------------------------------------------
DROP POLICY IF EXISTS audit_log_isolation ON audit_log;
CREATE POLICY audit_log_isolation ON audit_log
    USING       (tenant_id = passkey.current_tenant_id())
    WITH CHECK  (tenant_id = passkey.current_tenant_id());
