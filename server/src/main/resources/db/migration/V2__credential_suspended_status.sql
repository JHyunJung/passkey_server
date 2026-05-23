-- V2: Add SUSPENDED status to credential lifecycle (MDS post-registration revocation).
-- See docs/superpowers/specs/2026-05-23-mds-post-registration-revocation-design.md §5.

-- (1) Replace status CHECK to allow SUSPENDED. ACTIVE/REVOKED unchanged.
ALTER TABLE credential DROP CONSTRAINT ck_cred_status;
ALTER TABLE credential ADD CONSTRAINT ck_cred_status
  CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED'));

-- (2) Suspended metadata columns (nullable — non-SUSPENDED rows leave them NULL).
ALTER TABLE credential ADD (
  suspended_at      TIMESTAMP(6) WITH TIME ZONE NULL,
  suspended_reason  VARCHAR2(64)                NULL,
  unsuspended_at    TIMESTAMP(6) WITH TIME ZONE NULL,
  unsuspended_by    VARCHAR2(128)               NULL
);

-- (3) Index for "find ACTIVE rows by AAGUID" scan path.
-- aaguid is sparse (most rows non-null), status is enum-cardinality 3.
-- Tenant_id intentionally omitted: APP_ADMIN scans cross-tenant.
CREATE INDEX ix_credential_aaguid_status ON credential (aaguid, status);
