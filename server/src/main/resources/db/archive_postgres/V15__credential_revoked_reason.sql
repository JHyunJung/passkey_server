-- ============================================================
-- V15__credential_revoked_reason.sql
-- Capture WHO/WHEN/WHY a credential was revoked. Required for the account-recovery runbook —
-- end-user CS needs to tell a caller "your passkey was revoked at <time> because of <reason>".
-- Reasons are an enum; the CHECK constraint pins the vocabulary so admin SPA / RP CS can rely on
-- it. NULL = active (never revoked).
-- ============================================================

SET LOCAL search_path TO passkey;

ALTER TABLE credential
    ADD COLUMN revoked_at     timestamptz,
    ADD COLUMN revoked_reason text;

ALTER TABLE credential
    ADD CONSTRAINT ck_credential__revoked_reason
        CHECK (revoked_reason IS NULL
               OR revoked_reason IN ('USER_REQUEST',
                                     'ADMIN_FORCED',
                                     'COMPROMISE_SUSPECTED',
                                     'SIGNATURE_COUNTER_REGRESSION',
                                     'LIFECYCLE_EXPIRED'));
