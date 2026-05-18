-- ============================================================
-- V9__audit_funnel_index.sql
-- Speeds up AdminFunnelController's per-tenant + per-event-type aggregation. Partial index on
-- the two hottest event types keeps the index small.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE INDEX IF NOT EXISTS ix_audit_log__tenant_event_created
    ON audit_log (tenant_id, event_type, created_at)
    WHERE event_type IN ('CREDENTIAL_REGISTERED', 'CREDENTIAL_AUTHENTICATED');
