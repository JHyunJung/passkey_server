-- ============================================================
-- V18__audit_log_partition_helper.sql
-- A Postgres function that idempotently creates the {month, month+1} partitions of audit_log so
-- a daily Spring scheduler can call it without coordinating with the operator. Without this, the
-- first INSERT on the 1st of an uncovered month fails with "no partition of relation".
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE OR REPLACE FUNCTION ensure_audit_log_partition(target date)
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
AS $$
DECLARE
    part_start date := date_trunc('month', target)::date;
    part_end   date := (date_trunc('month', target) + interval '1 month')::date;
    part_name  text := format('audit_log_%s', to_char(part_start, 'YYYY_MM'));
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN   pg_namespace n ON n.oid = c.relnamespace
        WHERE  n.nspname = 'passkey' AND c.relname = part_name
    ) THEN
        EXECUTE format(
            'CREATE TABLE passkey.%I PARTITION OF passkey.audit_log FOR VALUES FROM (%L) TO (%L)',
            part_name, part_start, part_end);
        RAISE NOTICE 'audit_log partition % created for [% .. %)', part_name, part_start, part_end;
    END IF;
END;
$$;

-- Owner default; runtime needs EXECUTE so the application scheduler can call it without elevating
-- to the app_admin role.
ALTER FUNCTION ensure_audit_log_partition(date) OWNER TO app_migrator;
GRANT EXECUTE ON FUNCTION ensure_audit_log_partition(date) TO app_runtime;
GRANT EXECUTE ON FUNCTION ensure_audit_log_partition(date) TO app_admin;

-- Backfill: make sure the *current* and *next* month exist regardless of when this migration runs.
SELECT ensure_audit_log_partition(current_date);
SELECT ensure_audit_log_partition((current_date + interval '1 month')::date);
