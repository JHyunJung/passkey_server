-- ============================================================
-- V1__baseline.sql
-- Roles (3-tier), schema, extensions, helper function for RLS.
-- ============================================================

-- 1. Roles --------------------------------------------------------------------
-- app_migrator is provided by docker-compose POSTGRES_USER (owner).
-- app_runtime  : RP API + RP admin traffic. NOBYPASSRLS NOSUPERUSER.
-- app_admin    : Platform Operator traffic only. BYPASSRLS.

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_runtime') THEN
    EXECUTE format(
      'CREATE ROLE app_runtime LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE',
      '${app_runtime_password}'
    );
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin') THEN
    EXECUTE format(
      'CREATE ROLE app_admin LOGIN PASSWORD %L NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE',
      '${app_admin_password}'
    );
  END IF;
END $$;

-- 2. Schema -------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS passkey AUTHORIZATION app_migrator;

GRANT USAGE ON SCHEMA passkey TO app_runtime, app_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA passkey
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime, app_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA passkey
    GRANT USAGE, SELECT ON SEQUENCES TO app_runtime, app_admin;

-- 3. Extensions ---------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 4. Helper function: current_tenant_id() -------------------------------------
-- Returns NULL when app.current_tenant is unset → fail-closed (RLS yields 0 rows).
CREATE OR REPLACE FUNCTION passkey.current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid
$$;

GRANT EXECUTE ON FUNCTION passkey.current_tenant_id() TO app_runtime, app_admin;
