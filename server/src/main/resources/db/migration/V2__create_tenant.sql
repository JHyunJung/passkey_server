-- ============================================================
-- V2__create_tenant.sql
-- Creates the `tenant` and `tenant_user` tables.
-- `tenant`      is RLS-exempt (resolution target).
-- `tenant_user` is tenant-scoped — ENABLE + FORCE RLS. Policies live in R__rls_policies.sql.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE tenant (
    id          uuid        PRIMARY KEY,
    name        text        NOT NULL,
    slug        text        NOT NULL,
    status      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_tenant__slug UNIQUE (slug),
    CONSTRAINT ck_tenant__status CHECK (status IN ('ACTIVE','SUSPENDED','DELETED'))
);

CREATE TABLE tenant_user (
    id            uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES tenant(id),
    external_id   text        NOT NULL,
    display_name  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_tenant_user__tenant_external UNIQUE (tenant_id, external_id)
);

CREATE INDEX ix_tenant_user__tenant ON tenant_user(tenant_id);

-- RLS: enable + force. Policies in R__rls_policies.sql.
ALTER TABLE tenant_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_user FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE         ON tenant      TO app_runtime, app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_user TO app_runtime, app_admin;
