-- ============================================================
-- V8__create_admin_user.sql
-- Admin console users.
-- tenant_id NULL → Platform Operator (cross-tenant access via app_admin DataSource).
-- tenant_id set  → RP Admin (本 tenant 한정, RLS 적용).
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE admin_user (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        REFERENCES tenant(id),
    email           text        NOT NULL,
    password_hash   text        NOT NULL,
    display_name    text        NOT NULL,
    role            text        NOT NULL,
    status          text        NOT NULL DEFAULT 'ACTIVE',
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_admin_user__email UNIQUE (email),
    CONSTRAINT ck_admin_user__role CHECK (role IN ('PLATFORM_OPERATOR','RP_ADMIN')),
    CONSTRAINT ck_admin_user__status CHECK (status IN ('ACTIVE','SUSPENDED')),
    CONSTRAINT ck_admin_user__tenant_for_rp
        CHECK ((role = 'PLATFORM_OPERATOR' AND tenant_id IS NULL)
            OR (role = 'RP_ADMIN'           AND tenant_id IS NOT NULL))
);

CREATE INDEX ix_admin_user__tenant ON admin_user(tenant_id);

-- admin_user is intentionally RLS-exempt at the DB layer — login lookup happens before tenant
-- context is set. Authorization is enforced in the application layer (AdminAuthorizationFilter).
GRANT SELECT, INSERT, UPDATE ON admin_user TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_user TO app_admin;
