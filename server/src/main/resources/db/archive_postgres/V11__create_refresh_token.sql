-- ============================================================
-- V11__create_refresh_token.sql
-- Stateful refresh-token store. Each issued refresh JWT is recorded by its `jti` so the server can
-- (a) revoke a single token, (b) revoke all tokens of a user (e.g. credential revoke), (c) detect
-- reuse of a rotated token and burn the entire family. Per-tenant RLS — refresh-time lookups must
-- happen with TenantContextHolder set (handled by the new /api/v1/rp/auth/refresh endpoint which
-- runs under the RP API-key chain).
-- ============================================================

SET LOCAL search_path TO passkey;

-- The PK column is named `id` to match the BaseEntity contract (TenantScopedEntity → BaseEntity).
-- Semantically the `id` value IS the JWT jti claim; this keeps the JPA mapping straightforward.
CREATE TABLE refresh_token (
    id               uuid        PRIMARY KEY,                      -- = JWT jti
    tenant_id        uuid        NOT NULL REFERENCES tenant(id),
    tenant_user_id   uuid        NOT NULL REFERENCES tenant_user(id),
    parent_jti       uuid,                                  -- rotation lineage; NULL on first issue
    issued_at        timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    revoked_reason   text,                                  -- enum-ish: ROTATED, USER_LOGOUT, CREDENTIAL_REVOKED, REUSE_DETECTED, ADMIN_FORCED
    client_ip        text,
    user_agent       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_refresh_token__user_active
    ON refresh_token (tenant_user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX ix_refresh_token__expires_at
    ON refresh_token (expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX ix_refresh_token__parent
    ON refresh_token (parent_jti)
    WHERE parent_jti IS NOT NULL;

ALTER TABLE refresh_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_token FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_token TO app_runtime, app_admin;
