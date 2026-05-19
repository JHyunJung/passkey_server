-- ============================================================
-- V6__create_api_key.sql
-- Per-tenant API keys for RP-side authentication. Argon2id hash stored; plaintext is shown
-- exactly once at provisioning time.
--
-- Lookup pattern: key is "pk_<prefix>.<secret>". The 8-byte prefix is indexed for fast
-- per-tenant filtering; the secret is Argon2-verified at runtime.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE api_key (
    id            uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES tenant(id),
    prefix        text        NOT NULL,
    secret_hash   text        NOT NULL,
    name          text        NOT NULL,
    status        text        NOT NULL DEFAULT 'ACTIVE',
    last_used_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_api_key__prefix UNIQUE (prefix),
    CONSTRAINT ck_api_key__status CHECK (status IN ('ACTIVE','REVOKED'))
);

CREATE INDEX ix_api_key__tenant ON api_key(tenant_id);

-- NOTE: api_key is RLS-exempt by design. It must be queryable BEFORE the tenant context is set
-- (the resolver looks up the key prefix to *find* which tenant the request belongs to).
-- The prefix is treated as a public identifier; the secret hash + Argon2 verify is the actual
-- gate. app_runtime gets SELECT/UPDATE (for last_used_at touch) but only app_admin can INSERT
-- new keys (via the admin console, M4).

GRANT SELECT, UPDATE ON api_key TO app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_key TO app_admin;
