-- ============================================================
-- V4__create_credential.sql
-- WebAuthn credential storage. Public key + credential id (raw bytes, base64url-encoded for
-- storage), signature counter, AAGUID, transports, user-handle. tenant-scoped + RLS.
-- ============================================================

SET LOCAL search_path TO passkey;

CREATE TABLE credential (
    id                      uuid        PRIMARY KEY,
    tenant_id               uuid        NOT NULL REFERENCES tenant(id),
    tenant_user_id          uuid        NOT NULL REFERENCES tenant_user(id),
    credential_id           text        NOT NULL,                       -- base64url-encoded raw id
    public_key_cose         bytea       NOT NULL,                       -- raw COSE public key
    aaguid                  uuid,
    transports              text,                                       -- CSV: "usb,nfc,ble,internal,hybrid"
    user_handle             text        NOT NULL,                       -- base64url-encoded
    signature_counter       bigint      NOT NULL DEFAULT 0,
    backup_eligible         boolean     NOT NULL DEFAULT false,
    backup_state            boolean     NOT NULL DEFAULT false,
    nickname                text,
    status                  text        NOT NULL DEFAULT 'ACTIVE',
    last_used_at            timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_credential__credential_id_per_tenant
        UNIQUE (tenant_id, credential_id),
    CONSTRAINT ck_credential__status CHECK (status IN ('ACTIVE','REVOKED'))
);

CREATE INDEX ix_credential__tenant_user ON credential(tenant_id, tenant_user_id);
CREATE INDEX ix_credential__credential_id ON credential(tenant_id, credential_id);

ALTER TABLE credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON credential TO app_runtime, app_admin;
