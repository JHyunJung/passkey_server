-- ============================================================
-- V1__oracle_baseline.sql
-- Oracle 19c baseline. Replaces the entire PostgreSQL V1-V18 history (see ../archive_postgres/).
--
-- Layout:
--   1. Users: APP_RUNTIME (no EXEMPT ACCESS POLICY), APP_ADMIN (with), connected to PASSKEY schema
--      owned by APP_MIGRATOR (the Flyway runner).
--   2. Application context PASSKEY_CTX + setter package — secure context, only the package can
--      mutate `tenant_id`. Client sessions cannot bypass via direct DBMS_SESSION calls.
--   3. Seven tenant-scoped tables + tenant + admin_user + api_key (RLS-exempt where needed).
--   4. audit_log uses Interval Partitioning so monthly partitions auto-create.
--   5. scheduler_lease — leader-election table used by AuditChainScheduler (replaces
--      pg_try_advisory_xact_lock).
--   6. Grants. Note: VPD policy attachment lives in R__vpd_policies.sql (repeatable, idempotent).
--
-- Idempotency: Flyway runs V1 exactly once, so CREATE statements do not need IF NOT EXISTS guards.
-- ============================================================

-- 1. Users --------------------------------------------------------------------
-- The PASSKEY schema is owned by APP_MIGRATOR. Flyway connects as APP_MIGRATOR; runtime traffic
-- runs as APP_RUNTIME; cross-tenant admin queries run as APP_ADMIN.
--
-- Oracle has no PostgreSQL "BYPASSRLS" attribute. The Oracle equivalent is the system privilege
-- EXEMPT ACCESS POLICY — granted only to APP_ADMIN. APP_RUNTIME never gets it, so VPD policies
-- are enforced for every runtime query.
--
-- IDENTIFIED BY uses Flyway placeholders interpolated from
-- spring.flyway.placeholders.app_runtime_password / app_admin_password.

CREATE USER APP_RUNTIME IDENTIFIED BY "${app_runtime_password}"
    DEFAULT TABLESPACE USERS
    QUOTA UNLIMITED ON USERS;

CREATE USER APP_ADMIN IDENTIFIED BY "${app_admin_password}"
    DEFAULT TABLESPACE USERS
    QUOTA UNLIMITED ON USERS;

GRANT CREATE SESSION TO APP_RUNTIME;
GRANT CREATE SESSION TO APP_ADMIN;

-- EXEMPT ACCESS POLICY: lets APP_ADMIN bypass every VPD policy. Equivalent to the old
-- BYPASSRLS attribute on the Postgres app_admin role.
GRANT EXEMPT ACCESS POLICY TO APP_ADMIN;

-- 2. Application context + setter package -----------------------------------
-- Oracle "secure" application context: only the package below can call SET_CONTEXT, so a malicious
-- client cannot impersonate another tenant by issuing DBMS_SESSION.SET_CONTEXT directly.
CREATE OR REPLACE PACKAGE passkey_ctx_pkg AS
    PROCEDURE set_tenant(p_tenant_hex IN VARCHAR2);
    PROCEDURE clear_tenant;
END passkey_ctx_pkg;
/

CREATE OR REPLACE PACKAGE BODY passkey_ctx_pkg AS
    -- p_tenant_hex is the canonical lowercase hex UUID (e.g. '7c9e6679f6...'). The Java side
    -- already normalises UUID → hex without dashes before binding; storage compares RAW(16) bytes
    -- via HEXTORAW() inside the VPD predicate.
    PROCEDURE set_tenant(p_tenant_hex IN VARCHAR2) IS
    BEGIN
        IF p_tenant_hex IS NULL OR p_tenant_hex = '' THEN
            DBMS_SESSION.CLEAR_CONTEXT('PASSKEY_CTX', NULL, 'TENANT_ID');
        ELSE
            DBMS_SESSION.SET_CONTEXT('PASSKEY_CTX', 'TENANT_ID', p_tenant_hex);
        END IF;
    END set_tenant;

    PROCEDURE clear_tenant IS
    BEGIN
        DBMS_SESSION.CLEAR_CONTEXT('PASSKEY_CTX', NULL, 'TENANT_ID');
    END clear_tenant;
END passkey_ctx_pkg;
/

-- "ACCESSED GLOBALLY = FALSE" means the value is per-session. The trusted package is the only
-- writer (third arg of CREATE CONTEXT).
CREATE CONTEXT PASSKEY_CTX USING passkey_ctx_pkg;

GRANT EXECUTE ON passkey_ctx_pkg TO APP_RUNTIME, APP_ADMIN;

-- Public synonym so APP_RUNTIME / APP_ADMIN can call the secure setter package unqualified —
-- TenantConnectionProvider issues `BEGIN passkey_ctx_pkg.set_tenant(?); END;` without a schema
-- prefix.
CREATE PUBLIC SYNONYM passkey_ctx_pkg FOR APP_MIGRATOR.passkey_ctx_pkg;

-- Predicate function used by every VPD policy. Returns the WHERE-clause snippet appended to each
-- SELECT/UPDATE/DELETE on a tenant-scoped table. When TENANT_ID is unset → predicate is
-- "1 = 0" (fail-closed: zero rows).
CREATE OR REPLACE FUNCTION passkey_tenant_predicate(
    p_schema IN VARCHAR2,
    p_object IN VARCHAR2
) RETURN VARCHAR2 IS
    v_tid VARCHAR2(32);
BEGIN
    v_tid := SYS_CONTEXT('PASSKEY_CTX', 'TENANT_ID');
    IF v_tid IS NULL OR LENGTH(v_tid) = 0 THEN
        RETURN '1 = 0';
    END IF;
    -- HEXTORAW expects 32 hex chars (16 bytes). The Java provider strips dashes before binding.
    RETURN 'tenant_id = HEXTORAW(''' || v_tid || ''')';
END passkey_tenant_predicate;
/

GRANT EXECUTE ON passkey_tenant_predicate TO APP_RUNTIME, APP_ADMIN, PUBLIC;

-- 3. Tables ------------------------------------------------------------------
-- All UUID columns are RAW(16) — Hibernate's @JdbcTypeCode(SqlTypes.UUID) plus ojdbc11 round-trip
-- java.util.UUID ↔ RAW(16) automatically. RAW comparisons in literal SQL use HEXTORAW(...).
--
-- All timestamp columns are TIMESTAMP(6) WITH TIME ZONE — stores the offset alongside the
-- instant. Java OffsetDateTime ↔ ojdbc11 native binding.
--
-- All BOOLEAN-like columns are NUMBER(1) with CHECK (col IN (0,1)) — Oracle 19c has no native
-- BOOLEAN in SQL contexts. Hibernate maps Java boolean ↔ NUMBER(1) by default.

-- tenant ---------------------------------------------------------------------
CREATE TABLE tenant (
    id          RAW(16)                          NOT NULL,
    name        VARCHAR2(255)                    NOT NULL,
    slug        VARCHAR2(64)                     NOT NULL,
    status      VARCHAR2(16)                     NOT NULL,
    created_at  TIMESTAMP(6) WITH TIME ZONE      DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at  TIMESTAMP(6) WITH TIME ZONE      DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_tenant PRIMARY KEY (id),
    CONSTRAINT uk_tenant_slug UNIQUE (slug),
    CONSTRAINT ck_tenant_status CHECK (status IN ('ACTIVE','SUSPENDED','DELETED'))
);

-- tenant_user (tenant-scoped) ------------------------------------------------
CREATE TABLE tenant_user (
    id            RAW(16)                        NOT NULL,
    tenant_id     RAW(16)                        NOT NULL,
    external_id   VARCHAR2(255)                  NOT NULL,
    display_name  VARCHAR2(255),
    created_at    TIMESTAMP(6) WITH TIME ZONE    DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at    TIMESTAMP(6) WITH TIME ZONE    DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_tenant_user PRIMARY KEY (id),
    CONSTRAINT fk_tenant_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT uk_tenant_user_external UNIQUE (tenant_id, external_id)
);
CREATE INDEX ix_tenant_user_tenant ON tenant_user (tenant_id);

-- tenant_webauthn_config (tenant-scoped) -------------------------------------
CREATE TABLE tenant_webauthn_config (
    id                     RAW(16)               NOT NULL,
    tenant_id              RAW(16)               NOT NULL,
    rp_id                  VARCHAR2(255)         NOT NULL,
    rp_name                VARCHAR2(255)         NOT NULL,
    origins                VARCHAR2(2000)        NOT NULL,
    timeout_ms             NUMBER(10)            DEFAULT 60000 NOT NULL,
    user_verification      VARCHAR2(16)          DEFAULT 'PREFERRED' NOT NULL,
    attestation_conveyance VARCHAR2(16)          DEFAULT 'NONE' NOT NULL,
    resident_key           VARCHAR2(16)          DEFAULT 'PREFERRED' NOT NULL,
    cred_protect           VARCHAR2(32)          DEFAULT 'NONE' NOT NULL,
    created_at             TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at             TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_tenant_webauthn_config PRIMARY KEY (id),
    CONSTRAINT fk_twc_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT uk_twc_tenant UNIQUE (tenant_id),
    CONSTRAINT ck_twc_user_verification
        CHECK (user_verification IN ('REQUIRED','PREFERRED','DISCOURAGED')),
    CONSTRAINT ck_twc_attestation
        CHECK (attestation_conveyance IN ('NONE','INDIRECT','DIRECT','ENTERPRISE')),
    CONSTRAINT ck_twc_resident_key
        CHECK (resident_key IN ('REQUIRED','PREFERRED','DISCOURAGED')),
    CONSTRAINT ck_twc_cred_protect
        CHECK (cred_protect IN ('NONE','UV_OPTIONAL','UV_OPTIONAL_WITH_CREDID','UV_REQUIRED'))
);
-- uk_twc_tenant already provides the unique index on (tenant_id) — no separate ix_twc_tenant.

-- credential (tenant-scoped) -------------------------------------------------
CREATE TABLE credential (
    id                 RAW(16)                   NOT NULL,
    tenant_id          RAW(16)                   NOT NULL,
    tenant_user_id     RAW(16)                   NOT NULL,
    credential_id      VARCHAR2(1024)            NOT NULL,
    public_key_cose    BLOB                      NOT NULL,
    aaguid             RAW(16),
    transports         VARCHAR2(255),
    user_handle        VARCHAR2(255)             NOT NULL,
    signature_counter  NUMBER(19)                DEFAULT 0 NOT NULL,
    backup_eligible    NUMBER(1)                 DEFAULT 0 NOT NULL,
    backup_state       NUMBER(1)                 DEFAULT 0 NOT NULL,
    nickname           VARCHAR2(255),
    status             VARCHAR2(16)              DEFAULT 'ACTIVE' NOT NULL,
    revoked_at         TIMESTAMP(6) WITH TIME ZONE,
    revoked_reason     VARCHAR2(40),
    last_used_at       TIMESTAMP(6) WITH TIME ZONE,
    created_at         TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at         TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_credential PRIMARY KEY (id),
    CONSTRAINT fk_cred_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT fk_cred_tenant_user FOREIGN KEY (tenant_user_id) REFERENCES tenant_user (id),
    CONSTRAINT uk_cred_per_tenant UNIQUE (tenant_id, credential_id),
    CONSTRAINT ck_cred_status CHECK (status IN ('ACTIVE','REVOKED')),
    CONSTRAINT ck_cred_backup_eligible CHECK (backup_eligible IN (0,1)),
    CONSTRAINT ck_cred_backup_state CHECK (backup_state IN (0,1)),
    CONSTRAINT ck_cred_revoked_reason
        CHECK (revoked_reason IS NULL OR revoked_reason IN
              ('USER_REQUEST','ADMIN_FORCED','COMPROMISE_SUSPECTED',
               'SIGNATURE_COUNTER_REGRESSION','LIFECYCLE_EXPIRED'))
);
CREATE INDEX ix_cred_tenant_user ON credential (tenant_id, tenant_user_id);
-- uk_cred_per_tenant already provides the (tenant_id, credential_id) index.

-- tenant_attestation_policy (tenant-scoped) ----------------------------------
CREATE TABLE tenant_attestation_policy (
    id                  RAW(16)                  NOT NULL,
    tenant_id           RAW(16)                  NOT NULL,
    -- "mode" is reserved in Oracle 19c — use attestation_mode in DDL + JPA mapping.
    attestation_mode    VARCHAR2(16)             DEFAULT 'ANY' NOT NULL,
    allowed_aaguids     VARCHAR2(4000),
    denied_aaguids      VARCHAR2(4000),
    mds_strict          NUMBER(1)                DEFAULT 0 NOT NULL,
    allow_zero_aaguid   NUMBER(1)                DEFAULT 0 NOT NULL,
    allow_syncable      NUMBER(1)                DEFAULT 1 NOT NULL,
    created_at          TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at          TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_tap PRIMARY KEY (id),
    CONSTRAINT fk_tap_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT uk_tap_tenant UNIQUE (tenant_id),
    CONSTRAINT ck_tap_mode CHECK (attestation_mode IN ('ANY','ALLOWLIST','DENYLIST')),
    CONSTRAINT ck_tap_mds_strict CHECK (mds_strict IN (0,1)),
    CONSTRAINT ck_tap_allow_zero_aaguid CHECK (allow_zero_aaguid IN (0,1)),
    CONSTRAINT ck_tap_allow_syncable CHECK (allow_syncable IN (0,1))
);

-- api_key (RLS-exempt by design — resolver needs to look up tenant from prefix) --------------
CREATE TABLE api_key (
    id            RAW(16)                        NOT NULL,
    tenant_id     RAW(16)                        NOT NULL,
    prefix        VARCHAR2(32)                   NOT NULL,
    secret_hash   VARCHAR2(255)                  NOT NULL,
    name          VARCHAR2(100)                  NOT NULL,
    status        VARCHAR2(16)                   DEFAULT 'ACTIVE' NOT NULL,
    last_used_at  TIMESTAMP(6) WITH TIME ZONE,
    created_at    TIMESTAMP(6) WITH TIME ZONE    DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at    TIMESTAMP(6) WITH TIME ZONE    DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_api_key PRIMARY KEY (id),
    CONSTRAINT fk_api_key_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT uk_api_key_prefix UNIQUE (prefix),
    CONSTRAINT ck_api_key_status CHECK (status IN ('ACTIVE','REVOKED'))
);
CREATE INDEX ix_api_key_tenant ON api_key (tenant_id);

-- audit_log (tenant-scoped) --------------------------------------------------
-- NOTE: Interval Partitioning requires Oracle Enterprise Edition (with the Partitioning option).
-- The baseline ships a non-partitioned table so it boots on Oracle Free / SE2; the
-- production EE-licensed instance can apply an ALTER TABLE ... MODIFY PARTITION BY RANGE
-- in a follow-up migration (out of baseline scope).
-- The PK on (id, created_at) is kept for cross-environment uniformity — if/when Partitioning is
-- added in prod, the partitioning key must be part of the primary key for local indexes.
CREATE TABLE audit_log (
    id            RAW(16)                        NOT NULL,
    tenant_id     RAW(16)                        NOT NULL,
    event_type    VARCHAR2(64)                   NOT NULL,
    actor_type    VARCHAR2(16)                   NOT NULL,
    actor_id      VARCHAR2(255),
    subject_type  VARCHAR2(64),
    subject_id    VARCHAR2(255),
    payload       CLOB,
    prev_hash     VARCHAR2(128),
    row_hash      VARCHAR2(128)                  NOT NULL,
    -- Oracle disallows TIMESTAMP WITH TIME ZONE in primary keys (ORA-02329). LOCAL TIME ZONE
    -- normalises to the DB timezone (we set it to UTC) on storage, so OffsetDateTime round-trips
    -- safely while keeping the column eligible for the composite PK that future Partitioning
    -- requires.
    created_at    TIMESTAMP(6) WITH LOCAL TIME ZONE  DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_audit_log PRIMARY KEY (id, created_at),
    CONSTRAINT fk_audit_log_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT ck_audit_log_payload_json CHECK (payload IS JSON)
);

CREATE INDEX ix_audit_log_tenant_created ON audit_log (tenant_id, created_at);
CREATE INDEX ix_audit_log_tenant_event
    ON audit_log (tenant_id, event_type, created_at);

-- admin_user (RLS-exempt; cross-tenant login lookup happens before context is set) -----------
CREATE TABLE admin_user (
    id              RAW(16)                      NOT NULL,
    tenant_id       RAW(16),
    email           VARCHAR2(320)                NOT NULL,
    password_hash   VARCHAR2(255)                NOT NULL,
    display_name    VARCHAR2(255)                NOT NULL,
    role            VARCHAR2(32)                 NOT NULL,
    status          VARCHAR2(16)                 DEFAULT 'ACTIVE' NOT NULL,
    last_login_at   TIMESTAMP(6) WITH TIME ZONE,
    created_at      TIMESTAMP(6) WITH TIME ZONE  DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at      TIMESTAMP(6) WITH TIME ZONE  DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_admin_user PRIMARY KEY (id),
    CONSTRAINT fk_admin_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT uk_admin_user_email UNIQUE (email),
    CONSTRAINT ck_admin_user_role CHECK (role IN ('PLATFORM_OPERATOR','RP_ADMIN')),
    CONSTRAINT ck_admin_user_status CHECK (status IN ('ACTIVE','SUSPENDED')),
    CONSTRAINT ck_admin_user_tenant_for_rp
        CHECK ((role = 'PLATFORM_OPERATOR' AND tenant_id IS NULL)
            OR (role = 'RP_ADMIN'           AND tenant_id IS NOT NULL))
);
CREATE INDEX ix_admin_user_tenant ON admin_user (tenant_id);

-- refresh_token (tenant-scoped) ----------------------------------------------
CREATE TABLE refresh_token (
    id               RAW(16)                     NOT NULL,
    tenant_id        RAW(16)                     NOT NULL,
    tenant_user_id   RAW(16)                     NOT NULL,
    parent_jti       RAW(16),
    issued_at        TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    expires_at       TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked_at       TIMESTAMP(6) WITH TIME ZONE,
    revoked_reason   VARCHAR2(40),
    client_ip        VARCHAR2(64),
    user_agent       VARCHAR2(255),
    created_at       TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    updated_at       TIMESTAMP(6) WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_refresh_token PRIMARY KEY (id),
    CONSTRAINT fk_rt_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT fk_rt_tenant_user FOREIGN KEY (tenant_user_id) REFERENCES tenant_user (id)
);
CREATE INDEX ix_rt_user ON refresh_token (tenant_user_id);
CREATE INDEX ix_rt_expires ON refresh_token (expires_at);
CREATE INDEX ix_rt_parent ON refresh_token (parent_jti);

-- scheduler_lease (singleton leader-election table — replaces pg_try_advisory_xact_lock) -----
-- AuditChainScheduler grabs the row with SELECT FOR UPDATE SKIP LOCKED. The first replica into
-- the @Scheduled window holds the row lock for the duration of its transaction; others skip.
CREATE TABLE scheduler_lease (
    name        VARCHAR2(64)                     NOT NULL,
    acquired_at TIMESTAMP(6) WITH TIME ZONE,
    holder      VARCHAR2(255),
    CONSTRAINT pk_scheduler_lease PRIMARY KEY (name)
);

INSERT INTO scheduler_lease (name) VALUES ('audit-chain-verifier');

-- 4. Grants ------------------------------------------------------------------
-- Object grants. APP_RUNTIME and APP_ADMIN run as separate Oracle users, so DML must be granted
-- explicitly per table. Synonyms below let unqualified table names resolve in both runtimes.

GRANT SELECT, INSERT, UPDATE         ON tenant      TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_user TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_webauthn_config TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON credential TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_attestation_policy TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, UPDATE                 ON api_key TO APP_RUNTIME;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_key TO APP_ADMIN;
GRANT SELECT, INSERT                 ON audit_log TO APP_RUNTIME;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_log TO APP_ADMIN;
GRANT SELECT, INSERT, UPDATE         ON admin_user TO APP_RUNTIME;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_user TO APP_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_token TO APP_RUNTIME, APP_ADMIN;
GRANT SELECT, UPDATE                 ON scheduler_lease TO APP_RUNTIME, APP_ADMIN;

-- DBMS_LOCK is used by AuditService for per-tenant audit-chain serialisation (replaces
-- pg_advisory_xact_lock). Both runtimes need EXECUTE.
GRANT EXECUTE ON DBMS_LOCK TO APP_RUNTIME, APP_ADMIN;

-- 5. Public synonyms so APP_RUNTIME / APP_ADMIN can address tables unqualified ---------------
-- (Hibernate generates `SELECT ... FROM tenant_user` without schema prefix.)
CREATE PUBLIC SYNONYM tenant                    FOR APP_MIGRATOR.tenant;
CREATE PUBLIC SYNONYM tenant_user               FOR APP_MIGRATOR.tenant_user;
CREATE PUBLIC SYNONYM tenant_webauthn_config    FOR APP_MIGRATOR.tenant_webauthn_config;
CREATE PUBLIC SYNONYM credential                FOR APP_MIGRATOR.credential;
CREATE PUBLIC SYNONYM tenant_attestation_policy FOR APP_MIGRATOR.tenant_attestation_policy;
CREATE PUBLIC SYNONYM api_key                   FOR APP_MIGRATOR.api_key;
CREATE PUBLIC SYNONYM audit_log                 FOR APP_MIGRATOR.audit_log;
CREATE PUBLIC SYNONYM admin_user                FOR APP_MIGRATOR.admin_user;
CREATE PUBLIC SYNONYM refresh_token             FOR APP_MIGRATOR.refresh_token;
CREATE PUBLIC SYNONYM scheduler_lease           FOR APP_MIGRATOR.scheduler_lease;
