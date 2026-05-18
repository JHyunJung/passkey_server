-- ============================================================
-- R__vpd_policies.sql  (repeatable — re-applied when this file's hash changes)
-- Desired state for all Virtual Private Database policies in schema PASSKEY.
-- Adding a tenant-scoped table requires updating this file in the same PR.
--
-- Each policy attaches passkey_tenant_predicate(...) (defined in V1__oracle_baseline.sql) to a
-- table so that every SELECT/INSERT/UPDATE/DELETE has its WHERE clause appended with
--     tenant_id = HEXTORAW(SYS_CONTEXT('PASSKEY_CTX','TENANT_ID'))
-- (or "1 = 0" when the context is unset). update_check => TRUE rejects rows whose tenant_id does
-- not match — the equivalent of Postgres's WITH CHECK clause.
--
-- Idempotency: DBMS_RLS.ADD_POLICY raises ORA-28101 when the policy already exists, so we DROP
-- (suppressing ORA-28102 "policy does not exist") and re-add. This makes the file safely
-- repeatable.
-- ============================================================

DECLARE
    TYPE tnames IS TABLE OF VARCHAR2(64);
    v_tables tnames := tnames(
        'TENANT_USER',
        'TENANT_WEBAUTHN_CONFIG',
        'CREDENTIAL',
        'TENANT_ATTESTATION_POLICY',
        'AUDIT_LOG',
        'REFRESH_TOKEN'
    );
    v_policy_name VARCHAR2(64);
BEGIN
    FOR i IN 1 .. v_tables.COUNT LOOP
        v_policy_name := LOWER(v_tables(i)) || '_tenant_isolation';

        -- Drop existing policy if any. ORA-28102 = policy doesn't exist → swallow.
        BEGIN
            DBMS_RLS.DROP_POLICY(
                object_schema => 'APP_MIGRATOR',
                object_name   => v_tables(i),
                policy_name   => v_policy_name
            );
        EXCEPTION
            WHEN OTHERS THEN
                IF SQLCODE != -28102 THEN
                    RAISE;
                END IF;
        END;

        DBMS_RLS.ADD_POLICY(
            object_schema      => 'APP_MIGRATOR',
            object_name        => v_tables(i),
            policy_name        => v_policy_name,
            function_schema    => 'APP_MIGRATOR',
            policy_function    => 'PASSKEY_TENANT_PREDICATE',
            statement_types    => 'SELECT,INSERT,UPDATE,DELETE',
            update_check       => TRUE,
            policy_type        => DBMS_RLS.SHARED_CONTEXT_SENSITIVE
        );
    END LOOP;
END;
/
