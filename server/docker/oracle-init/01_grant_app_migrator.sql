-- Init script run as SYSDBA on FREEPDB1 after the container is healthy.
-- The gvenzl image creates APP_MIGRATOR with default app-user privileges (CREATE SESSION,
-- RESOURCE quota). To run our Flyway baseline we also need:
--   * CREATE USER / DROP USER / ALTER USER  — to provision APP_RUNTIME and APP_ADMIN
--   * GRANT ANY OBJECT PRIVILEGE             — so Flyway can grant SELECT/INSERT/... to those users
--   * GRANT ANY PRIVILEGE                    — for EXEMPT ACCESS POLICY on APP_ADMIN
--   * CREATE ANY CONTEXT / DROP ANY CONTEXT  — for the secure application context
--   * EXECUTE_CATALOG_ROLE                   — for DBMS_RLS / DBMS_LOCK / DBMS_SESSION
--   * EXECUTE on DBMS_RLS, DBMS_LOCK         — the policy package and audit-chain lock
--   * CREATE PUBLIC SYNONYM / DROP PUBLIC SYNONYM
--
-- These are PDB-level grants. The container starts in CDB$ROOT; we switch to FREEPDB1 first.
ALTER SESSION SET CONTAINER = FREEPDB1;

GRANT CREATE USER, DROP USER, ALTER USER             TO APP_MIGRATOR;
GRANT GRANT ANY OBJECT PRIVILEGE                     TO APP_MIGRATOR;
GRANT GRANT ANY PRIVILEGE                            TO APP_MIGRATOR;
GRANT CREATE ANY CONTEXT, DROP ANY CONTEXT           TO APP_MIGRATOR;
GRANT CREATE PUBLIC SYNONYM, DROP PUBLIC SYNONYM     TO APP_MIGRATOR;
-- WITH GRANT OPTION so the V1 baseline can re-grant EXECUTE on these system packages to
-- APP_RUNTIME / APP_ADMIN after creating those users.
GRANT EXECUTE ON SYS.DBMS_RLS     TO APP_MIGRATOR WITH GRANT OPTION;
GRANT EXECUTE ON SYS.DBMS_LOCK    TO APP_MIGRATOR WITH GRANT OPTION;
GRANT EXECUTE ON SYS.DBMS_SESSION TO APP_MIGRATOR WITH GRANT OPTION;
GRANT UNLIMITED TABLESPACE                           TO APP_MIGRATOR;
