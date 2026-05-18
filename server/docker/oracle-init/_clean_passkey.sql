-- _clean_passkey.sql
-- Standalone schema reset for integration testing / Flyway changes. This file is intentionally
-- prefixed with an underscore so the gvenzl init-script loader (which only runs files at first
-- boot) does NOT auto-execute it. Invoke manually:
--
--   docker cp server/docker/oracle-init/_clean_passkey.sql passkey-oracle:/tmp/clean.sql
--   docker exec passkey-oracle sqlplus -L -S APP_MIGRATOR/change_me_migrator@//localhost:1521/FREEPDB1 @/tmp/clean.sql
--
-- After running this, the next `./gradlew test --tests "...integration.*"` (or `bootRun`) replays
-- V1__oracle_baseline.sql + R__vpd_policies.sql from a clean slate.

SET SERVEROUTPUT ON
BEGIN
  FOR r IN (SELECT object_name FROM user_objects WHERE object_type = 'TABLE') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP TABLE "' || r.object_name || '" CASCADE CONSTRAINTS PURGE';
    EXCEPTION WHEN OTHERS THEN DBMS_OUTPUT.PUT_LINE('skip table ' || r.object_name); END;
  END LOOP;

  FOR r IN (SELECT object_name FROM user_objects WHERE object_type = 'PACKAGE') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP PACKAGE "' || r.object_name || '"';
    EXCEPTION WHEN OTHERS THEN DBMS_OUTPUT.PUT_LINE('skip package ' || r.object_name); END;
  END LOOP;

  FOR r IN (SELECT object_name FROM user_objects WHERE object_type = 'FUNCTION') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP FUNCTION "' || r.object_name || '"';
    EXCEPTION WHEN OTHERS THEN DBMS_OUTPUT.PUT_LINE('skip function ' || r.object_name); END;
  END LOOP;

  BEGIN EXECUTE IMMEDIATE 'DROP CONTEXT PASSKEY_CTX'; EXCEPTION WHEN OTHERS THEN NULL; END;

  FOR r IN (SELECT synonym_name FROM all_synonyms
             WHERE owner = 'PUBLIC' AND table_owner = 'APP_MIGRATOR') LOOP
    BEGIN EXECUTE IMMEDIATE 'DROP PUBLIC SYNONYM "' || r.synonym_name || '"';
    EXCEPTION WHEN OTHERS THEN NULL; END;
  END LOOP;

  BEGIN EXECUTE IMMEDIATE 'DROP USER APP_RUNTIME CASCADE'; EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN EXECUTE IMMEDIATE 'DROP USER APP_ADMIN CASCADE';   EXCEPTION WHEN OTHERS THEN NULL; END;
END;
/

SELECT object_name, object_type FROM user_objects ORDER BY object_type, object_name;
EXIT
