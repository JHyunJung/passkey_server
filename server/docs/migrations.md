# Database Migration Conventions

Flyway is the single source of truth for the Oracle schema. Connections from
the application use the `APP_RUNTIME` user (no `EXEMPT ACCESS POLICY` — VPD
applies); Flyway itself runs as `APP_MIGRATOR`, the object owner.

> v1.5에서 PostgreSQL RLS → Oracle 19c Virtual Private Database(VPD)로 이식.
> 구 PG migration history는 `src/main/resources/db/archive_postgres/`에 보존되어
> 있고, 현재 baseline은 `db/migration/V1__oracle_baseline.sql` 단일 파일이다.

## File types

| Prefix | Purpose | Re-runs |
|--------|---------|---------|
| `V<n>__<name>.sql` | Versioned schema change (DDL). | Once. |
| `R__<name>.sql` | Repeatable script. Re-applied when file hash changes. | On change. |

## Naming

- `V<n>__create_<entity>.sql` — new table(s) and indexes.
- `V<n>__alter_<entity>__<change>.sql` — schema alterations.
- `R__vpd_policies.sql` — the canonical VPD policy desired-state (table array
  consumed by `DBMS_RLS.ADD_POLICY`).

## VPD (Virtual Private Database) conventions

1. **Every tenant-scoped table** carries a `tenant_id RAW(16)` column and gets a
   VPD policy attached by `R__vpd_policies.sql` via `DBMS_RLS.ADD_POLICY`. The
   policy function `passkey_tenant_predicate` returns
   `tenant_id = HEXTORAW(SYS_CONTEXT('PASSKEY_CTX','TENANT_ID'))`, or `'1 = 0'`
   when no tenant context is set (fail-closed).

2. **Policies live in `R__vpd_policies.sql`** — desired-state. Adding a new
   tenant-scoped table requires three coordinated edits:
   - the `V<n>__create_<table>.sql` migration (with the `tenant_id` column + DML
     grant to `APP_RUNTIME`/`APP_ADMIN`),
   - the table name added to the array in `R__vpd_policies.sql`,
   - `RlsPolicyCatalogTest.EXPECTED_TABLES` updated (table name uppercase).

3. **The `tenant` table itself is VPD-exempt** — it is the resolution target.
   `admin_user` is likewise exempt (cross-tenant login lookup runs before any
   tenant context is set).

4. **`APP_RUNTIME` must not hold `EXEMPT ACCESS POLICY`** — that is what keeps
   VPD enforced on runtime traffic. Only `APP_ADMIN` (Platform Operator
   cross-tenant queries) is granted the exemption.

## Index creation

Oracle `CREATE INDEX` does not need PostgreSQL's `CONCURRENTLY`; standard online
index creation (`CREATE INDEX ... ONLINE` on EE) covers large-table cases. Place
index DDL alongside the table's `V<n>__` migration.

## Failure recovery

If a versioned migration fails mid-flight:

1. Inspect with `SELECT * FROM "flyway_schema_history" ORDER BY installed_rank DESC`.
2. Fix the underlying SQL.
3. `./gradlew flywayRepair` to clear the failed row.
4. Re-run.

Never edit a previously-applied versioned file. Add a new `V<n+1>__` migration
that corrects the state.

For a full schema reset during integration-test / migration work, see the
cleanup snippet in `CLAUDE.md` ("DB schema reset") or
`docker/oracle-init/02_clean_passkey.sql`.
