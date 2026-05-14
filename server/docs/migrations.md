# Database Migration Conventions

Flyway is the single source of truth for the `passkey` schema. Connections from
the application use the `app_runtime` role (NOBYPASSRLS); Flyway itself runs as
`app_migrator`.

## File types

| Prefix | Purpose | Re-runs |
|--------|---------|---------|
| `V<n>__<name>.sql` | Versioned schema change (DDL). | Once. |
| `R__<name>.sql` | Repeatable script. Re-applied when file hash changes. | On change. |

## Naming

- `V<n>__create_<entity>.sql` — new table(s) and indexes.
- `V<n>__alter_<entity>__<change>.sql` — schema alterations.
- `V<n>__add_index_<table>__<cols>.sql` — index that requires `CONCURRENTLY`.
- `R__rls_policies.sql` — the canonical RLS policy desired-state.

## RLS conventions

1. **Every tenant-scoped table** gets:
   ```sql
   ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
   ALTER TABLE <t> FORCE  ROW LEVEL SECURITY;
   ```
   `FORCE` ensures even the table owner is subject to RLS.

2. **Policies live in `R__rls_policies.sql`** — desired-state. Adding a new
   tenant-scoped table requires both the `V<n>__` migration that creates the
   table (with ENABLE + FORCE) and an update to `R__rls_policies.sql`.

3. **The `tenant` table itself is RLS-exempt** — it is the resolution target.

## Concurrent index creation

`CREATE INDEX CONCURRENTLY` cannot run inside a transaction. Place such
statements in their own file with the Flyway metadata header:

```sql
-- flyway:executeInTransaction=false
CREATE INDEX CONCURRENTLY ix_<t>__<cols> ON passkey.<t> (...);
```

## Failure recovery

If a versioned migration fails mid-flight:

1. Inspect with `select * from flyway_schema_history order by installed_rank desc`.
2. Fix the underlying SQL.
3. `./gradlew flywayRepair` to clear the failed row.
4. Re-run.

Never edit a previously-applied versioned file. Add a new `V<n+1>__` migration
that corrects the state.
