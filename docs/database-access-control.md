# Database access control

## Hosted architecture

The browser calls the AegisTrace FastAPI service. It does not use the Supabase
Data API to read or write application tables. The hosted service connects to
PostgreSQL as `postgres`; the live connection was inspected and that role has
`BYPASSRLS`. Keep the database credential server-side.

## Supabase Data API boundary

Migration `0021_public_schema_rls` enables row-level security on all 49 current
application tables in `public`, revokes object privileges from `PUBLIC`,
`anon`, and `authenticated`, and removes those roles from the current migration
owner's default privileges for future tables, sequences, and functions. The
`service_role` and server-side database owner grants remain intact. No policies
grant browser-role access; the intended rule is deny by default.

The four trigger-only integrity functions also have public execution grants
revoked and their `search_path` pinned to `pg_catalog`; their trigger bindings
remain in place.

The migration intentionally cannot be downgraded to the old broad grants.
Future migrations that add a table to `public` must enable RLS and preserve the
server-only Data API boundary. Do not create policies for `anon` or
`authenticated` unless a reviewed product feature explicitly requires direct
client access.

## Verification queries

Run in Supabase SQL Editor or through the connected database MCP:

```sql
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

SELECT
  rolname,
  count(*) FILTER (WHERE has_table_privilege(rolname, c.oid, 'SELECT')) AS select_count,
  count(*) FILTER (WHERE has_table_privilege(rolname, c.oid, 'INSERT')) AS insert_count,
  count(*) FILTER (WHERE has_table_privilege(rolname, c.oid, 'UPDATE')) AS update_count,
  count(*) FILTER (WHERE has_table_privilege(rolname, c.oid, 'DELETE')) AS delete_count
FROM pg_roles
CROSS JOIN pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE rolname IN ('anon', 'authenticated', 'service_role', 'postgres')
  AND n.nspname = 'public'
  AND c.relkind IN ('r', 'p')
GROUP BY rolname
ORDER BY rolname;
```

Expected after deployment: all 49 current tables have RLS enabled; `anon` and
`authenticated` have zero table privileges; `postgres` and `service_role` retain
their backend access. The health endpoint should still report the database as
connected.

## Platform-owned default privileges

The database connection used by this project is not a member of
`supabase_admin`, so it cannot change that platform role's default privileges.
Current application tables are owned by `postgres`, and future application
migrations run under the server database connection. If a future platform
operation creates objects in `public` as `supabase_admin`, inspect its grants
and enable RLS before exposing that object through the Data API.
