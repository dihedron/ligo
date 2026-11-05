-- The target database of ligo-plugin-postgres: the database ledger, its schema
-- and table, the roles an access level grants, and the admin role the plugin
-- connects as (.specs/ligo-postgres-plugin.md §5). Idempotent: lab.sh up, every
-- deploy and CI run it, as the postgres superuser, with the admin's password as
-- a psql variable:
--   psql -v admin_password=... -f target.sql
\set ON_ERROR_STOP on

SELECT 'CREATE ROLE lab_target_admin LOGIN CREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lab_target_admin') \gexec
ALTER ROLE lab_target_admin PASSWORD :'admin_password';
SELECT 'CREATE ROLE "LEDGER_RO_ROLE" NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'LEDGER_RO_ROLE') \gexec
SELECT 'CREATE ROLE "LEDGER_RW_ROLE" NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'LEDGER_RW_ROLE') \gexec
SELECT 'CREATE ROLE "LEDGER_DDL_ROLE" NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'LEDGER_DDL_ROLE') \gexec
-- the principals pg_hba verifies against the directory (EXTERNAL_DIR)
SELECT 'CREATE ROLE ligo_ldap NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ligo_ldap') \gexec
-- the admin grants these roles to the principals it creates
GRANT "LEDGER_RO_ROLE", "LEDGER_RW_ROLE", "LEDGER_DDL_ROLE", ligo_ldap TO lab_target_admin WITH ADMIN OPTION;
-- it ends a revoked role's sessions
GRANT pg_signal_backend TO lab_target_admin;
SELECT 'CREATE DATABASE ledger'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ledger') \gexec

\connect ledger
REVOKE ALL ON DATABASE ledger FROM PUBLIC;
GRANT CONNECT ON DATABASE ledger TO lab_target_admin, "LEDGER_RO_ROLE", "LEDGER_RW_ROLE", "LEDGER_DDL_ROLE";
CREATE SCHEMA IF NOT EXISTS ledger;
CREATE TABLE IF NOT EXISTS ledger.entries (id bigint PRIMARY KEY, amount numeric NOT NULL);
GRANT USAGE ON SCHEMA ledger TO "LEDGER_RO_ROLE", "LEDGER_RW_ROLE", "LEDGER_DDL_ROLE";
-- a role that owns objects cannot be dropped (PG-10)
GRANT CREATE ON SCHEMA ledger TO "LEDGER_DDL_ROLE";
GRANT SELECT ON ledger.entries TO "LEDGER_RO_ROLE", "LEDGER_RW_ROLE";
GRANT INSERT, UPDATE ON ledger.entries TO "LEDGER_RW_ROLE";
