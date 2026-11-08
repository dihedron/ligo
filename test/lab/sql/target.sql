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

-- Two tenancies on one database, as the platform team creates them outside
-- ligo (.specs/ligo-tenancy.md §6): lab.sh serve test-accounts.
\connect postgres
SELECT format('CREATE ROLE %I NOLOGIN', r) FROM unnest(ARRAY['acme_db01_read', 'acme_db01_write', 'globex_db02_read', 'globex_db02_write']) r
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) \gexec
GRANT acme_db01_read, acme_db01_write, globex_db02_read, globex_db02_write TO lab_target_admin WITH ADMIN OPTION;
\connect ledger
GRANT CONNECT ON DATABASE ledger TO acme_db01_read, acme_db01_write, globex_db02_read, globex_db02_write;
CREATE SCHEMA IF NOT EXISTS acme_db01;
CREATE TABLE IF NOT EXISTS acme_db01.entries (id bigint PRIMARY KEY, amount numeric NOT NULL);
GRANT USAGE ON SCHEMA acme_db01 TO acme_db01_read, acme_db01_write;
GRANT SELECT ON acme_db01.entries TO acme_db01_read, acme_db01_write;
GRANT INSERT, UPDATE ON acme_db01.entries TO acme_db01_write;
CREATE SCHEMA IF NOT EXISTS globex_db02;
CREATE TABLE IF NOT EXISTS globex_db02.entries (id bigint PRIMARY KEY, amount numeric NOT NULL);
GRANT USAGE ON SCHEMA globex_db02 TO globex_db02_read, globex_db02_write;
GRANT SELECT ON globex_db02.entries TO globex_db02_read, globex_db02_write;
GRANT INSERT, UPDATE ON globex_db02.entries TO globex_db02_write;
