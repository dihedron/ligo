-- The target database of the target-postgres stand-in (phase 6): the
-- database ledger, its schema and table, the two roles an access level
-- grants, and the admin role the plugin connects as. Idempotent: lab.sh up
-- and every deploy run it, as the postgres superuser, with the admin's
-- password as a psql variable:
--   psql -v admin_password=... -f target.sql
\set ON_ERROR_STOP on

SELECT 'CREATE ROLE lab_target_admin LOGIN CREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lab_target_admin') \gexec
ALTER ROLE lab_target_admin PASSWORD :'admin_password';
SELECT 'CREATE ROLE "LEDGER_RO_ROLE" NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'LEDGER_RO_ROLE') \gexec
SELECT 'CREATE ROLE "LEDGER_RW_ROLE" NOLOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'LEDGER_RW_ROLE') \gexec
-- the admin grants the two roles to the principals it creates
GRANT "LEDGER_RO_ROLE", "LEDGER_RW_ROLE" TO lab_target_admin WITH ADMIN OPTION;
SELECT 'CREATE DATABASE ledger'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ledger') \gexec

\connect ledger
REVOKE ALL ON DATABASE ledger FROM PUBLIC;
GRANT CONNECT ON DATABASE ledger TO lab_target_admin, "LEDGER_RO_ROLE", "LEDGER_RW_ROLE";
CREATE SCHEMA IF NOT EXISTS ledger;
CREATE TABLE IF NOT EXISTS ledger.entries (id bigint PRIMARY KEY, amount numeric NOT NULL);
GRANT USAGE ON SCHEMA ledger TO "LEDGER_RO_ROLE", "LEDGER_RW_ROLE";
GRANT SELECT ON ledger.entries TO "LEDGER_RO_ROLE", "LEDGER_RW_ROLE";
GRANT INSERT, UPDATE ON ledger.entries TO "LEDGER_RW_ROLE";
