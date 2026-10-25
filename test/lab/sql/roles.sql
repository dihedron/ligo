-- The database roles and the database of §4.1, created by operations, not by
-- migrations. Run once, as a superuser, with the passwords as psql variables:
--   psql -v migrator_password=... -v app_password=... -v reader_password=...
--        -v dbos_password=... -f roles.sql
-- The lab (test/lab/lab.sh up) and CI (.github/workflows/ci.yml) both use it.
\set ON_ERROR_STOP on

CREATE ROLE ligo_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE ligo_app      LOGIN PASSWORD :'app_password';
CREATE ROLE ligo_reader   LOGIN PASSWORD :'reader_password';
CREATE ROLE ligo_dbos     LOGIN PASSWORD :'dbos_password';

CREATE DATABASE ligo OWNER ligo_migrator;

\connect ligo
-- public is owned by the migrator, which owns every object in it (§4.1); the
-- other roles get privileges on objects from the migrations' GRANTs.
ALTER SCHEMA public OWNER TO ligo_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ligo_app, ligo_reader;
-- DBOS manages its own schema (EXT-08) and has no access to public.
CREATE SCHEMA dbos AUTHORIZATION ligo_dbos;
