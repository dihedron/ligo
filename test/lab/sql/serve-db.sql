-- The database of the lab's ligo service, ligo_serve, with the roles of
-- roles.sql (which must have run): the integration tests keep the database
-- ligo (.specs/ligo-test-environment.md, "The ligo service on ligo1").
-- Run once, as a superuser.
\set ON_ERROR_STOP on

CREATE DATABASE ligo_serve OWNER ligo_migrator;

\connect ligo_serve
ALTER SCHEMA public OWNER TO ligo_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ligo_app, ligo_reader;
CREATE SCHEMA dbos AUTHORIZATION ligo_dbos;
