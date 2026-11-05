# PostgreSQL

`ligo` uses one database, with four roles, so that a compromise of one does not give the others' rights.

| Role | Used by | Rights |
| :------------ | :------------- | :------------------------ |
| `ligo_migrator` | `ligo migrate` | Owns the schema; no other component uses it |
| `ligo_app` | The service | Reads and writes its tables; can only append to the audit log |
| `ligo_reader` | The workload API's resolver | Reads the view of active bindings only |
| `ligo_dbos` | The durable workflows | Owns the schema `dbos`, the workflow journal |

Create them once, as a superuser, with passwords of your own:

```bash
psql -v migrator_password=... -v app_password=... -v reader_password=... -v dbos_password=... \
  -f /usr/share/ligo/examples/roles.sql
```

Serve the database over TLS only, and let `pg_hba.conf` accept those roles over `hostssl` with `scram-sha-256`, from the `ligo` hosts only.

Apply the migrations with the DSN of `ligo_migrator`. They are forward-only, each in its own transaction, under an advisory lock, and the command refuses to run if an applied migration's content changed:

```bash
LIGO_MIGRATOR_DSN='host=db.internal dbname=ligo sslmode=verify-full user=ligo_migrator password=<password>' ligo migrate
```

Back up the database with point-in-time recovery. The schemas `public` and `dbos` must be backed up together (*Operator's Guide*).
