# Configuration reference

`server.yaml` holds no secrets, only the names of environment variables. Every change except certificate files needs a rolling restart. A key that lists entries, such as `realms`, shows its fields by their path. Defaults are given where a key may be left out.

::: landscape

## `service`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `service` | The service's identity. | |
| `service.application_version` | The version given to the durable workflows. A workflow runs only on replicas of its version. | Set it on every upgrade |
| `service.instance_id_env` | The variable holding the replica's ID. Set, stable and unique per replica. | `^[A-Za-z0-9._-]{1,58}$` |
| `service.startup_timeout` | How long SPIRE and the sealer have to be ready, before startup ends with an error naming the dependency. | 60 s; 5 s to 10 min |
| `service.workload_advertise` | How workloads reach the workload API; served as the `ligo` flow, and the same on every replica. | Required |
| `service.workload_advertise.destination` | The address of the API, or of its load balancer. | |
| `service.workload_advertise.port` | Its port. | |
| `service.workload_advertise.server_name` | The TLS name a workload should expect. | |

## `realms` and `core_identity`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `realms` | One trust domain, with one agent socket on this host. Plugins run per realm. | At least one |
| `realms.name` | The realm's name. | Unique |
| `realms.trust_domain` | Its trust domain. | |
| `realms.spiffe_workload_socket` | The agent's Workload API socket. | `unix:///…` |
| `core_identity` | `ligo`'s own SVID: serving TLS, and logging in to Transit. | Required |
| `core_identity.realm` | The realm it comes from. | |
| `core_identity.svid_selector` | Selects exactly one SVID. | |
| `core_identity.svid_selector.match_expr` | An expression over `spiffe_id`, `trust_domain`, `path`, `hint`, `subject_cn` and `instance_name`. | Must match exactly one |
| `core_identity.svid_selector.jwt_audience` | The audiences of its JWT-SVIDs. | Includes Transit's |
| `core_identity.svid_selector.allow_shared_svid` | Lets instances share a SPIFFE ID. | Off |

## `server`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `server` | The three listeners. | |
| `server.workload_listener` | The read-only workload API. | |
| `server.workload_listener.listen_address` | Its address. | |
| `server.workload_listener.tls_source` | Its certificate: `spiffe`, or `file`. | |
| `server.workload_listener.tls_cert_file` | With `file`; reloaded on `SIGHUP`. | |
| `server.workload_listener.tls_key_file` | With `file`; reloaded on `SIGHUP`. | |
| `server.workload_listener.auth_modes` | `x509_svid`, preferred as it has no bearer token; `jwt_svid`. | Not empty |
| `server.workload_listener.accepted_trust_domains` | The callers' domains: each a realm, or federated. | |
| `server.workload_listener.federated_trust_domains` | Domains verified through a realm's federation. | |
| `server.workload_listener.federated_trust_domains.trust_domain` | The domain. | Never also a realm |
| `server.workload_listener.federated_trust_domains.via_realm` | The realm whose agent delivers its bundle. | |
| `server.workload_listener.expected_jwt_audience` | The audience a workload's JWT-SVID must have. | Required with `jwt_svid` |
| `server.workload_listener.max_token_ttl` | The longest accepted `exp - iat`. It bounds a stolen token's replay. | |
| `server.workload_listener.clock_skew` | The tolerated skew. | |
| `server.workload_listener.rate_limit` | Per caller. | |
| `server.workload_listener.rate_limit.per_svid_rps` | Requests per second. | |
| `server.workload_listener.rate_limit.burst` | Burst. | |
| `server.workload_listener.resolution_cache` | The in-memory cache that answers workloads. | |
| `server.workload_listener.resolution_cache.full_reload_interval` | How often it reloads whatever it was told. This bounds a lost notification's staleness. | |
| `server.workload_listener.resolution_cache.max_staleness` | Beyond this age the API refuses to answer, rather than answer from old data. | |
| `server.admin_listener` | The admin API and web UI. | |
| `server.admin_listener.listen_address` | Its address. | |
| `server.admin_listener.external_origin` | The origin browsers use, checked on each request. | Required |
| `server.admin_listener.tls_source` | `spiffe`, or `file`. Browsers warn on an SVID, so people's access usually uses `file`. | |
| `server.admin_listener.tls_cert_file` | With `file`; reloaded on `SIGHUP`. | |
| `server.admin_listener.tls_key_file` | With `file`; reloaded on `SIGHUP`. | |
| `server.admin_listener.client_svid_auth` | Client SVIDs, for automation and CLI users. | |
| `server.admin_listener.client_svid_auth.enabled` | On or off. | |
| `server.admin_listener.client_svid_auth.accepted_trust_domains` | Their domains. | |
| `server.admin_listener.allow_basic_auth` | LDAP passwords on each API call. | Off; CI should use SVIDs |
| `server.admin_listener.session` | Web UI sessions. | |
| `server.admin_listener.session.idle_timeout` | Ends an idle session. | |
| `server.admin_listener.session.absolute_timeout` | Ends any session. | |
| `server.admin_listener.session.authz_recheck_interval` | How often a user's LDAP groups are re-read. | |
| `server.admin_listener.rate_limit` | Limits on logins and the API. | |
| `server.admin_listener.rate_limit.login_per_ip_per_min` | Logins per address. | |
| `server.admin_listener.rate_limit.login_per_user_per_min` | Logins per user and address. An attacker elsewhere cannot lock an administrator out. | |
| `server.admin_listener.rate_limit.login_per_user_global_per_min` | Logins per user overall. | |
| `server.admin_listener.rate_limit.api_per_principal_rps` | API calls per second, per principal. | |
| `server.admin_listener.rate_limit.max_tracked_keys` | The limiter's memory bound. | 10000 to 10000000 |
| `server.metrics_listener` | `GET /metrics`, plain HTTP without authentication. | |
| `server.metrics_listener.listen_address` | Bind it to a loopback or management address. | `127.0.0.1:9090` |

## `observability`, `admin_auth`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `observability` | Traces. | |
| `observability.tracing` | OpenTelemetry over OTLP/gRPC. | |
| `observability.tracing.otlp_endpoint` | The collector's `host:port`. | Empty: off |
| `observability.tracing.sample_ratio` | Share of new traces kept; a sampled caller's are always kept. | 0.1 |
| `observability.tracing.insecure` | For a collector without TLS. | Off |
| `observability.tracing.ca_cert_file` | Roots for the collector. Not with `insecure`. | System roots |
| `admin_auth` | How people sign in. | |
| `admin_auth.ldap` | The directory. | |
| `admin_auth.ldap.url` | `ldaps://…`. | |
| `admin_auth.ldap.ca_cert_file` | Its roots; reloaded on `SIGHUP`. | |
| `admin_auth.ldap.service_bind_dn` | The account that searches. | |
| `admin_auth.ldap.service_bind_password_env` | The variable holding its password. | |
| `admin_auth.ldap.user_base_dn` | Where users are. | |
| `admin_auth.ldap.user_filter` | Finds a user; `%s` is the escaped name. | |
| `admin_auth.ldap.group_membership_filter` | Finds a user's groups; `%s` is the user's DN. | |
| `admin_auth.ldap.nested_groups` | Follows groups in groups. | Off |

## `authorization`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `authorization` | Who may do what. | |
| `authorization.bindings` | Grants of a role, on jurisdiction patterns. | |
| `authorization.bindings.ldap_group_dn` | The group holding it. | Required for `break_glass` |
| `authorization.bindings.spiffe_id` | Or the SPIFFE principal holding it. | Required for `trusted_automation` |
| `authorization.bindings.role` | `viewer`, `operator`, `approver`, `break_glass`, `trusted_automation`, `admin.full_access`. | |
| `authorization.bindings.jurisdictions` | The jurisdiction patterns. | |
| `authorization.bindings.platforms` | `trusted_automation` only: limits it to these platforms. | All in its jurisdictions |
| `authorization.bindings.approval_reference_pattern` | `trusted_automation` only: the form of the upstream approval's reference. | Anchored RE2 |
| `authorization.bindings.rate_limit` | Overrides the API limit for this principal. | |
| `authorization.bindings.rate_limit.api_rps` | Requests per second. | |
| `authorization.bindings.rate_limit.burst` | Burst. | |
| `authorization.approval` | The maker-checker rules. | |
| `authorization.approval.required_jurisdictions` | Jurisdictions whose sides need an approver. Elsewhere, a requester acting for a side approves it automatically. | |
| `authorization.approval.require_distinct_approvers_across_jurisdictions` | A different person per side. | On |
| `authorization.approval.change_request_ttl` | When a pending request expires. | |

## `charter`, `regex_policy`, `bindings`, `propagation`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `charter` | The charter: the rules every jurisdiction complies with. How jurisdictions are derived, their name prefixes, which may connect, and accounts. | One per installation |
| `charter.source_jurisdictions` | One entry per trust domain any platform accepts. | Exactly one each |
| `charter.source_jurisdictions.trust_domain` | The domain. | |
| `charter.source_jurisdictions.mode` | `static`, one jurisdiction; `path_template`, from the path. | |
| `charter.source_jurisdictions.jurisdiction` | With `static`. | A jurisdiction path |
| `charter.source_jurisdictions.path_regex` | With `path_template`: starts with `^/`, ends with a literal `/`. Matched against the regex's fixed prefix only. | |
| `charter.source_jurisdictions.jurisdiction_template` | With `path_template`, such as `cloud/${1}/${2}`. | |
| `charter.name_prefixes` | Gives each owner its own name range. First match wins. | |
| `charter.name_prefixes.jurisdictions` | The jurisdiction patterns it applies to. | |
| `charter.name_prefixes.prefix` | `{n}` is the jurisdiction's n-th segment. | |
| `charter.name_prefixes.resources` | `source`, `target`, `binding`. | |
| `charter.interconnects` | Which cross-jurisdiction pairs may bind. | |
| `charter.interconnects.default_cross_jurisdiction` | When no rule matches: `deny` or `allow`. | Use `deny` |
| `charter.interconnects.rules` | Evaluated in order. | |
| `charter.interconnects.rules.name` | Unique; `default` is reserved. | |
| `charter.interconnects.rules.from` | Source jurisdiction patterns. | |
| `charter.interconnects.rules.to` | Target jurisdiction patterns. | |
| `charter.interconnects.rules.action` | `allow`, or `deny`. | |
| `charter.interconnects.rules.additional_approvals` | Further parties who must approve, on `allow` rules. | |
| `charter.interconnects.rules.additional_approvals.name` | The party; its side is `PARTY:<name>`. | |
| `charter.interconnects.rules.additional_approvals.jurisdiction` | Its jurisdiction, whose approvers decide. | A jurisdiction path |
| `charter.interconnects.rules.distinct_approvers` | `false` lets one person approve both sides for these pairs. | Audited risk |
| `charter.accounts` | The structure of account-managed jurisdictions. Absent: no accounts. | Optional |
| `charter.accounts.jurisdiction` | An account's root, such as `cloud/{account}`. `approval.required_jurisdictions` must cover it. | Contains `{account}` |
| `charter.accounts.source_jurisdiction` | A project's jurisdiction, such as `cloud/{account}/app/{project}`. | Below `jurisdiction`, not overlapping `target_jurisdiction` |
| `charter.accounts.target_jurisdiction` | A tenancy's jurisdiction, such as `cloud/{account}/data/{tenancy}`. | Below `jurisdiction` |
| `charter.accounts.ldap_groups` | Roles from the directory, one rule for all accounts. | |
| `charter.accounts.ldap_groups.search_base` | The DN every group lies below. | |
| `charter.accounts.ldap_groups.roles` | The rules. | |
| `charter.accounts.ldap_groups.roles.group_dn` | A DN with `{account}`, optionally `{project}`, each one whole value. | The same depth in every rule |
| `charter.accounts.ldap_groups.roles.role` | `viewer`, `operator`, `approver` or `break_glass`. | |
| `charter.accounts.ldap_groups.roles.jurisdiction` | The jurisdiction it gives, at or below `jurisdiction`. May end in `/*`. | Only placeholders of its `group_dn` |
| `regex_policy` | Limits on source regexes. | |
| `regex_policy.max_length` | Longest regex. | |
| `regex_policy.min_literal_path_segments` | Fixed path segments a regex must begin with. | |
| `regex_policy.narrowing_state_limit` | Work limit of the narrowing check. Undecided counts as not narrowing. | |
| `bindings` | Binding expiry. | |
| `bindings.max_expiry` | Longest `expiresAt` from now. | |
| `bindings.expiry_warning` | Announced this long before. | |
| `propagation` | Applying source and target changes to their bindings. | |
| `propagation.interval` | How often the queue is read. | |
| `propagation.max_concurrent` | Bounds the load on targets. | |

## `storage`, `secret_sealing`, `plugins`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `storage` | The database. | |
| `storage.postgres` | Connections. | |
| `storage.postgres.app_dsn_env` | The variable holding `ligo_app`'s DSN. | `verify-full` |
| `storage.postgres.reader_dsn_env` | `ligo_reader`'s. | `verify-full` |
| `storage.postgres.dbos_dsn_env` | `ligo_dbos`'s. | `verify-full` |
| `storage.postgres.max_conns` | Per pool. | 1 to 1000 |
| `storage.postgres.app_statement_timeout` | Bounds a statement. | 100 ms to 5 min |
| `storage.postgres.reader_statement_timeout` | Bounds a resolver query. | 100 ms to 5 min |
| `storage.dbos` | The workflow journal. | |
| `storage.dbos.workflow_retention` | How long finished workflows, and their sealed checkpoints, are kept. | |
| `secret_sealing` | How secrets between stages are sealed. | |
| `secret_sealing.provider` | `vault-transit`. `local-kek` needs `--insecure-dev`: development only. | |
| `secret_sealing.vault_transit` | Transit. | |
| `secret_sealing.vault_transit.address` | Its address. | |
| `secret_sealing.vault_transit.namespace` | A Vault Enterprise namespace. | |
| `secret_sealing.vault_transit.auth_mount` | The JWT auth mount. | |
| `secret_sealing.vault_transit.role` | `ligo`'s role. | |
| `secret_sealing.vault_transit.jwt_audience` | One of `core_identity.svid_selector.jwt_audience`. | |
| `secret_sealing.vault_transit.mount` | The Transit mount. | |
| `secret_sealing.vault_transit.key_name` | The key. | Not exportable |
| `secret_sealing.vault_transit.ca_cert_file` | Roots for `address`. | System roots |
| `secret_sealing.local_kek_file` | `local-kek` only: a 32-byte key. | Not readable by others |
| `plugins` | The plugin host. | |
| `plugins.directory` | Root-owned, not writable by others. | `/usr/lib/ligo/plugins` |
| `plugins.rpc_timeout` | Each call's deadline. | 60 s |
| `plugins.retry` | Retryable errors within a step. | |
| `plugins.retry.max_attempts` | Attempts. | |
| `plugins.retry.initial_backoff` | First wait. | |
| `plugins.retry.max_backoff` | Longest wait. | |
| `plugins.max_concurrent_rpcs_per_instance` | Bounds the load on a backend. | 4 |
| `plugins.restart_backoff` | After a plugin process dies. | |
| `plugins.restart_backoff.initial` | First wait. | |
| `plugins.restart_backoff.max` | Longest wait. | |

## `ui`, `break_glass`, `notifications`, `reconciliation`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `ui` | The web UI. | |
| `ui.theme` | Your branding. Files must be owned by root; their hashes are audited at startup. | |
| `ui.theme.default_mode` | `system`, `light`, or `dark`. | `system` |
| `ui.theme.product_name` | Shown in the UI. | `ligo` |
| `ui.theme.directory` | Conventional files: `theme.css`, `logo.svg` or `.png`, `logo-dark.*`, `favicon.*`, `fonts/*.woff2`. | |
| `ui.theme.css_file` | Overrides the conventional file. | |
| `ui.theme.logo_file` | Overrides it. | |
| `ui.theme.logo_dark_file` | Overrides it. | |
| `ui.theme.favicon_file` | Overrides it. | |
| `ui.theme.fonts_dir` | Overrides it. | |
| `ui.theme.colors` | Token overrides, by `light` and `dark`, as CSS hex colours. | |
| `break_glass` | Emergency changes. | |
| `break_glass.min_justification_length` | Shortest justification. | At least 20 |
| `break_glass.incident_reference_pattern` | The form of an incident reference. | Anchored RE2 |
| `break_glass.policies` | The first entry matching a side's jurisdiction applies. | |
| `break_glass.policies.jurisdictions` | Its jurisdiction patterns. Each `break_glass` grant's jurisdictions must appear here. | |
| `break_glass.policies.default_ttl` | Until the change is reverted, unless ratified. | 5 min to 24 h |
| `break_glass.policies.max_ttl` | The longest allowed. | At most 24 h |
| `break_glass.policies.max_open` | How many may be open. | At least 1 |
| `break_glass.policies.warn_before` | When the expiry is announced. | |
| `notifications` | Webhooks. | |
| `notifications.webhooks` | Each receives the events it names, signed. | |
| `notifications.webhooks.name` | Its name. | |
| `notifications.webhooks.url` | `https://` only. | |
| `notifications.webhooks.ca_cert_file` | Roots for the URL. | |
| `notifications.webhooks.hmac_secret_env` | The variable holding its signing secret. | Must be set |
| `notifications.webhooks.timeout` | Each delivery's deadline. | |
| `notifications.webhooks.jurisdictions` | Only events about these jurisdiction patterns. | All |
| `notifications.webhooks.events` | The events. | |
| `reconciliation` | Repairs drift and rotates static secrets. | |
| `reconciliation.enabled` | On or off. | |
| `reconciliation.interval` | How often. | |
| `reconciliation.jitter` | Spreads the work. | |
| `reconciliation.max_concurrent` | Bounds the load on targets. | |

## Plugins: `identity_providers`, `secret_stores`, `platform_providers`

| Key | Meaning | Default and rules |
| :------------------------- | :------------------------------- | :------------------ |
| `identity_providers` | Stage 1. | |
| `identity_providers.type` | Such as `openldap.v1`. | A type has one kind |
| `identity_providers.builtin` | No binary. | |
| `identity_providers.binary` | Relative to `plugins.directory`. | |
| `identity_providers.sha256` | Its hash, checked before every start. | 64 lowercase hex |
| `identity_providers.instances` | Its instances. | |
| `secret_stores` | Stage 3; the same fields, and `network_flows` on each instance. | |
| `platform_providers` | Stage 2. | |
| `platform_providers.platforms` | Each platform is one of its instances. | |
| `identity_providers.instances.name` | Its name, unique within its kind. | |
| `identity_providers.instances.realm` | Its realm. Wiring must stay within one realm. | |
| `identity_providers.instances.svid_selector` | Selects its SVID: exactly one. | |
| `identity_providers.instances.svid_selector.match_expr` | An expression over the SVID, as for `core_identity`. | |
| `identity_providers.instances.svid_selector.jwt_audience` | Audiences of its JWT-SVIDs; includes any `bootstrap_credential`'s. | |
| `identity_providers.instances.svid_selector.allow_shared_svid` | Lets instances share a SPIFFE ID, as two platforms of one plugin do. | |
| `identity_providers.instances.config` | The plugin's own settings: below. | |
| `identity_providers.instances.network_flows` | Flows added to every binding that uses it. | |
| `identity_providers.instances.network_flows.name` | Its name, unique within its kind. | |
| `identity_providers.instances.network_flows.purpose` | What the flow is for, such as `DATA` or `CREDENTIALS`. | |
| `identity_providers.instances.network_flows.protocol` | Such as `TCP`. | |
| `identity_providers.instances.network_flows.destination` | A name or address, within its `allowed_endpoints`. | |
| `identity_providers.instances.network_flows.ports` | Its ports. | |
| `identity_providers.instances.network_flows.tls` | Whether the flow uses TLS. | |
| `identity_providers.instances.network_flows.server_name` | The TLS name to expect. | |
| `identity_providers.instances.network_flows.description` | What it is, for readers. | |
| `secret_stores.type` | The plugin type, such as `postgres.v1`. A type has one kind. | |
| `secret_stores.builtin` | A plugin inside `ligo`, with no binary. | |
| `secret_stores.binary` | Its file, relative to `plugins.directory`. | |
| `secret_stores.sha256` | Its hash, 64 lowercase hex, checked before every start. | |
| `secret_stores.instances` | Its instances. | |
| `secret_stores.instances.name` | Its name, unique within its kind. | |
| `secret_stores.instances.realm` | Its realm. Wiring must stay within one realm. | |
| `secret_stores.instances.svid_selector` | Selects its SVID: exactly one. | |
| `secret_stores.instances.svid_selector.match_expr` | An expression over the SVID, as for `core_identity`. | |
| `secret_stores.instances.svid_selector.jwt_audience` | Audiences of its JWT-SVIDs; includes any `bootstrap_credential`'s. | |
| `secret_stores.instances.svid_selector.allow_shared_svid` | Lets instances share a SPIFFE ID, as two platforms of one plugin do. | |
| `secret_stores.instances.config` | The plugin's own settings: below. | |
| `secret_stores.instances.network_flows` | Flows added to every binding that uses it. | |
| `secret_stores.instances.network_flows.name` | Its name, unique within its kind. | |
| `secret_stores.instances.network_flows.purpose` | What the flow is for, such as `DATA` or `CREDENTIALS`. | |
| `secret_stores.instances.network_flows.protocol` | Such as `TCP`. | |
| `secret_stores.instances.network_flows.destination` | A name or address, within its `allowed_endpoints`. | |
| `secret_stores.instances.network_flows.ports` | Its ports. | |
| `secret_stores.instances.network_flows.tls` | Whether the flow uses TLS. | |
| `secret_stores.instances.network_flows.server_name` | The TLS name to expect. | |
| `secret_stores.instances.network_flows.description` | What it is, for readers. | |
| `platform_providers.type` | The plugin type, such as `postgres.v1`. A type has one kind. | |
| `platform_providers.builtin` | A plugin inside `ligo`, with no binary. | |
| `platform_providers.binary` | Its file, relative to `plugins.directory`. | |
| `platform_providers.sha256` | Its hash, 64 lowercase hex, checked before every start. | |
| `platform_providers.platforms.name` | Its name, unique within its kind. | |
| `platform_providers.platforms.realm` | Its realm. Wiring must stay within one realm. | |
| `platform_providers.platforms.jurisdiction` | Its owner jurisdiction: the team that runs it. A jurisdiction path. | |
| `platform_providers.platforms.target_jurisdictions` | Jurisdiction patterns that may own targets here. By default its jurisdiction and below. | |
| `platform_providers.platforms.namespace_template` | What a target's namespace must be, from the placeholders of `charter.accounts.target_jurisdiction`, such as `{account}_{tenancy}`. Needs a plugin that declares a namespace field. | |
| `platform_providers.platforms.display_name` | Its name, for readers. | |
| `platform_providers.platforms.description` | What it is, for readers. | |
| `platform_providers.platforms.contacts` | Who to ask. | |
| `platform_providers.platforms.contacts.name` | Its name, unique within its kind. | |
| `platform_providers.platforms.contacts.email` | Their address. | |
| `platform_providers.platforms.check_existence` | Whether validation reads that a target's objects exist. | |
| `platform_providers.platforms.network_flows` | Flows added to every binding that uses it. | |
| `platform_providers.platforms.network_flows.name` | Its name, unique within its kind. | |
| `platform_providers.platforms.network_flows.purpose` | What the flow is for, such as `DATA` or `CREDENTIALS`. | |
| `platform_providers.platforms.network_flows.protocol` | Such as `TCP`. | |
| `platform_providers.platforms.network_flows.destination` | A name or address, within its `allowed_endpoints`. | |
| `platform_providers.platforms.network_flows.ports` | Its ports. | |
| `platform_providers.platforms.network_flows.tls` | Whether the flow uses TLS. | |
| `platform_providers.platforms.network_flows.server_name` | The TLS name to expect. | |
| `platform_providers.platforms.network_flows.description` | What it is, for readers. | |
| `platform_providers.platforms.identity_provider` | Its Stage 1: a type and an instance. | |
| `platform_providers.platforms.identity_provider.type` | The plugin type, such as `postgres.v1`. A type has one kind. | |
| `platform_providers.platforms.identity_provider.instance` | An instance of that type, in the same realm. | |
| `platform_providers.platforms.identity_provider.secret_storage_strategy` | Such as `vault-static`. May be omitted when one fits. | |
| `platform_providers.platforms.secret_store` | Its Stage 3: a type, an instance and a strategy. | |
| `platform_providers.platforms.secret_store.type` | The plugin type, such as `postgres.v1`. A type has one kind. | |
| `platform_providers.platforms.secret_store.instance` | An instance of that type, in the same realm. | |
| `platform_providers.platforms.secret_store.secret_storage_strategy` | Such as `vault-static`. May be omitted when one fits. | |
| `platform_providers.platforms.principal_prefix` | Replaces `bnd_` in new bindings' names, at most 4 characters. | |
| `platform_providers.platforms.allowed_source_trust_domains` | The trust domains of its sources. | |
| `platform_providers.platforms.rotation_interval` | How often static secrets rotate. | |
| `platform_providers.platforms.svid_selector` | Selects its SVID: exactly one. | |
| `platform_providers.platforms.svid_selector.match_expr` | An expression over the SVID, as for `core_identity`. | |
| `platform_providers.platforms.svid_selector.jwt_audience` | Audiences of its JWT-SVIDs; includes any `bootstrap_credential`'s. | |
| `platform_providers.platforms.svid_selector.allow_shared_svid` | Lets instances share a SPIFFE ID, as two platforms of one plugin do. | |
| `platform_providers.platforms.config` | The plugin's own settings: below. | |

:::

## Plugin configuration

Each plugin refuses, naming the field, any value that breaks its rules, and any field it does not know.

| `postgres.v1` field | Meaning | Rules |
| :----------------- | :----------------------------- | :------------------ |
| `host` | The server's name, verified against its certificate. | Required |
| `port` | Its port. | 1 to 65535 |
| `database` | The one database of this platform. | An identifier |
| `grantable_roles` | The privilege bounds. | Identifiers; this or `grantable_role_templates` is required |
| `grantable_role_templates` | Bounds per target: `{namespace}` stands for its schema. | Each holds `{namespace}` once |
| `allowed_endpoints` | Where outputs may point. | Must contain `host:port` |
| `bootstrap_credential` | The admin role's credential: `source: vault`, `address`, `auth_mount`, `role`, `jwt_audience`, `kv_path`. | `kv_path` only |
| `ca_file` | Roots for the server and that Vault. | System roots |
| `directory_group` | The group role of directory-verified roles. | Required with `EXTERNAL_DIR` |

| `vault.v1` field | Meaning | Rules |
| :----------------- | :----------------------------- | :------------------ |
| `address` | Vault or OpenBao. | `https://host[:port]` |
| `allowed_endpoints` | Must contain its `host:port`. | Required |
| `auth_mount` | The JWT auth mount, for the plugin and for workloads. | Required |
| `role` | The plugin's own JWT role. | Required |
| `workload_jwt_audience` | The audience of workloads' JWT-SVIDs for their roles. | Required |
| `kv_mount` | A KV v2 mount. | `kv` |
| `namespace` | A Vault Enterprise namespace. | |
| `database_mount` | The database secrets engine. | `database` |
| `db_connection` | The engine's connection to the target. | Required with `vault-dynamic` |
| `ca_file` | Roots for `address`. | System roots |

| `openldap.v1` field | Meaning | Rules |
| :----------------- | :----------------------------- | :------------------ |
| `url` | `ldaps://host[:port]`. | `ldap://` and StartTLS are refused |
| `service_ou_dn` | The accounts' parent. | A valid DN |
| `allowed_endpoints` | Must contain the `host:port` of `url`. | Required |
| `bootstrap_credential` | The service account, with its DN as `username`. | `kv_path` only |
| `ca_file` | Roots for the directory and that Vault. | System roots |
