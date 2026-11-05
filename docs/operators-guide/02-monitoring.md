# Monitoring

Logs are structured JSON, with `request_id`, `binding_id`, `workflow_id` and `attempt`, and secrets redacted. Traces are off until you set `observability.tracing.otlp_endpoint`; a workflow joins the trace of the request that started it.

## Alert on these

| Metric or check | Alert when | First step |
| :------------------------------- | :------------- | :---------------------------- |
| `ligo_audit_chain_valid` | 0 | Treat as a security incident: *Incident procedures* |
| `ligo_db_scrape_success` | 0 | The database's gauges are stale: check PostgreSQL |
| `ligo_bindings{phase="FAILED"}`, `{phase="DELETE_FAILED"}` | Above 0 for long | `ligo list bindings`, then the error reference |
| `ligo_propagation_oldest_seconds{priority="0"}` | Rising | Removals of access are waiting: a platform is likely down |
| `ligo_privilege_bound_violations` | Above 0 | An access level grants beyond its platform's current bounds |
| `ligo_interconnect_violations` | Above 0 | Existing bindings the policy would now deny |
| `ligo_rotation_overdue` | Above 0 | Static secrets are not rotating: check `reconciliation` and the plugin |
| `ligo_resolution_cache_age_seconds` | Near `max_staleness` | The workload API will soon refuse: check PostgreSQL |
| `ligo_bundle_conflicts_total` | Rising | Two sources claim one trust domain's bundle: check SPIRE |
| `ligo_break_glass_open` | Above 0 | Someone used break-glass: review it |
| `ligo_notifications_abandoned_total` | Rising | A webhook has been down for 24 h |
| `ligo_plugin_process_restarts_total` | Rising | A plugin keeps dying: see its logs |

## All metrics

No metric carries a scope label, as scopes are unbounded. Per-scope views come from the admin API and the audit log.

::: landscape

| Metric | Labels | Meaning |
| :------------------------------- | :------------------- | :----------------------------- |
| `ligo_bindings` | `phase`, `zone` | Bindings by phase |
| `ligo_bindings_expiring` | `within` | Bindings expiring within `24h` or `7d` |
| `ligo_binding_expirations_total` | `result` | Expiries: `revoked`, `deferred` |
| `ligo_workflow_duration_seconds` | `op`, `result` | Workflow duration |
| `ligo_step_duration_seconds` | `stage`, `provider_type`, `result` | Step duration |
| `ligo_plugin_rpc_total` | `provider_type`, `instance`, `method`, `code` | Plugin calls |
| `ligo_plugin_process_restarts_total` | `type`, `zone` | Plugin process restarts |
| `ligo_workload_requests_total` | `auth_mode`, `result` | Workload API calls |
| `ligo_resolution_cache_age_seconds` | | Age of the resolver's cache |
| `ligo_resolution_invalid_regex_total` | | Stored regexes the resolver refused |
| `ligo_bundle_conflicts_total` | | Conflicting trust bundles |
| `ligo_change_requests` | `status`, `zone` | Change requests |
| `ligo_change_request_sides_pending` | `resource_type`, `side_kind` | Sides awaiting a decision |
| `ligo_delegated_approvals_total` | | Sides approved by delegation |
| `ligo_sources` | `state` | Sources |
| `ligo_targets` | `state` | Targets |
| `ligo_propagation_queue_depth` | `priority` | Bindings waiting for a change |
| `ligo_propagation_oldest_seconds` | `priority` | Age of the oldest; priority 0 removes access |
| `ligo_propagation_started_total` | `cause` | Propagations started |
| `ligo_propagation_failed_total` | `cause` | Propagations failed |
| `ligo_privilege_bound_violations` | | Levels beyond their platform's bounds |
| `ligo_regex_narrowing_checks_total` | `result` | `narrowing`, `wider`, `undecided` |
| `ligo_interconnect_denied_total` | `rule` | Requests the policy refused |
| `ligo_interconnect_violations` | | Existing bindings the policy would deny |
| `ligo_audit_chain_valid` | | 1 while the chain verifies |
| `ligo_break_glass_open` | `zone` | Open emergency changes |
| `ligo_break_glass_total` | `zone`, `operation`, `outcome` | `ratified`, `reverted`, `revert_failed`, `review_overdue` |
| `ligo_notifications_abandoned_total` | | Notifications given up on |
| `ligo_rotation_overdue` | | Static secrets past their rotation |
| `ligo_db_scrape_success` | | 1 when the database's gauges are current |

:::

## Webhooks

Each request carries `X-Ligo-Timestamp` and `X-Ligo-Signature: sha256=<hex HMAC-SHA256 over "<timestamp>.<body>">`. Receivers should check it, refuse timestamps older than 5 minutes, and deduplicate on `eventId`. A failure never delays the change it announces. Page on these at least: `BREAK_GLASS_USED`, `BREAK_GLASS_REVERT_FAILED`, `BREAK_GLASS_REVIEW_OVERDUE`, `CONFIG_APPROVAL_POLICY_WEAKENED`, `CONFIG_GOVERNANCE_POLICY_CHANGED`, `SYSTEM_INTERCONNECT_VIOLATIONS`.

## The audit log

Every state-changing action, propagation and workflow outcome is audited, in a hash chain the application can only append to. Forward it to your SIEM. Verify it with `ligo audit verify`, and read it with `ligo audit list`.
