// Package metrics declares ligo's Prometheus metrics, under the normative
// names of §10.1, in one registry served on the metrics listener. Events
// are counted where they happen, through the variables here; state is
// read from the database at each scrape (DB). No metric carries a scope
// label: the number of scopes is unbounded (§10.1).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Registry holds every ligo metric, and the Go runtime's.
var Registry = prometheus.NewRegistry()

func counter(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

func histogram(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help,
		Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300}}, labels)
}

func gauge(name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

// Events, counted where they happen.
var (
	WorkflowDuration       = histogram("ligo_workflow_duration_seconds", "Duration of apply and delete workflows.", "op", "result")
	StepDuration           = histogram("ligo_step_duration_seconds", "Duration of workflow steps.", "stage", "provider_type", "result")
	PluginRPCs             = counter("ligo_plugin_rpc_total", "Plugin RPCs by method and gRPC code.", "provider_type", "instance", "method", "code")
	WorkloadRequests       = counter("ligo_workload_requests_total", "Workload API requests.", "auth_mode", "result")
	PropagationStarted     = counter("ligo_propagation_started_total", "Propagations of source and target changes started.", "cause")
	PropagationFailed      = counter("ligo_propagation_failed_total", "Propagations of source and target changes that failed.", "cause")
	BindingExpirations     = counter("ligo_binding_expirations_total", "Expired bindings revoked or deferred.", "result")
	RegexNarrowingChecks   = counter("ligo_regex_narrowing_checks_total", "Regex narrowing checks by result.", "result")
	InterconnectDenied     = counter("ligo_interconnect_denied_total", "Changes denied by the interconnection policy, by rule.", "rule")
	PluginRestarts         = counter("ligo_plugin_process_restarts_total", "Plugin process restarts.", "type", "zone")
	BreakGlass             = counter("ligo_break_glass_total", "Break-glass changes by outcome.", "zone", "operation", "outcome")
	NotificationsAbandoned = counter("ligo_notifications_abandoned_total", "Webhook notifications given up after their retries.", "webhook")
	DelegatedApprovals     = counter("ligo_delegated_approvals_total", "Sides approved by delegation (ADR-11).", "principal", "zone", "operation")
	BundleConflicts        = counter("ligo_bundle_conflicts_total", "Bundles discarded because they came from a non-authoritative socket.", "trust_domain", "socket_zone")
)

// State known in the process: set by startup's checks and the audit
// chain's periodic verification.
var (
	InterconnectViolations   = gauge("ligo_interconnect_violations", "Existing bindings the current interconnection policy would deny (§8.2 rule 18).")
	PrivilegeBoundViolations = gauge("ligo_privilege_bound_violations", "Access levels and flows outside their platform's current bounds (§8.2 rule 19).")
	AuditChainValid          = gauge("ligo_audit_chain_valid", "1 when the last verification of the audit chain succeeded, else 0.")
)

func init() {
	Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		WorkflowDuration, StepDuration, PluginRPCs, WorkloadRequests, PropagationStarted, PropagationFailed, BindingExpirations,
		RegexNarrowingChecks, InterconnectDenied, PluginRestarts, BreakGlass, NotificationsAbandoned, DelegatedApprovals, BundleConflicts,
		InterconnectViolations, PrivilegeBoundViolations, AuditChainValid)
}
