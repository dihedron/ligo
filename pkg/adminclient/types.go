// SPDX-License-Identifier: MIT

package adminclient

import "github.com/dihedron/ligo/pkg/adminclient/internal/gen"

// The resources of the admin API. They are aliases of the types generated
// from api/openapi/admin.v1alpha1.yaml, under names of this package, so that
// a change of generator does not break an importer. Platform-specific parts
// (a target's definition and grants, a binding's parameters, auth and spec,
// an instance's config) are free-form JSON: their schemas are the plugins'.
type (
	Source              = gen.Source
	SourceDetail        = gen.SourceDetail // a source with its last 20 audit entries
	SourceSpec          = gen.SourceSpec
	Target              = gen.Target
	TargetDetail        = gen.TargetDetail // a target with its last 20 audit entries
	TargetSpec          = gen.TargetSpec
	AccessLevel         = gen.AccessLevel
	Binding             = gen.Binding
	BindingDetail       = gen.BindingDetail // a binding with its stages and last 20 audit entries
	BindingSpec         = gen.BindingSpec
	Stage               = gen.Stage
	Platform            = gen.Platform
	Instance            = gen.Instance // an identity provider or a secret store
	Definition          = gen.InstanceDefinition
	ChangeRequest       = gen.ChangeRequest
	Hold                = gen.Hold // a hold on a binding that a person removed in an emergency
	Side                = gen.Side
	AuditEntry          = gen.AuditEntry
	Account             = gen.Account
	CatalogTarget       = gen.CatalogTarget
	CatalogDetail       = gen.CatalogTargetDetail // a target with the charter outcome for each of the caller's sources
	CatalogSource       = gen.CatalogSource
	Outcome             = gen.Outcome
	NetworkFlow         = gen.NetworkFlow
	Contact             = gen.Contact
	Visibility          = gen.Visibility
	ResourceState       = gen.ResourceState
	BindingPhase        = gen.BindingPhase
	ResourceType        = gen.ResourceType
	ChangeRequestStatus = gen.ChangeRequestStatus
)

// Page is one page of a list: its items and the token of the next page, empty
// at the end.
type Page[T any] struct {
	Items         []T
	NextPageToken string
}

// The answers and requests of the operations of containment, charter,
// maintenance, audit and executors.
type (
	SourceTestRequest = gen.SourceTestRequest
	SourceTestResult  = gen.SourceTestResult
	RevokeRequest     = gen.RevokeRequest // Comment is required; ApprovalReference is Options'
	Revocation        = gen.Revocation    // the requests filed, and the bindings that could not be revoked
	Charter           = gen.Charter
	Evaluation        = gen.Evaluation
	Maintenance       = gen.Maintenance
	AuditVerification = gen.AuditVerification
	Executor          = gen.Executor
	ExecutorRecovery  = gen.ExecutorRecovery
)
