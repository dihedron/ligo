package workload_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
)

// specProto returns the normative protobuf block of §7.1 of the specification.
func specProto(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../../.specs/ligo_specification.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "\n**gRPC (`api/proto/workload/v1alpha1/workload.proto`)**")
	if !ok {
		t.Fatal("no workload gRPC contract in §7.1")
	}
	_, block, ok := strings.Cut(section, "\n```protobuf\n")
	if !ok {
		t.Fatal("no protobuf block in §7.1")
	}
	block, _, ok = strings.Cut(block, "\n```\n")
	if !ok {
		t.Fatal("unterminated protobuf block in §7.1")
	}
	return block + "\n"
}

// TestContractMatchesSpec: workload.proto is §7.1's block, verbatim.
func TestContractMatchesSpec(t *testing.T) {
	file, err := os.ReadFile("workload.proto")
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != specProto(t) {
		t.Error("workload.proto differs from §7.1: copy the block verbatim, then run make proto")
	}
}

// TestContractShape: the generated code has §7.1's package, service and RPCs.
func TestContractShape(t *testing.T) {
	fd := workloadv1alpha1.File_api_proto_workload_v1alpha1_workload_proto
	if got := fd.Package(); got != "ligo.workload.v1alpha1" {
		t.Errorf("package %q", got)
	}
	if fd.Services().Len() != 1 {
		t.Fatalf("%d services, want 1", fd.Services().Len())
	}
	s := fd.Services().Get(0)
	var rpcs []string
	for i := range s.Methods().Len() {
		rpcs = append(rpcs, string(s.Methods().Get(i).Name()))
	}
	if s.Name() != "WorkloadBindingService" || !slices.Equal(rpcs, []string{"GetBindings", "GetFlows"}) {
		t.Errorf("service %s with %v", s.Name(), rpcs)
	}
}
