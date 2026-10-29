package plugin_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// specProto returns the normative protobuf block of §5.9 of the specification.
func specProto(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../../.specs/ligo_specification.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "\n### 5.9 Plugin Protobuf contract")
	if !ok {
		t.Fatal("no §5.9 in the specification")
	}
	_, block, ok := strings.Cut(section, "\n```protobuf\n")
	if !ok {
		t.Fatal("no protobuf block in §5.9")
	}
	block, _, ok = strings.Cut(block, "\n```\n")
	if !ok {
		t.Fatal("unterminated protobuf block in §5.9")
	}
	return block + "\n"
}

// TestContractMatchesSpec: plugin.proto is §5.9's block, verbatim.
func TestContractMatchesSpec(t *testing.T) {
	file, err := os.ReadFile("plugin.proto")
	if err != nil {
		t.Fatal(err)
	}
	if string(file) != specProto(t) {
		t.Error("plugin.proto differs from §5.9: copy the block verbatim, then run make proto")
	}
}

// TestContractShape: the generated code has §5.9's package, services and RPCs.
func TestContractShape(t *testing.T) {
	fd := pluginv1.File_api_proto_plugin_v1_plugin_proto
	if got := fd.Package(); got != "ligo.plugin.v1" {
		t.Errorf("package %q", got)
	}
	want := map[string][]string{
		"PluginControl":          {"Describe", "ConfigureInstances", "Health"},
		"IdentityProviderPlugin": {"EnsureIdentity", "CleanupIdentity"},
		"PlatformProviderPlugin": {"GetUISchemas", "ValidateTarget", "ValidateBinding", "EnsureTarget", "CleanupTarget"},
		"SecretStorePlugin":      {"EnsureSecretStore", "CleanupSecretStore"},
	}
	services := fd.Services()
	if services.Len() != len(want) {
		t.Errorf("%d services, want %d", services.Len(), len(want))
	}
	for name, rpcs := range want {
		sd := services.ByName(protoreflect.Name(name))
		if sd == nil {
			t.Errorf("no service %s", name)
			continue
		}
		var got []string
		for i := range sd.Methods().Len() {
			got = append(got, string(sd.Methods().Get(i).Name()))
		}
		if !slices.Equal(got, rpcs) {
			t.Errorf("%s: RPCs %v, want %v", name, got, rpcs)
		}
	}
}
