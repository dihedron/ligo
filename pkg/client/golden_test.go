// SPDX-License-Identifier: MIT

package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// PY-G: the golden documents of api/testdata/workload decode to the values in expected.json; the Python
// SDK's tests decode the same files to the same values.
func TestGoldenDocuments(t *testing.T) {
	dir := filepath.Join("..", "..", "api", "testdata", "workload")
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var want map[string]any
	if err := json.Unmarshal(read("expected.json"), &want); err != nil {
		t.Fatal(err)
	}
	// normalize turns a value into what expected.json holds, through JSON.
	normalize := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	var bdoc struct {
		Items []wireBinding `json:"items"`
	}
	if err := json.Unmarshal(read("bindings.json"), &bdoc); err != nil {
		t.Fatal(err)
	}
	bindings := []map[string]any{}
	for _, w := range bdoc.Items {
		b := w.binding()
		endpoint, _ := b.Spec["endpoint"].(string)
		bindings = append(bindings, map[string]any{"id": b.ID, "name": b.Name, "source": b.Source, "target": b.Target,
			"accessLevel": b.AccessLevel, "platformType": b.PlatformType, "platform": b.Platform, "revision": b.Revision,
			"updatedAt": b.UpdatedAt.Unix(), "description": b.Description, "annotations": orEmpty(b.Annotations), "endpoint": endpoint,
			"auth": map[string]any{"strategy": b.Auth.Strategy, "storeType": b.Auth.StoreType, "storeInstance": b.Auth.StoreInstance,
				"config": orEmpty(b.Auth.Config)}})
	}
	if got := normalize(bindings); !reflect.DeepEqual(got, want["bindings"]) {
		t.Errorf("bindings:\n got %v\nwant %v", got, want["bindings"])
	}

	var fdoc struct {
		Items []wireFlows `json:"items"`
	}
	if err := json.Unmarshal(read("flows.json"), &fdoc); err != nil {
		t.Fatal(err)
	}
	flows := []map[string]any{}
	for _, w := range fdoc.Items {
		bf := w.flows()
		fl := []map[string]any{}
		for _, f := range bf.Flows {
			ports := [][2]int{}
			for _, p := range f.Ports {
				ports = append(ports, [2]int{p.Low, p.High})
			}
			fl = append(fl, map[string]any{"name": f.Name, "purpose": f.Purpose, "protocol": f.Protocol, "destination": f.Destination,
				"ports": ports, "tls": f.TLS, "serverName": f.ServerName, "description": f.Description, "declaredBy": f.DeclaredBy})
		}
		flows = append(flows, map[string]any{"binding": bf.Binding, "source": bf.Source, "target": bf.Target, "flows": fl})
	}
	if got := normalize(flows); !reflect.DeepEqual(got, want["flows"]) {
		t.Errorf("flows:\n got %v\nwant %v", got, want["flows"])
	}

	token, ttl, err := parseLogin(read("store-login.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := normalize(map[string]any{"token": token, "ttlSeconds": int(ttl / time.Second)}); !reflect.DeepEqual(got, want["login"]) {
		t.Errorf("login: %v", got)
	}
	now := time.Unix(1_800_000_000, 0)
	for name, strategy := range map[string]string{"static": strategyStatic, "dynamic": "vault-dynamic"} {
		c, err := parseSecret(strategy, read("store-"+name+".json"), now)
		if err != nil {
			t.Fatal(err)
		}
		lease := 0
		if !c.Expires.IsZero() {
			lease = int(c.Expires.Sub(now) / time.Second)
		}
		got := normalize(map[string]any{"username": c.Username, "password": c.Password, "leaseSeconds": lease})
		if !reflect.DeepEqual(got, want[name]) {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
