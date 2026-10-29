package flows

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func decode(t *testing.T, doc string) Flow {
	t.Helper()
	var f Flow
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatalf("%s: %v", doc, err)
	}
	return f
}

// TestSchema checks flows against the normative schema of §3.3 and the
// rules it cannot express.
func TestSchema(t *testing.T) {
	ok := `{"name":"ledger-listener","purpose":"DATA","protocol":"TCP","destination":"ledger-db.prod.internal","ports":[1522],"tls":true,"serverName":"ledger-db.prod.internal","description":"Dedicated TCPS listener"}`
	for doc, want := range map[string]bool{
		ok: true,
		`{"name":"dns","purpose":"DISCOVERY","protocol":"UDP","destination":"10.0.0.0/24","ports":["5300-5310",53],"tls":false}`: true,
		`{"name":"v6","purpose":"DATA","protocol":"TCP","destination":"2001:db8::1","ports":[443],"tls":true}`:                   true,
		strings.Replace(ok, `"ledger-listener"`, `"Ledger"`, 1):                                                                  false, // name pattern
		strings.Replace(ok, `"DATA"`, `"OTHER"`, 1):                                                                              false, // purpose enum
		strings.Replace(ok, `"TCP"`, `"SCTP"`, 1):                                                                                false, // protocol enum
		strings.Replace(ok, `[1522]`, `[]`, 1):                                                                                   false, // minItems
		strings.Replace(ok, `[1522]`, `[0]`, 1):                                                                                  false, // minimum
		strings.Replace(ok, `[1522]`, `[65536]`, 1):                                                                              false, // maximum
		strings.Replace(ok, `[1522]`, `["10-5"]`, 1):                                                                             false, // low < high
		strings.Replace(ok, `[1522]`, `["5-5"]`, 1):                                                                              false, // low < high
		strings.Replace(ok, `[1522]`, `["0-5"]`, 1):                                                                              false, // 1..65535
		strings.Replace(ok, `[1522]`, `["1-99999"]`, 1):                                                                          false, // 1..65535
		strings.Replace(ok, `"tls":true`, `"tls":false`, 1):                                                                      false, // serverName only if tls
		strings.Replace(ok, `"ledger-db.prod.internal","ports"`, `"-bad-.x","ports"`, 1):                                         false, // destination
		strings.Replace(ok, `"ledger-db.prod.internal","ports"`, `"10.0.0.0/33","ports"`, 1):                                     false,
		strings.Replace(ok, `"tls":true`, `"tls":true,"declaredBy":"ligo"`, 1):                                                   false, // output only
	} {
		f := decode(t, doc)
		err := f.Validate()
		if want && err != nil {
			t.Errorf("%s: %v", doc, err)
		}
		if !want && !errors.Is(err, ErrInvalidFlow) {
			t.Errorf("%s: got %v, want ErrInvalidFlow", doc, err)
		}
	}
}

func TestUnknownField(t *testing.T) {
	var f Flow
	if err := json.Unmarshal([]byte(`{"name":"x","bogus":1}`), &f); err == nil {
		t.Error("unknown field accepted (additionalProperties: false)")
	}
}

func TestPortsRoundTrip(t *testing.T) {
	f := decode(t, `{"name":"a","purpose":"DATA","protocol":"TCP","destination":"h","ports":[53,"5300-5310"],"tls":false}`)
	out, err := json.Marshal(f.Ports)
	if err != nil || string(out) != `[53,"5300-5310"]` {
		t.Errorf("ports marshal to (%s, %v)", out, err)
	}
}

func TestValidateList(t *testing.T) {
	a := decode(t, `{"name":"a","purpose":"DATA","protocol":"TCP","destination":"h","ports":[1],"tls":false}`)
	if err := ValidateList([]Flow{a, a}, 32); !errors.Is(err, ErrInvalidFlow) {
		t.Errorf("duplicate names: %v", err)
	}
	if err := ValidateList([]Flow{a}, 0); !errors.Is(err, ErrInvalidFlow) {
		t.Errorf("too many flows: %v", err)
	}
	if err := ValidateList([]Flow{a}, 32); err != nil {
		t.Error(err)
	}
}

// allowed is the allowlist of oracle-prod in §8.1.
var allowed = []string{"ora-scan.prod.internal:1521", "ledger-db.prod.internal:1522"}

// TestAC64 is acceptance scenario AC-64 (allowlist part), and INV-24.
func TestAC64(t *testing.T) {
	al, err := ParseAllowlist(allowed)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		dest  string
		ports string
		ok    bool
	}{
		{"ledger-db.prod.internal", "[1522]", true},
		{"LEDGER-DB.prod.internal", "[1522]", true},
		{"evil.example.org", "[443]", false},
		{"ledger-db.prod.internal", "[1600]", false},
		{"ledger-db.prod.internal", `["1522-1523"]`, false},
	} {
		checkAllowed(t, al, v.dest, v.ports, v.ok)
	}
}

func TestAllowlist(t *testing.T) {
	al, err := ParseAllowlist([]string{"10.1.0.0/16", "db.internal", "[2001:db8::7]:5432", "192.0.2.10:443", "db.internal:5432"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		dest  string
		ports string
		ok    bool
	}{
		{"10.1.2.3", "[80]", true},
		{"10.1.2.0/24", `["1000-2000"]`, true},
		{"10.0.0.0/8", "[80]", false}, // wider than the allowed CIDR
		{"10.2.0.1", "[80]", false},
		{"db.internal", `[1, "100-200"]`, true}, // the entry without port allows any
		{"2001:db8::7", "[5432]", true},
		{"2001:db8::7", "[5433]", false},
		{"192.0.2.10", "[443]", true},
		{"192.0.2.10", "[443, 444]", false},
		{"other.internal", "[80]", false},
		{"10.1.2.3.example", "[80]", false}, // a name never matches a CIDR
	} {
		checkAllowed(t, al, v.dest, v.ports, v.ok)
	}
	for _, bad := range []string{"", "db.internal:0", "db.internal:x", "10.0.0.0/8:80", "-x"} {
		if _, err := ParseAllowlist([]string{bad}); err == nil {
			t.Errorf("allowlist entry %q accepted", bad)
		}
	}
}

// TestParseMultirange reads the ports column back (target_network_flows):
// single ports stay numbers, wider ranges stay ranges.
func TestParseMultirange(t *testing.T) {
	ports, err := ParseMultirange("{[1522,1523),[2000,2101)}")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ports)
	if string(data) != `[1522,"2000-2100"]` {
		t.Errorf("ports %s", data)
	}
	for _, bad := range []string{"", "{}", "{[0,1)}", "{(1,2]}", "1522"} {
		if _, err := ParseMultirange(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestCanonicalPorts: ports compare as the database stores them, sorted
// with neighbours merged.
func TestCanonicalPorts(t *testing.T) {
	var ports []Port
	if err := json.Unmarshal([]byte(`[1523, 1522, 443, "2000-2100", "2050-2200"]`), &ports); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(CanonicalPorts(ports))
	if string(data) != `[443,"1522-1523","2000-2200"]` {
		t.Errorf("ports %s", data)
	}
}

// TestCheckEndpoint: an endpoint without a port is allowed only by an entry
// without a port (§5.7).
func TestCheckEndpoint(t *testing.T) {
	al, err := ParseAllowlist([]string{"10.1.0.0/16", "db.internal", "pg.internal:5432", "[2001:db8::7]:5432"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		host string
		port int
		ok   bool
	}{
		{"db.internal", 0, true},
		{"DB.internal", 8200, true},
		{"pg.internal", 5432, true},
		{"pg.internal", 5433, false},
		{"pg.internal", 0, false}, // no port: only an entry without port allows it
		{"10.1.2.3", 9000, true},
		{"10.2.0.1", 9000, false},
		{"2001:db8::7", 5432, true},
		{"2001:db8::7", 0, false},
		{"other.internal", 0, false},
		{"", 0, false},
	} {
		err := al.CheckEndpoint(v.host, v.port)
		if v.ok != (err == nil) || (err != nil && !errors.Is(err, ErrDestinationNotAllowed)) {
			t.Errorf("%s:%d: %v", v.host, v.port, err)
		}
	}
}

func checkAllowed(t *testing.T, al Allowlist, dest, ports string, ok bool) {
	t.Helper()
	f := decode(t, `{"name":"f","purpose":"DATA","protocol":"TCP","destination":"`+dest+`","ports":`+ports+`,"tls":false}`)
	err := al.CheckFlow(f)
	if ok && err != nil {
		t.Errorf("%s %s: %v", dest, ports, err)
	}
	if !ok && !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("%s %s: got %v, want ErrDestinationNotAllowed", dest, ports, err)
	}
}

// TestEffective reproduces the computed list of §3.6.
func TestEffective(t *testing.T) {
	target := []Flow{decode(t, `{"name":"ledger-listener","purpose":"DATA","protocol":"TCP","destination":"ledger-db.prod.internal","ports":[1522],"tls":true,"serverName":"ledger-db.prod.internal"}`)}
	platform := []Flow{decode(t, `{"name":"scan-listener","purpose":"DATA","protocol":"TCP","destination":"ora-scan.prod.internal","ports":[1521],"tls":true,"serverName":"ora-scan.prod.internal"}`)}
	store := []Flow{decode(t, `{"name":"vault","purpose":"CREDENTIALS","protocol":"TCP","destination":"vault.prod.internal","ports":[8200],"tls":true,"serverName":"vault.prod.internal"}`)}
	ligo := LigoFlow("ligo.prod.internal", 8443, "ligo.prod.internal")
	got, err := json.Marshal(Effective("ledger-schema", target, "oracle-prod", platform, "vault-prod", store, ligo))
	if err != nil {
		t.Fatal(err)
	}
	want := `[` +
		`{"name":"ledger-listener","purpose":"DATA","protocol":"TCP","destination":"ledger-db.prod.internal","ports":[1522],"tls":true,"serverName":"ledger-db.prod.internal","declaredBy":"target:ledger-schema"},` +
		`{"name":"scan-listener","purpose":"DATA","protocol":"TCP","destination":"ora-scan.prod.internal","ports":[1521],"tls":true,"serverName":"ora-scan.prod.internal","declaredBy":"platform:oracle-prod"},` +
		`{"name":"vault","purpose":"CREDENTIALS","protocol":"TCP","destination":"vault.prod.internal","ports":[8200],"tls":true,"serverName":"vault.prod.internal","declaredBy":"secret-store:vault-prod"},` +
		`{"name":"ligo-workload-api","purpose":"DISCOVERY","protocol":"TCP","destination":"ligo.prod.internal","ports":[8443],"tls":true,"serverName":"ligo.prod.internal","declaredBy":"ligo"}]`
	if string(got) != want {
		t.Errorf("effective flows:\n got %s\nwant %s", got, want)
	}
	if target[0].DeclaredBy != "" {
		t.Error("Effective modified its input")
	}
}

// TestEffectiveCatalog checks the catalog view (no secret store) and the
// order by name within a group.
func TestEffectiveCatalog(t *testing.T) {
	mk := func(name string) Flow {
		return decode(t, `{"name":"`+name+`","purpose":"DATA","protocol":"TCP","destination":"h","ports":[1],"tls":false}`)
	}
	got := Effective("t", []Flow{mk("b"), mk("a")}, "p", []Flow{mk("c")}, "", []Flow{mk("s")}, LigoFlow("l", 8443, "l"))
	var names []string
	for _, f := range got {
		names = append(names, f.DeclaredBy+"/"+f.Name)
	}
	if strings.Join(names, " ") != "target:t/a target:t/b platform:p/c ligo/ligo-workload-api" {
		t.Errorf("got %v", names)
	}
}

func TestPortsYAML(t *testing.T) {
	var f Flow
	doc := `{ name: vault, purpose: CREDENTIALS, protocol: TCP, destination: "vault.prod.internal", ports: [8200, "9000-9010"], tls: true, server_name: "vault.prod.internal" }`
	if err := yaml.Unmarshal([]byte(doc), &f); err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if out, _ := json.Marshal(f.Ports); string(out) != `[8200,"9000-9010"]` || f.ServerName != "vault.prod.internal" {
		t.Errorf("got ports %s, serverName %q", out, f.ServerName)
	}
}
