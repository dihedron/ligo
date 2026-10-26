package pluginsdk

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// fakeWorkload is a Workload API client with fixed X.509-SVIDs; it issues
// JWT-SVIDs valid from now() for lifetime and records their parameters.
type fakeWorkload struct {
	svids    []*x509svid.SVID
	err      error
	now      func() time.Time
	lifetime time.Duration
	params   []jwtsvid.Params
}

func (f *fakeWorkload) FetchX509SVIDs(context.Context) ([]*x509svid.SVID, error) {
	return f.svids, f.err
}

func (f *fakeWorkload) FetchJWTSVID(_ context.Context, p jwtsvid.Params) (*jwtsvid.SVID, error) {
	f.params = append(f.params, p)
	iat := f.now()
	enc := base64.RawURLEncoding.EncodeToString
	aud := append([]string{p.Audience}, p.ExtraAudiences...)
	claims := fmt.Sprintf(`{"sub":%q,"aud":["%s"],"iat":%d,"exp":%d,"n":%d}`,
		p.Subject, strings.Join(aud, `","`), iat.Unix(), iat.Add(f.lifetime).Unix(), len(f.params))
	token := enc([]byte(`{"alg":"ES256","kid":"k","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." + enc(make([]byte, 64))
	return jwtsvid.ParseInsecure(token, aud)
}

func svid(id, hint, cn string) *x509svid.SVID {
	return &x509svid.SVID{
		ID:           spiffeid.RequireFromString(id),
		Hint:         hint,
		Certificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
	}
}

// labSVIDs: what the prod agent gives a plugin process with two instances.
func labSVIDs() []*x509svid.SVID {
	return []*x509svid.SVID{
		svid("spiffe://prod.lab/ns/sys/sa/plugin-pg-prod", "pg-prod", "pg"),
		svid("spiffe://prod.lab/ns/sys/sa/plugin-pg-dr", "pg-dr", "pg"),
		svid("spiffe://test.lab/ns/sys/sa/plugin-pg-test", "pg-test", "pg"),
	}
}

func newSelector(t *testing.T, f *fakeWorkload, instance, td, expr string, aud ...string) *InstanceSVIDSelector {
	t.Helper()
	s, err := NewInstanceSVIDSelector(f, instance, td, SelectorConfig{MatchExpr: expr, JWTAudience: aud})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCompileSelector: boolean expressions over SVIDEvalEnv's normative
// names compile; anything else fails at config load (§5.4).
func TestCompileSelector(t *testing.T) {
	for _, ok := range []string{
		`hint == instance_name`,
		`spiffe_id == "spiffe://prod.lab/x" && trust_domain == "prod.lab"`,
		`path startsWith "/ns/sys/" and subject_cn != ""`,
	} {
		if _, err := CompileSelector(ok); err != nil {
			t.Errorf("CompileSelector(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		``,                // empty
		`hint`,            // not a boolean
		`spiffeID == "x"`, // not a field of the environment
		`hint ==`,         // syntax
		`len(path) + 1`,   // not a boolean
	} {
		if _, err := CompileSelector(bad); err == nil {
			t.Errorf("CompileSelector(%q) compiled", bad)
		}
	}
}

func TestSelectX509SVID(t *testing.T) {
	f := &fakeWorkload{svids: labSVIDs()}
	got, err := newSelector(t, f, "pg-prod", "prod.lab", `hint == instance_name`).SelectX509SVID(context.Background())
	if err != nil || got.ID.String() != "spiffe://prod.lab/ns/sys/sa/plugin-pg-prod" {
		t.Errorf("SelectX509SVID = (%v, %v)", got, err)
	}
}

func TestSelectX509SVIDRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		expr, td, want string
	}{
		"none":    {`hint == "nope"`, "prod.lab", "matched no SVID"},
		"several": {`subject_cn == "pg"`, "prod.lab", "matched more than one SVID"},
		"foreign": {`hint == "pg-test"`, "prod.lab", "foreign trust domain"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newSelector(t, &fakeWorkload{svids: labSVIDs()}, "pg-prod", tc.td, tc.expr).SelectX509SVID(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	agentDown := errors.New("agent down")
	_, err := newSelector(t, &fakeWorkload{err: agentDown}, "pg-prod", "prod.lab", `true`).SelectX509SVID(context.Background())
	if !errors.Is(err, agentDown) {
		t.Errorf("Workload API error: %v", err)
	}
}

// TestNewSelectorRefusals: a bad expression or no JWT audience for FetchJWT.
func TestNewSelectorRefusals(t *testing.T) {
	if _, err := NewInstanceSVIDSelector(&fakeWorkload{}, "i", "prod.lab", SelectorConfig{MatchExpr: `hint`}); err == nil {
		t.Error("a non-boolean expression was accepted")
	}
	s := newSelector(t, &fakeWorkload{svids: labSVIDs()}, "pg-prod", "prod.lab", `hint == instance_name`)
	if _, err := s.FetchJWT(context.Background()); err == nil {
		t.Error("FetchJWT without jwt_audience gave a token")
	}
}

// TestFetchJWT: the selected subject, jwt_audience[0] as Audience and the
// rest as ExtraAudiences; cached until 80% of the lifetime (§5.4).
func TestFetchJWT(t *testing.T) {
	now := time.Now().Truncate(time.Second) // the fake's tokens are parsed against the real clock
	f := &fakeWorkload{svids: labSVIDs(), now: func() time.Time { return now }, lifetime: 100 * time.Second}
	s := newSelector(t, f, "pg-prod", "prod.lab", `hint == instance_name`, "https://bao", "extra")
	s.now = f.now
	ctx := context.Background()

	first, err := s.FetchJWT(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := f.params[0]
	if p.Subject.String() != "spiffe://prod.lab/ns/sys/sa/plugin-pg-prod" || p.Audience != "https://bao" || !slices.Equal(p.ExtraAudiences, []string{"extra"}) {
		t.Errorf("params %+v", p)
	}
	now = now.Add(79 * time.Second)
	if again, _ := s.FetchJWT(ctx); again != first || len(f.params) != 1 {
		t.Error("refetched before 80% of the lifetime")
	}
	now = now.Add(time.Second)
	if fresh, _ := s.FetchJWT(ctx); fresh == first || len(f.params) != 2 {
		t.Error("cached past 80% of the lifetime")
	}
}
