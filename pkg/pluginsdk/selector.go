// Package pluginsdk is what every ligo plugin builds on (§5): SVID selection,
// bootstrap credentials, redacted logging and the plugin error model.
package pluginsdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// SVIDEvalEnv is the environment of a selector expression; its expr names
// are normative (§5.4).
type SVIDEvalEnv struct {
	SpiffeID     string `expr:"spiffe_id"`
	TrustDomain  string `expr:"trust_domain"`
	Path         string `expr:"path"`
	Hint         string `expr:"hint"`
	SubjectCN    string `expr:"subject_cn"`
	InstanceName string `expr:"instance_name"`
}

// SelectorConfig is an instance's svid_selector.
type SelectorConfig struct {
	MatchExpr   string   `json:"matchExpr"   yaml:"match_expr"`
	JWTAudience []string `json:"jwtAudience" yaml:"jwt_audience"`
}

// CompileSelector compiles a match expression; it must be a boolean over
// SVIDEvalEnv, checked when the configuration is loaded (§5.4).
func CompileSelector(matchExpr string) (*vm.Program, error) {
	if matchExpr == "" {
		return nil, errors.New("empty selector expression")
	}
	program, err := expr.Compile(matchExpr, expr.Env(SVIDEvalEnv{}), expr.AsBool())
	if err != nil {
		return nil, fmt.Errorf("selector expression: %w", err)
	}
	return program, nil
}

// WorkloadClient is the part of the SPIRE Workload API a selector uses;
// *workloadapi.Client implements it.
type WorkloadClient interface {
	FetchX509SVIDs(ctx context.Context) ([]*x509svid.SVID, error)
	FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error)
}

// InstanceSVIDSelector resolves a plugin instance's own SVID among those the
// agent issues to the plugin process.
type InstanceSVIDSelector struct {
	client          WorkloadClient
	program         *vm.Program
	instanceName    string
	zoneTrustDomain string
	audience        []string
	now             func() time.Time

	mu       sync.Mutex
	jwt      string
	jwtUntil time.Time
}

// NewInstanceSVIDSelector compiles cfg's expression for one instance of the
// zone with trust domain zoneTrustDomain.
func NewInstanceSVIDSelector(client WorkloadClient, instanceName, zoneTrustDomain string, cfg SelectorConfig) (*InstanceSVIDSelector, error) {
	program, err := CompileSelector(cfg.MatchExpr)
	if err != nil {
		return nil, fmt.Errorf("instance %q: %w", instanceName, err)
	}
	return &InstanceSVIDSelector{
		client: client, program: program, instanceName: instanceName,
		zoneTrustDomain: zoneTrustDomain, audience: cfg.JWTAudience, now: time.Now,
	}, nil
}

// SelectX509SVID returns the single SVID matching the instance expression,
// which must belong to the zone's trust domain.
func (s *InstanceSVIDSelector) SelectX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	svids, err := s.client.FetchX509SVIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching x509 svids: %w", err)
	}
	return s.Pick(svids)
}

// Pick returns the single SVID of svids matching the instance expression,
// which must belong to the zone's trust domain.
func (s *InstanceSVIDSelector) Pick(svids []*x509svid.SVID) (*x509svid.SVID, error) {
	var match *x509svid.SVID
	for _, c := range svids {
		env := SVIDEvalEnv{
			SpiffeID: c.ID.String(), TrustDomain: c.ID.TrustDomain().Name(), Path: c.ID.Path(),
			Hint: c.Hint, InstanceName: s.instanceName,
		}
		if len(c.Certificates) > 0 {
			env.SubjectCN = c.Certificates[0].Subject.CommonName
		}
		out, err := expr.Run(s.program, env)
		if err != nil {
			return nil, fmt.Errorf("evaluating selector for %q: %w", s.instanceName, err)
		}
		if ok, _ := out.(bool); ok {
			if match != nil {
				return nil, fmt.Errorf("selector for %q matched more than one SVID", s.instanceName)
			}
			match = c
		}
	}
	if match == nil {
		return nil, fmt.Errorf("selector for %q matched no SVID", s.instanceName)
	}
	if match.ID.TrustDomain().Name() != s.zoneTrustDomain {
		return nil, fmt.Errorf("selector for %q resolved to foreign trust domain", s.instanceName)
	}
	return match, nil
}

// FetchJWT returns a JWT-SVID of the selected subject for the instance's
// audiences (jwt_audience[0], then the others as extra audiences), cached
// until 80% of its lifetime has elapsed (§5.4).
func (s *InstanceSVIDSelector) FetchJWT(ctx context.Context) (string, error) {
	if len(s.audience) == 0 {
		return "", fmt.Errorf("instance %q has no jwt_audience", s.instanceName)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.jwt != "" && now.Before(s.jwtUntil) {
		return s.jwt, nil
	}
	selected, err := s.SelectX509SVID(ctx)
	if err != nil {
		return "", err
	}
	svid, err := s.client.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: s.audience[0], ExtraAudiences: s.audience[1:], Subject: selected.ID,
	})
	if err != nil {
		return "", fmt.Errorf("fetching jwt svid for %q: %w", s.instanceName, err)
	}
	issued := now
	if iat, ok := svid.Claims["iat"].(float64); ok {
		issued = time.Unix(int64(iat), 0)
	}
	s.jwt = svid.Marshal()
	s.jwtUntil = issued.Add(svid.Expiry.Sub(issued) * 8 / 10)
	return s.jwt, nil
}
