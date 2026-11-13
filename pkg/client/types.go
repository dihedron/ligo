package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Errors a caller can test with errors.Is.
var (
	// ErrUnauthorized: ligo refused the caller, or the server is not ligo.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrUnavailable: ligo cannot resolve bindings now, or cannot be reached. Retry later.
	ErrUnavailable = errors.New("unavailable")
)

// Filter narrows a request; an empty field does not filter.
type Filter struct {
	Target           string
	PlatformType     string // ignored by Flows
	WatchCredentials bool   // Watch only: read each binding's credential too
}

// Binding is one binding of the calling workload.
type Binding struct {
	ID, Name, Source, Target string
	AccessLevel              string
	PlatformType, Platform   string
	Revision                 int64
	UpdatedAt                time.Time
	Spec                     map[string]any // differs per platform type
	Auth                     Auth
}

// Endpoint is the spec's "endpoint", or "" when the platform type has none.
func (b Binding) Endpoint() string {
	s, _ := b.Spec["endpoint"].(string)
	return s
}

// Auth says where the binding's credential is kept.
type Auth struct {
	Strategy      string // "vault-static", "vault-dynamic", or "" when there is no secret store
	StoreType     string
	StoreInstance string
	Config        map[string]string // what the store's plugin finalized: address, audience, authMount, role, secretPath or credsPath
}

// BindingFlows are the network flows a binding needs.
type BindingFlows struct {
	Binding, Source, Target string
	Flows                   []Flow
}

// Flow is one network flow.
type Flow struct {
	Name, Purpose, Protocol, Destination string
	Ports                                []PortRange
	TLS                                  bool
	ServerName, Description, DeclaredBy  string
}

// PortRange is inclusive; a single port has Low == High.
type PortRange struct{ Low, High int }

// UnmarshalJSON reads a port as ligo writes it: a number, or "low-high".
func (p *PortRange) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		p.Low, p.High = n, n
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("port %s: a number or \"low-high\"", data)
	}
	low, high, ok := strings.Cut(s, "-")
	l, err1 := strconv.Atoi(low)
	h, err2 := strconv.Atoi(high)
	if !ok || err1 != nil || err2 != nil {
		return fmt.Errorf("port %q: a number or \"low-high\"", s)
	}
	p.Low, p.High = l, h
	return nil
}

// wireBinding is an item of GET /v1/bindings.
type wireBinding struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Source       string         `json:"source"`
	Target       string         `json:"target"`
	AccessLevel  string         `json:"accessLevel"`
	PlatformType string         `json:"platformType"`
	Platform     string         `json:"platform"`
	Revision     int64          `json:"revision"`
	Auth         wireAuth       `json:"auth"`
	Spec         map[string]any `json:"spec"`
	UpdatedAt    time.Time      `json:"updatedAt"`
}

type wireAuth struct {
	Strategy      string         `json:"secretStorageStrategy"`
	StoreType     string         `json:"secretStoreType"`
	StoreInstance string         `json:"secretStoreInstance"`
	Config        map[string]any `json:"config"`
}

func (w wireBinding) binding() Binding {
	cfg := make(map[string]string, len(w.Auth.Config))
	for k, v := range w.Auth.Config {
		if s, ok := v.(string); ok {
			cfg[k] = s
		} else {
			cfg[k] = fmt.Sprint(v) // the shipped store plugins write strings only
		}
	}
	return Binding{ID: w.ID, Name: w.Name, Source: w.Source, Target: w.Target, AccessLevel: w.AccessLevel,
		PlatformType: w.PlatformType, Platform: w.Platform, Revision: w.Revision, UpdatedAt: w.UpdatedAt, Spec: w.Spec,
		Auth: Auth{Strategy: w.Auth.Strategy, StoreType: w.Auth.StoreType, StoreInstance: w.Auth.StoreInstance, Config: cfg}}
}

// wireFlows is an item of GET /v1/flows.
type wireFlows struct {
	Binding string `json:"binding"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	Flows   []struct {
		Name        string      `json:"name"`
		Purpose     string      `json:"purpose"`
		Protocol    string      `json:"protocol"`
		Destination string      `json:"destination"`
		Ports       []PortRange `json:"ports"`
		TLS         bool        `json:"tls"`
		ServerName  string      `json:"serverName"`
		Description string      `json:"description"`
		DeclaredBy  string      `json:"declaredBy"`
	} `json:"flows"`
}

func (w wireFlows) flows() BindingFlows {
	out := BindingFlows{Binding: w.Binding, Source: w.Source, Target: w.Target, Flows: make([]Flow, len(w.Flows))}
	for i, f := range w.Flows {
		out.Flows[i] = Flow{Name: f.Name, Purpose: f.Purpose, Protocol: f.Protocol, Destination: f.Destination, Ports: f.Ports,
			TLS: f.TLS, ServerName: f.ServerName, Description: f.Description, DeclaredBy: f.DeclaredBy}
	}
	return out
}
