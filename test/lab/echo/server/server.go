// Command echo-server is the lab's echo target (lab only, not hardened;
// .specs/ligo-test-environment.md, "The echo target on ligo1"): it echoes a
// line of text with the client's identity to the clients its access list
// or its users admit, and target-echo keeps those lists through its
// control API.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// The modes: SPIFFE IDs on the access list, or users with a password.
const (
	ModeSVID     = "svid"
	ModePassword = "password"
)

var (
	idRE   = regexp.MustCompile(`^[0-9a-f-]{36}$`)                  // a binding ID
	userRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,62}$`) // a derived principal name
)

// state is what the control API changes, kept in a file.
type state struct {
	ACL   map[string]string `json:"acl"`   // binding ID: source SVID regex
	Users map[string]string `json:"users"` // user: SHA-256 of the password, hex
}

// Server is one echo server, in one mode.
type Server struct {
	Mode        string
	TrustDomain spiffeid.TrustDomain // of the clients
	ControlID   spiffeid.ID          // target-echo's SPIFFE ID, the only control client
	StatePath   string
	SVIDs       x509svid.Source
	Bundles     x509bundle.Source
	Log         *slog.Logger

	mu    sync.RWMutex
	st    state
	rules map[string]*regexp.Regexp
}

// load reads the state file; a missing file is an empty state.
func (s *Server) load() error {
	s.st = state{ACL: map[string]string{}, Users: map[string]string{}}
	s.rules = map[string]*regexp.Regexp{}
	data, err := os.ReadFile(s.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.st); err != nil {
		return fmt.Errorf("%s: %w", s.StatePath, err)
	}
	if s.st.ACL == nil {
		s.st.ACL = map[string]string{}
	}
	if s.st.Users == nil {
		s.st.Users = map[string]string{}
	}
	for id, re := range s.st.ACL {
		r, err := regexp.Compile(re)
		if err != nil {
			return fmt.Errorf("%s: binding %s: %w", s.StatePath, id, err)
		}
		s.rules[id] = r
	}
	return nil
}

// save writes the state file atomically; s.mu is held.
func (s *Server) save() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.StatePath), ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.StatePath)
}

func hash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// admitted reports whether a SPIFFE ID fully matches a regex of the list.
func (s *Server) admitted(id spiffeid.ID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if loc := r.FindStringIndex(id.String()); loc != nil && loc[0] == 0 && loc[1] == len(id.String()) {
			return true
		}
	}
	return false
}

// valid reports whether user exists with password.
func (s *Server) valid(user, password string) bool {
	s.mu.RLock()
	want, ok := s.st.Users[user]
	s.mu.RUnlock()
	return ok && subtle.ConstantTimeCompare([]byte(want), []byte(hash(password))) == 1
}

// dataTLS is the data port's TLS: the server's SVID; in the svid mode a
// client SVID of the trust domain is required, in the password mode it is
// optional and, when given, verified the same way.
func (s *Server) dataTLS() *tls.Config {
	member := tlsconfig.AuthorizeMemberOf(s.TrustDomain)
	if s.Mode == ModeSVID {
		return tlsconfig.MTLSServerConfig(s.SVIDs, s.Bundles, member)
	}
	c := tlsconfig.TLSServerConfig(s.SVIDs)
	c.ClientAuth = tls.RequestClientCert
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		id, _, err := x509svid.Verify(cs.PeerCertificates, s.Bundles)
		if err != nil {
			return err
		}
		return member(id, nil)
	}
	return c
}

// peer is the verified client SPIFFE ID of a connection, if any.
func peer(cs tls.ConnectionState) (spiffeid.ID, bool) {
	if len(cs.PeerCertificates) == 0 {
		return spiffeid.ID{}, false
	}
	id, err := x509svid.IDFromCert(cs.PeerCertificates[0])
	return id, err == nil
}

// handle serves one data connection: in the password mode an auth line
// first, then one line echoed with the client's identity, or "denied".
func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	tc := conn.(*tls.Conn)
	if err := tc.Handshake(); err != nil {
		s.Log.Info("handshake refused", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	in := bufio.NewScanner(conn)
	in.Buffer(make([]byte, 4096), 4096)
	id, hasID := peer(tc.ConnectionState())
	var identity string
	switch s.Mode {
	case ModeSVID:
		if !hasID || !s.admitted(id) {
			s.refuse(conn, "no access list entry matches "+id.String())
			return
		}
		identity = id.String()
	case ModePassword:
		if !in.Scan() {
			return
		}
		f := strings.Fields(in.Text())
		if len(f) != 3 || f[0] != "auth" || !s.valid(f[1], f[2]) {
			s.refuse(conn, "bad credentials")
			return
		}
		identity = f[1]
		if hasID {
			identity += " " + id.String()
		}
	}
	if !in.Scan() {
		return
	}
	_, _ = fmt.Fprintf(conn, "%s\t%s\n", in.Text(), identity)
	s.Log.Info("echoed", "identity", identity)
}

func (s *Server) refuse(conn net.Conn, why string) {
	_, _ = fmt.Fprintln(conn, "denied")
	s.Log.Info("denied", "remote", conn.RemoteAddr().String(), "reason", why)
}

// Serve accepts data connections on l until ctx ends.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	tl := tls.NewListener(l, s.dataTLS())
	go func() { <-ctx.Done(); _ = tl.Close() }()
	for {
		conn, err := tl.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Control is the control API, for target-echo only (mTLS, AuthorizeID).
func (s *Server) Control() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /acl/{id}", s.putACL)
	mux.HandleFunc("DELETE /acl/{id}", s.deleteACL)
	mux.HandleFunc("PUT /users/{name}", s.putUser)
	mux.HandleFunc("DELETE /users/{name}", s.deleteUser)
	return &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: tlsconfig.MTLSServerConfig(s.SVIDs, s.Bundles, tlsconfig.AuthorizeID(s.ControlID))}
}

func (s *Server) change(w http.ResponseWriter, f func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := f(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := s.save(); err != nil {
		s.Log.Error("save the state", "error", err)
		http.Error(w, "cannot save the state", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Regex string `json:"regex"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body)
	s.change(w, func() error {
		if err != nil || !idRE.MatchString(id) {
			return errors.New("a binding ID and {\"regex\"} are required")
		}
		re, err := regexp.Compile(body.Regex)
		if err != nil {
			return err
		}
		s.st.ACL[id], s.rules[id] = body.Regex, re
		s.Log.Info("access list entry set", "binding", id, "regex", body.Regex)
		return nil
	})
}

func (s *Server) deleteACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.change(w, func() error {
		delete(s.st.ACL, id)
		delete(s.rules, id)
		s.Log.Info("access list entry removed", "binding", id)
		return nil
	})
}

func (s *Server) putUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Password string `json:"password"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body)
	s.change(w, func() error {
		if err != nil || !userRE.MatchString(name) || body.Password == "" {
			return errors.New("a user name and {\"password\"} are required")
		}
		s.st.Users[name] = hash(body.Password)
		s.Log.Info("user set", "user", name)
		return nil
	})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.change(w, func() error {
		delete(s.st.Users, name)
		s.Log.Info("user removed", "user", name)
		return nil
	})
}
