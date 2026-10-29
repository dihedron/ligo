package flows

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrDestinationNotAllowed is returned for a flow outside the platform's
// allowed_endpoints (422 flow-destination-not-allowed).
var ErrDestinationNotAllowed = errors.New("flow-destination-not-allowed")

// Allowlist is a parsed allowed_endpoints list (§5.7).
type Allowlist struct {
	entries []endpoint
}

// endpoint is a host or a network, with an optional port (0: any port).
type endpoint struct {
	host   string // lower case; empty for a network
	prefix netip.Prefix
	port   int
}

// ParseAllowlist parses entries of the forms host, host:port, address,
// [address]:port, address:port and CIDR.
func ParseAllowlist(entries []string) (Allowlist, error) {
	var al Allowlist
	for _, e := range entries {
		ep, err := parseEndpoint(e)
		if err != nil {
			return Allowlist{}, fmt.Errorf("allowed_endpoints entry %q: %w", e, err)
		}
		al.entries = append(al.entries, ep)
	}
	return al, nil
}

func parseEndpoint(e string) (endpoint, error) {
	if p, err := netip.ParsePrefix(e); err == nil {
		return endpoint{prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(e); err == nil {
		return endpoint{prefix: netip.PrefixFrom(a, a.BitLen())}, nil
	}
	host, port := e, 0
	if h, p, err := net.SplitHostPort(e); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return endpoint{}, fmt.Errorf("port %q must be within 1..65535", p)
		}
		host, port = h, n
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return endpoint{prefix: netip.PrefixFrom(a, a.BitLen()), port: port}, nil
	}
	if !validDNSName(host) {
		return endpoint{}, errors.New("not a host, an address or a CIDR")
	}
	return endpoint{host: strings.ToLower(host), port: port}, nil
}

// covers reports whether the endpoint allows destination dest (a prefix if
// isIP, else a DNS name) on every port of p.
func (e endpoint) covers(prefix netip.Prefix, isIP bool, dest string, p Port) bool {
	if isIP {
		if !e.prefix.IsValid() || e.prefix.Addr().Is4() != prefix.Addr().Is4() ||
			e.prefix.Bits() > prefix.Bits() || !e.prefix.Contains(prefix.Addr()) {
			return false
		}
	} else if e.host == "" || !strings.EqualFold(e.host, dest) {
		return false
	}
	return e.port == 0 || (!p.isRange && p.Low == e.port)
}

// CheckFlow checks that the destination of f lies within the allowlist and
// that each of its ports is allowed by an entry for that destination
// (§5.7, INV-24).
func (al Allowlist) CheckFlow(f Flow) error {
	prefix, isIP, err := parseDestination(f.Destination)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDestinationNotAllowed, err)
	}
	for _, p := range f.Ports {
		allowed := false
		for _, e := range al.entries {
			if e.covers(prefix, isIP, f.Destination, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: flow %q to %s port %s", ErrDestinationNotAllowed, f.Name, f.Destination, portString(p))
		}
	}
	return nil
}

// CheckEndpoint checks that host (a DNS name or an address) on port lies
// within the allowlist; port 0 (none given) is allowed only by an entry
// without a port, which allows any (§5.7).
func (al Allowlist) CheckEndpoint(host string, port int) error {
	var prefix netip.Prefix
	a, err := netip.ParseAddr(host)
	isIP := err == nil
	if isIP {
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	for _, e := range al.entries {
		if e.covers(prefix, isIP, host, Port{Low: port}) {
			return nil
		}
	}
	return fmt.Errorf("%w: endpoint %s", ErrDestinationNotAllowed, net.JoinHostPort(host, strconv.Itoa(port)))
}

func portString(p Port) string {
	if !p.isRange {
		return strconv.Itoa(p.Low)
	}
	return fmt.Sprintf("%d-%d", p.Low, p.High)
}
