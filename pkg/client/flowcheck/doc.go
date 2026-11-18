// Package flowcheck checks the network flows of a workload's bindings with
// netcheck, so that a workload or an operator sees which flow a firewall still
// blocks before the application connects (the Developer's Guide, Part 1).
//
// Check runs on demand and never on its own. A TCP flow is a connection test,
// or a TLS handshake when the flow says tls; a UDP flow passes when no ICMP
// error comes back; a CIDR destination or a port range is skipped and reported.
// WithICMP adds an echo check per host and needs the process to be allowed ICMP
// sockets: cap_net_raw on the binary (setcap cap_net_raw=+ep), or a
// net.ipv4.ping_group_range that includes its group.
package flowcheck
