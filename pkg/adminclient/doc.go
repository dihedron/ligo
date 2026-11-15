// Package adminclient is the Go client of ligo's admin API
// (.specs/ligo-adminclient.md): the one client that the ligo CLI, the
// Terraform provider and the MCP server share, so that authentication,
// server verification, the mapping of errors and the rules of change
// requests are written and tested once.
//
// The package verifies the server (by a CA pool, or by its SPIFFE ID against
// a bundle: there is no option to skip it), authenticates with an SVID or
// with LDAP credentials, never follows a redirect, reads no more than 8 MiB
// of a response, and never logs or prints a password. It keeps no cache,
// reads no file, and starts no goroutine; the only environment it honours is the
// standard proxy variables, through net/http.
//
// Every mutation of the admin API files a change request; the methods that
// change something return it and never claim the resource has changed.
package adminclient
