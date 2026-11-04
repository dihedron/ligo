package main

import "testing"

// TestLiteralID: only a regex that matches one SPIFFE ID gives a subject a
// JWT role can bind.
func TestLiteralID(t *testing.T) {
	for regex, want := range map[string]string{
		`^spiffe://prod\.lab/ns/echo/sa/bound$`:    "spiffe://prod.lab/ns/echo/sa/bound",
		`^spiffe://prod\.lab/ns/e2e/sa/w0a1b-c_d$`: "spiffe://prod.lab/ns/e2e/sa/w0a1b-c_d",
		`^spiffe://prod\.lab/ns/echo/sa/[a-z]+$`:   "",
		`^spiffe://prod.lab/ns/echo/sa/bound$`:     "", // an unescaped dot matches any character
		`spiffe://prod\.lab/ns/echo/sa/bound`:      "", // not anchored
		`spiffe://prod\.lab/ns/echo/sa/bound$`:     "", // no ^
		`^spiffe://prod\.lab/ns/echo/sa/bound|x$`:  "",
		`^spiffe://prod\.lab/ns/echo/sa/(bound)$`:  "",
		`^https://prod\.lab/x$`:                    "",
		`^spiffe://Prod\.lab/ns/echo/sa/bound$`:    "", // not a valid trust domain
		``:                                         "",
	} {
		got, ok := literalID(regex)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", regex, got, ok, want)
		}
	}
}
