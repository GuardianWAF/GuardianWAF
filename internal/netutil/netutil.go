// Package netutil provides shared network utility helpers.
package netutil

import (
	"net"
	"strings"
)

// StripPort removes the port suffix from a host string, handling IPv6 brackets.
// Examples:
//
//	"example.com:8088"     → "example.com"
//	"[::1]:8088"           → "[::1]"
//	"example.com"          → "example.com"
//	"[::1]"                → "[::1]"
//	"::1"                  → "::1" (bare IPv6 has no port)
//
// Hosts that are not in host:port form are returned unchanged — the previous
// implementation chopped every unbracketed host at its last colon, mangling
// bare IPv6 literals ("::1" → ":").
func StripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if strings.Contains(host, "]") {
		return "[" + h + "]"
	}
	return h
}
