// Package netutil provides shared network utility helpers.
package netutil

import "strings"

// StripPort removes the port suffix from a host string, handling IPv6 brackets.
// Examples:
//
//	"example.com:8088"     → "example.com"
//	"[::1]:8088"           → "[::1]"
//	"example.com"          → "example.com"
//	"[::1]"                → "[::1]"
func StripPort(host string) string {
	if strings.Contains(host, "]") {
		// IPv6: [::1]:8088
		bracket := strings.LastIndex(host, "]")
		if idx := strings.LastIndex(host, ":"); idx > bracket {
			return host[:idx]
		}
		return host
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}
