package ssrf

import (
	"strings"
)

// IPv4 represents an IPv4 address as a 4-byte slice. A nil value means invalid/not-parsed.
type IPv4 []byte

// ParseIPv4 parses a standard dotted-decimal IPv4 address string.
// Returns nil if the input is not a valid IPv4 address.
func ParseIPv4(s string) IPv4 {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	ip := make(IPv4, 4)
	for i, part := range parts {
		if part == "" {
			return nil
		}
		n, ok := parseDecUint8(part)
		if !ok {
			return nil
		}
		ip[i] = n
	}
	return ip
}

// ParseDecimalIP parses a decimal-encoded IP address (e.g., 2130706433 -> 127.0.0.1).
// Returns nil if the input is not a valid decimal IP.
func ParseDecimalIP(s string) IPv4 {
	if s == "" || len(s) > 10 {
		return nil
	}
	// Must be all digits
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil
		}
	}
	// Parse as uint32
	var n uint64
	for _, c := range s {
		n = n*10 + uint64(c-'0')
		if n > 0xFFFFFFFF {
			return nil
		}
	}
	// Must be large enough to be a real IP (not just a small number)
	if n < 256 {
		return nil
	}
	return IPv4{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
}

// ParseOctalIP parses an octal-encoded IP address (e.g., 0177.0.0.1 -> 127.0.0.1).
// Returns nil if the input does not contain valid octal octets.
func ParseOctalIP(s string) IPv4 {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}

	hasOctal := false
	ip := make(IPv4, 4)
	for i, part := range parts {
		if part == "" {
			return nil
		}
		if strings.HasPrefix(part, "0") && len(part) > 1 && !strings.HasPrefix(part, "0x") {
			// Octal notation
			n, ok := parseOctalUint8(part)
			if !ok {
				return nil
			}
			ip[i] = n
			hasOctal = true
		} else {
			n, ok := parseDecUint8(part)
			if !ok {
				return nil
			}
			ip[i] = n
		}
	}

	if !hasOctal {
		return nil // Not an octal IP, just a regular IP
	}
	return ip
}

// ParseHexIP parses a hex-encoded IP address (e.g., 0x7f.0x0.0x0.0x1 -> 127.0.0.1).
// Returns nil if the input does not contain valid hex octets.
func ParseHexIP(s string) IPv4 {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}

	hasHex := false
	ip := make(IPv4, 4)
	for i, part := range parts {
		if part == "" {
			return nil
		}
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
			n, ok := parseHexUint8(part[2:])
			if !ok {
				return nil
			}
			ip[i] = n
			hasHex = true
		} else {
			n, ok := parseDecUint8(part)
			if !ok {
				return nil
			}
			ip[i] = n
		}
	}

	if !hasHex {
		return nil // Not a hex IP
	}
	return ip
}

// IsPrivateIP returns true if the IP is in a private range:
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
func IsPrivateIP(ip IPv4) bool {
	if len(ip) != 4 {
		return false
	}
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}
	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	return false
}

// IsLoopback returns true if the IP is in the loopback range (127.0.0.0/8).
func IsLoopback(ip IPv4) bool {
	if len(ip) != 4 {
		return false
	}
	return ip[0] == 127
}

// IsLinkLocal returns true if the IP is in the link-local range (169.254.0.0/16).
func IsLinkLocal(ip IPv4) bool {
	if len(ip) != 4 {
		return false
	}
	return ip[0] == 169 && ip[1] == 254
}

// IsMetadataEndpoint returns true if the IP matches a known cloud metadata endpoint.
func IsMetadataEndpoint(ip IPv4) bool {
	if len(ip) != 4 {
		return false
	}
	// AWS/GCP: 169.254.169.254
	if ip[0] == 169 && ip[1] == 254 && ip[2] == 169 && ip[3] == 254 {
		return true
	}
	// Alibaba: 100.100.100.200
	if ip[0] == 100 && ip[1] == 100 && ip[2] == 100 && ip[3] == 200 {
		return true
	}
	return false
}

// parseDecUint8 parses a decimal string as a uint8 (0-255).
func parseDecUint8(s string) (byte, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}

// parseOctalUint8 parses an octal string (with leading 0) as a uint8.
func parseOctalUint8(s string) (byte, bool) {
	if s == "" {
		return 0, false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false
		}
		n = n*8 + int(c-'0')
	}
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}

// parseHexUint8 parses a hex string (without 0x prefix) as a uint8.
func parseHexUint8(s string) (byte, bool) {
	if s == "" || len(s) > 2 {
		return 0, false
	}
	var n int
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return byte(n), true
}

// parseFlexibleUint parses a number string in decimal, octal (0 prefix), or hex (0x prefix).
// Returns the parsed value and true, or 0 and false if invalid.
func parseFlexibleUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr := s[2:]
		if hexStr == "" {
			return 0, false
		}
		var n uint64
		for _, c := range hexStr {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n += uint64(c - '0')
			case c >= 'a' && c <= 'f':
				n += uint64(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n += uint64(c-'A') + 10
			default:
				return 0, false
			}
		}
		return n, true
	}
	if strings.HasPrefix(s, "0") && len(s) > 1 {
		// Octal
		var n uint64
		for _, c := range s {
			if c < '0' || c > '7' {
				return 0, false
			}
			n = n*8 + uint64(c-'0')
		}
		return n, true
	}
	// Decimal
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

// ParseAbbreviatedIP parses abbreviated IP forms (2 or 3 dot-separated parts).
// Follows POSIX inet_aton rules:
//   - A.B   → A.0.0.B  (A is 8-bit, B is 24-bit host)
//   - A.B.C → A.B.0.C  (A,B are 8-bit, C is 16-bit host)
//
// Each part can be decimal, octal (0 prefix), or hex (0x prefix).
// Returns nil if the input is not a valid abbreviated IP.
func ParseAbbreviatedIP(s string) IPv4 {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil
	}

	parsed := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		n, ok := parseFlexibleUint(part)
		if !ok {
			return nil
		}
		parsed[i] = n
	}

	switch len(parts) {
	case 2:
		// A.B → A is first octet (8-bit), B is 24-bit host
		if parsed[0] > 255 || parsed[1] > 0xFFFFFF {
			return nil
		}
		return IPv4{
			byte(parsed[0]),
			byte(parsed[1] >> 16),
			byte(parsed[1] >> 8),
			byte(parsed[1]),
		}
	case 3:
		// A.B.C → A is first (8-bit), B is second (8-bit), C is 16-bit host
		if parsed[0] > 255 || parsed[1] > 255 || parsed[2] > 0xFFFF {
			return nil
		}
		return IPv4{
			byte(parsed[0]),
			byte(parsed[1]),
			byte(parsed[2] >> 8),
			byte(parsed[2]),
		}
	}
	return nil
}

// ParseHexSingleIP parses a single hex number as an IP address (e.g., 0x7f000001 → 127.0.0.1).
// Returns nil if the input is not a valid hex-encoded IP.
func ParseHexSingleIP(s string) IPv4 {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil
	}
	hexStr := s[2:]
	if hexStr == "" || len(hexStr) > 8 {
		return nil
	}
	var n uint64
	for _, c := range hexStr {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += uint64(c-'A') + 10
		default:
			return nil
		}
	}
	if n > 0xFFFFFFFF {
		return nil
	}
	return IPv4{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
}
