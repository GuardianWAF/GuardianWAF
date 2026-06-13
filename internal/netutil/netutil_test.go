package netutil

import "testing"

func TestStripPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"simple", "example.com:8088", "example.com"},
		{"no_port", "example.com", "example.com"},
		{"ipv6_with_port", "[::1]:8088", "[::1]"},
		{"ipv6_no_port", "[::1]", "[::1]"},
		{"ipv6_bracket_only", "[2001:db8::1]:443", "[2001:db8::1]"},
		{"empty", "", ""},
		{"only_port", ":8088", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripPort(tt.host)
			if got != tt.want {
				t.Errorf("StripPort(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
