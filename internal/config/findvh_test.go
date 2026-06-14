package config

import "testing"

func TestFindVirtualHost_ExactMatch(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"example.com", "www.example.com"}},
		{Domains: []string{"api.example.com"}},
	}

	tests := []struct {
		host     string
		expected int // index of expected vhost, -1 for nil
	}{
		{"example.com", 0},
		{"www.example.com", 0},
		{"api.example.com", 1},
		{"other.com", -1},
		{"", -1},
	}

	for _, tt := range tests {
		result := FindVirtualHost(vhosts, tt.host)
		if tt.expected == -1 {
			if result != nil {
				t.Errorf("FindVirtualHost(%q) = %v, want nil", tt.host, result)
			}
		} else {
			if result == nil {
				t.Errorf("FindVirtualHost(%q) = nil, want vhost %d", tt.host, tt.expected)
			} else if result.Domains[0] != vhosts[tt.expected].Domains[0] {
				t.Errorf("FindVirtualHost(%q) = %v, want %v", tt.host, result.Domains, vhosts[tt.expected].Domains)
			}
		}
	}
}

func TestFindVirtualHost_WildcardMatch(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"*.example.com"}},
		{Domains: []string{"*.api.example.com"}},
	}

	tests := []struct {
		host     string
		expected int // index of expected vhost, -1 for nil
	}{
		{"www.example.com", 0},
		{"api.example.com", 0},
		{"sub.api.example.com", 0},
		{"deep.sub.api.example.com", 0},
		{"example.com", -1}, // exact match should not match wildcard
		{"notexample.com", -1},
		{"other.com", -1},
		{"", -1},
	}

	for _, tt := range tests {
		result := FindVirtualHost(vhosts, tt.host)
		if tt.expected == -1 {
			if result != nil {
				t.Errorf("FindVirtualHost(%q) = %v, want nil", tt.host, result)
			}
		} else {
			if result == nil {
				t.Errorf("FindVirtualHost(%q) = nil, want vhost %d", tt.host, tt.expected)
			}
		}
	}
}

func TestFindVirtualHost_WithPort(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"example.com"}},
	}

	result := FindVirtualHost(vhosts, "example.com:8080")
	if result == nil {
		t.Error("FindVirtualHost with port should strip port and find vhost")
	}

	result = FindVirtualHost(vhosts, "example.com")
	if result == nil {
		t.Error("FindVirtualHost without port should find vhost")
	}
}

func TestFindVirtualHost_EmptyAndNil(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"example.com"}},
	}

	if FindVirtualHost(nil, "example.com") != nil {
		t.Error("FindVirtualHost with nil vhosts should return nil")
	}

	if FindVirtualHost(vhosts, "") != nil {
		t.Error("FindVirtualHost with empty host should return nil")
	}

	if FindVirtualHost(nil, "") != nil {
		t.Error("FindVirtualHost with nil vhosts and empty host should return nil")
	}
}
