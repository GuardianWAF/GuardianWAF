package config

import "testing"

func TestFindVirtualHostExactMatchPrecedesWildcard(t *testing.T) {
	for _, host := range []string{"app.example.test", "app.example.test:8080"} {
		for _, exactFirst := range []bool{true, false} {
			exact := VirtualHostConfig{Domains: []string{"other.example.test", "app.example.test"}}
			wildcard := VirtualHostConfig{Domains: []string{"*.example.test"}}
			vhosts := []VirtualHostConfig{wildcard, exact}
			expected := 1
			if exactFirst {
				vhosts = []VirtualHostConfig{exact, wildcard}
				expected = 0
			}
			if got := FindVirtualHost(vhosts, host); got != &vhosts[expected] {
				t.Fatalf("host=%q exactFirst=%v selected=%v", host, exactFirst, got)
			}
		}
	}
	vhosts := []VirtualHostConfig{
		{Domains: []string{"*.example.test"}},
		{Domains: []string{"*.sub.example.test"}},
	}
	if got := FindVirtualHost(vhosts, "app.sub.example.test"); got != &vhosts[0] {
		t.Fatal("wildcard fallback order changed")
	}
	for _, host := range []string{"", "example.test", "other.test"} {
		if got := FindVirtualHost(vhosts, host); got != nil {
			t.Fatalf("unexpected match for %q: %v", host, got)
		}
	}
	if got := FindVirtualHost(nil, "app.example.test"); got != nil {
		t.Fatal("nil virtual host list matched")
	}
}
