package main

import "testing"

func TestIsLoopbackListen(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9443":  true,
		"127.0.0.2:9443":  true,
		"[::1]:9443":      true,
		"localhost:9443":  true,
		":9443":           false, // every interface
		"0.0.0.0:9443":    false,
		"[::]:9443":       false,
		"10.0.0.5:9443":   false,
		"example.com:443": false,
		"not-an-address":  false,
	} {
		if got := isLoopbackListen(addr); got != want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", addr, got, want)
		}
	}
}
