package ato

// FuzzAtoProcess exercises the ATO layer's Process against hostile login
// bodies and request shapes. The layer must never panic and must always
// return a valid engine action with a non-negative score. This drives the
// hand-rolled body extractors (JSON + form, QueryUnescape fallbacks, email
// regex gating) and all four detection checks (brute force, credential
// stuffing, password spray, impossible travel) with a shared long-lived
// tracker so detection state accumulates across execs like production.

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func FuzzAtoProcess(f *testing.F) {
	seeds := []struct{ body, ip string }{
		{`{"email":"user@example.com","password":"pw"}`, "192.0.2.1"},
		{`email=user%40example.com&password=pw`, "192.0.2.2"},
		{`username=admin&pass=secret`, "198.51.100.3"},
		{`login=x@y.z`, "203.0.113.4"},
		{`{"username":"u@x.y"}`, "192.0.2.5"},
		{`email=%zz@bad-escape`, "192.0.2.6"},
		{``, "192.0.2.7"},
		{`password=only`, "192.0.2.8"},
		{`{"email":"a@b.c","pass":"p","extra":{"nested":[1,2]}}`, "198.51.100.9"},
	}
	cfg := &Config{
		Enabled:       true,
		LoginPaths:    []string{"/login"},
		BruteForce:    BruteForceConfig{Enabled: true, Window: time.Minute, MaxAttemptsPerIP: 100000, MaxAttemptsPerEmail: 100000, BlockDuration: time.Minute},
		CredStuffing:  CredentialStuffingConfig{Enabled: true, DistributedThreshold: 100000, Window: time.Hour, BlockDuration: time.Minute},
		PasswordSpray: PasswordSprayConfig{Enabled: true, Threshold: 100000, Window: time.Minute, BlockDuration: time.Minute},
		Travel:        ImpossibleTravelConfig{Enabled: true, MaxDistanceKm: 500, MaxTimeHours: 1, BlockDuration: time.Minute},
	}
	// Shared long-lived layer: tracker/travel state accumulates across execs
	// (bounded by the round-4 cap eviction), mirroring production lifetime.
	layer, err := NewLayer(cfg)
	if err != nil {
		f.Fatalf("NewLayer: %v", err)
	}

	f.Add(seeds[0].body, seeds[0].ip)
	for _, s := range seeds[1:] {
		f.Add(s.body, s.ip)
	}

	f.Fuzz(func(t *testing.T, body, ipStr string) {
		if len(body) > 2048 || len(ipStr) > 64 {
			return
		}
		ctx := &engine.RequestContext{
			Path:        "/login",
			Method:      "POST",
			ClientIP:    net.ParseIP(ipStr),
			BodyString:  body,
			Headers:     map[string][]string{},
			Accumulator: engine.NewScoreAccumulator(2),
		}

		res := layer.Process(ctx)

		switch res.Action {
		case engine.ActionPass, engine.ActionLog, engine.ActionChallenge, engine.ActionBlock:
		default:
			t.Fatalf("FAIL: invalid action %v", res.Action)
		}
		if res.Score < 0 {
			t.Fatalf("FAIL: negative score %d", res.Score)
		}
	})
}
