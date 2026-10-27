package proxy

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestBalancerOwnsTargetMembership(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyWeighted, StrategyLeastConn, StrategyIPHash} {
		t.Run(strategy, func(t *testing.T) {
			first, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := NewTargetWithPolicy("http://192.0.2.2", 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			input := make([]*Target, 1, 3)
			input[0] = first
			b := NewBalancer(input, strategy)
			release, done := make(chan struct{}), make(chan struct{})
			go func() { <-release; input[0] = second; input = append(input, second); close(done) }()
			close(release)
			<-done
			for range 3 {
				if b.Next(httptest.NewRequest("GET", "/", nil)) != first || b.Len() != 1 {
					t.Fatal("caller mutation changed membership")
				}
			}
			got := b.Targets()
			got[0] = nil
			if b.Targets()[0] != first {
				t.Fatal("output mutation changed membership")
			}
			first.SetHealthy(false)
			if b.Next(httptest.NewRequest("GET", "/", nil)) != nil {
				t.Fatal("target object identity was not retained")
			}
		})
	}
	for _, input := range [][]*Target{nil, {}} {
		b := NewBalancer(input, "")
		if b.Len() != 0 || b.Next(httptest.NewRequest("GET", "/", nil)) != nil {
			t.Fatal(fmt.Sprint("empty membership:", input))
		}
	}
}
