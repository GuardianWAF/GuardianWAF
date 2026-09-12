package main

import (
	"log/slog"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const (
	periodicCleanupInterval = 5 * time.Minute
	cleanupMaxAge           = 30 * time.Minute
)

type staleCleaner interface {
	CleanupExpired(time.Duration)
}

type expiryCleaner interface {
	CleanupExpired()
}

type simpleCleaner interface {
	Cleanup()
}

type tenantRateLimiterCleaner interface {
	CleanupRateLimiter(maxAge time.Duration)
}

func startPeriodicCleanup(eng *engine.Engine, tenantManager any, interval time.Duration) (chan struct{}, *sync.WaitGroup) {
	if interval <= 0 {
		interval = periodicCleanupInterval
	}

	cleanupStop := make(chan struct{})
	cleanupWG := &sync.WaitGroup{}
	cleanupWG.Add(1)
	go func() {
		defer cleanupWG.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Recovery is per-tick, not per-goroutine: a panic in any
				// layer's cleanup implementation must cost one interval, not
				// the janitor's lifetime (same restart rationale as the
				// analyzer/watcher/event-consumer loops; the ticker bounds
				// the retry rate, so no backoff is needed).
				runCleanupTick(eng, tenantManager)
			case <-cleanupStop:
				return
			}
		}
	}()

	return cleanupStop, cleanupWG
}

// runCleanupTick runs one janitor sweep with panic isolation so the
// periodic-cleanup goroutine survives a panicking Cleanup implementation.
func runCleanupTick(eng *engine.Engine, tenantManager any) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("periodic cleanup panic recovered",
				"panic", r,
				"stack", string(debug.Stack()))
		}
	}()
	runPeriodicCleanup(eng, tenantManager)
}

func runPeriodicCleanup(eng *engine.Engine, tenantManager any) {
	if eng == nil {
		return
	}
	if rl := eng.FindLayer("ratelimit"); rl != nil {
		if c, ok := rl.(staleCleaner); ok {
			c.CleanupExpired(cleanupMaxAge)
		}
	}
	if acl := eng.FindLayer("ipacl"); acl != nil {
		if c, ok := acl.(expiryCleaner); ok {
			c.CleanupExpired()
		}
	}
	if atoL := eng.FindLayer("ato_protection"); atoL != nil {
		if c, ok := atoL.(simpleCleaner); ok {
			c.Cleanup()
		}
	}
	if bot := eng.FindLayer("botdetect"); bot != nil {
		if c, ok := bot.(simpleCleaner); ok {
			c.Cleanup()
		}
	}
	if tenantManager != nil && !isNilInterfaceValue(tenantManager) {
		if c, ok := tenantManager.(tenantRateLimiterCleaner); ok {
			c.CleanupRateLimiter(cleanupMaxAge)
		}
	}
	eng.Logs.Debug("Periodic cleanup completed")
}

// isNilInterfaceValue reports whether v, stored in an interface{}, is
// a typed nil pointer / chan / func / map / slice / interface.
// `v != nil` is false only for an untyped nil interface, not for a
// typed nil — without this check, a typed-nil tenant manager
// (e.g. `var x *T; pass x` through `any`) reaches the type assertion
// and a subsequent method call panics with a nil-pointer deref.
func isNilInterfaceValue(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
