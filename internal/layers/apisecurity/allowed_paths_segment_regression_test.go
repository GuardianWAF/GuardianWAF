package apisecurity

import (
	"testing"
)

// Regression (round 2026-09-18): matchPath's "/*/" branch is documented as a
// "Single segment wildcard" but anchored only the leading side
// (HasPrefix parts[0]+"/") and tested the trailing side with an UNANCHORED
// HasSuffix(path, parts[1]). For a key scoped AllowedPaths: ["/api/*/users"]:
//
//	"/api/admin/reset_users" matched (ends with "users")   -> authorized
//	"/api/v1/admin/users"    matched (multi-segment middle) -> authorized
//	"/api//users"            matched (empty segment)        -> authorized
//
// expanding the key's allowed-path scope far beyond the documented single
// segment — a fail-open authz defect on Validate/ValidateConstantTime (both
// gate AllowedPaths via matchAnyPath and return ErrUnauthorizedPath on
// no-match). The wildcard now stands for exactly one non-empty segment.

func TestMatchPathSingleSegmentAnchored(t *testing.T) {
	// Single-segment matches must keep working.
	if !matchPath("/api/*/users", "/api/v1/users") {
		t.Fatalf("/api/*/users did not match /api/v1/users")
	}
	if !matchPath("/api/*/users/extra", "/api/v1/users/extra") {
		t.Fatalf("/api/*/users/extra did not match /api/v1/users/extra")
	}
	if !matchPath("/*/users", "/x/users") {
		t.Fatalf("/*/users did not match /x/users")
	}

	// Over-matches: unanchored suffix, multi-segment middle, empty segment.
	for _, path := range []string{
		"/api/admin/reset_users", // ends with "users" but not "/users"
		"/api/v1/admin/users",    // multi-segment middle
		"/api//users",            // empty segment
		"/api/users",             // no wildcard segment at all
	} {
		if matchPath("/api/*/users", path) {
			t.Fatalf("/api/*/users must not match %q — scope expanded beyond one segment", path)
		}
	}

	// Non-matching sibling paths stay non-matching.
	if matchPath("/api/*/users", "/api/v1/items") {
		t.Fatalf("/api/*/users matched /api/v1/items")
	}
}

// End-to-end through the production Validate path: a key scoped to
// /api/*/users must be denied on an over-match path and authorized on the
// single-segment path.
func TestValidateAllowedPathsScopeAnchored(t *testing.T) {
	v, err := NewAPIKeyValidator([]APIKeyConfig{
		{
			Name:         "scoped-key",
			KeyHash:      "probe-secret-key",
			Enabled:      true,
			AllowedPaths: []string{"/api/*/users"},
		},
	})
	if err != nil {
		t.Fatalf("NewAPIKeyValidator: %v", err)
	}

	if _, verr := v.Validate("probe-secret-key", "/api/admin/reset_users"); verr == nil {
		t.Fatalf("Validate authorized /api/admin/reset_users for a key scoped to /api/*/users")
	}
	if cfg, verr := v.Validate("probe-secret-key", "/api/v1/users"); verr != nil {
		t.Fatalf("Validate denied /api/v1/users: %v", verr)
	} else if cfg.Name != "scoped-key" {
		t.Fatalf("unexpected key config: %q", cfg.Name)
	}
}
