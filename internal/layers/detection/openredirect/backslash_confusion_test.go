package openredirect

import (
	"net/url"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestBackslash_RelativePathWithBackslash_NotFlagged pins a false positive
// that blocked legitimate traffic. A single leading "\" (or any mid-path "\")
// is a path separator to a browser, resolving to a same-origin path:
// "/settings\profile" -> "/settings/profile", "\evil.com" -> "/evil.com".
// The old branch matched every normalized leading-"/" form, reported path
// segments as "external hosts" (score 65), and Process turned any finding
// into ActionBlock.
func TestBackslash_RelativePathWithBackslash_NotFlagged(t *testing.T) {
	d := NewDetector(true, 1.0)
	for _, target := range []string{
		`/settings\profile`,
		`/uploads\file.txt`,
		`\evil.com`,
		`/search?q=a\b`,
	} {
		ctx := makeCtx("app.example.com", "next="+url.QueryEscape(target), nil)
		result := d.Process(ctx)
		if len(result.Findings) != 0 {
			t.Fatalf("same-origin target %q should not trigger, got %d findings: %+v",
				target, len(result.Findings), result.Findings)
		}
		if result.Action != engine.ActionPass {
			t.Fatalf("same-origin target %q should pass, got %v", target, result.Action)
		}
	}
}

// TestBackslash_AuthorityForms_StillFlagged guards against over-correcting
// the above: the "\"->"/" rewrite is dangerous exactly when it produces an
// authority — a protocol-relative "//host" or a scheme followed by
// backslashes. These must keep triggering and blocking.
func TestBackslash_AuthorityForms_StillFlagged(t *testing.T) {
	d := NewDetector(true, 1.0)
	for _, target := range []string{
		`\\evil.com`,
		`\\evil.com\share`, // value from the fuzz seed corpus
		`/\evil.com`,
		`https:\\evil.com`,
		`http:\\evil.com\steal`,
		`https:\\app.example.com.evil.com\share`, // absolute form, external host
	} {
		ctx := makeCtx("app.example.com", "next="+url.QueryEscape(target), nil)
		result := d.Process(ctx)
		if len(result.Findings) == 0 {
			t.Fatalf("backslash authority payload %q should still trigger", target)
		}
		if result.Action != engine.ActionBlock {
			t.Fatalf("backslash authority payload %q should block, got %v", target, result.Action)
		}
	}
}

// TestBackslash_AbsoluteSameOriginURL_NotFlagged pins the absolute-URL form of
// the same false-positive family. A backslash after an ESTABLISHED same-origin
// authority is a path separator to a browser ("https://app/settings\profile"
// -> "/settings/profile"); the rewrite produces no new authority, so the
// target must pass and the request's own host must never be reported as an
// "external host". Same-origin comparison mirrors the http/https branch:
// case-insensitive exact match or "."+reqHost subdomain suffix.
func TestBackslash_AbsoluteSameOriginURL_NotFlagged(t *testing.T) {
	d := NewDetector(true, 1.0)
	for _, target := range []string{
		`https://app.example.com/settings\profile`,
		`https://app.example.com/search?q=a\b`,
		`http://app.example.com:8080/files\C:\docs`,   // host compared port-stripped
		`https://APP.example.com/settings\profile`,    // case-insensitive host
		`https://cdn.app.example.com/assets\logo.svg`, // subdomain suffix
	} {
		ctx := makeCtx("app.example.com", "next="+url.QueryEscape(target), nil)
		result := d.Process(ctx)
		if len(result.Findings) != 0 {
			t.Fatalf("same-origin absolute target %q should not trigger, got %d findings: %+v",
				target, len(result.Findings), result.Findings)
		}
		if result.Action != engine.ActionPass {
			t.Fatalf("same-origin absolute target %q should pass, got %v", target, result.Action)
		}
	}
}
