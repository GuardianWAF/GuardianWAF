package sanitizer

import (
	"strings"
	"testing"
)

// BenchmarkNormalizeAllLarge records the cost of the normalizer on large
// inputs. It exists because that cost is a capacity/DoS consideration, not a
// micro-optimisation: NormalizeAll runs several allocating passes, so its
// memory use is a large multiple of the input, and it runs BEFORE
// ValidateRequest checks max_body_size.
//
// Reference numbers (AMD Ryzen 7 PRO 6850H, Go 1.26.5):
//
//	1MB slashes   12.3 ms   17.8 MB/op
//	1MB dots       7.1 ms    9.4 MB/op
//	1MB percent    3.5 ms    2.1 MB/op
//	1MB plain      4.1 ms    2.1 MB/op
//
// The engine reads bodies up to waf.max_body_size (10 MiB default), so the
// worst case is roughly 123 ms and 178 MB of allocation per request. Run this
// before and after any change to the normalizer's pass structure.
func BenchmarkNormalizeAllLarge(b *testing.B) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"1MB slashes", strings.Repeat("/", 1<<20)},
		{"1MB dots", strings.Repeat("./", 1<<19)},
		{"1MB percent", strings.Repeat("%25", (1<<20)/3)},
		{"1MB plain", strings.Repeat("a", 1<<20)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = NormalizeAll(tc.in)
			}
		})
	}
}
