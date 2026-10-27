package textmatch

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// reference is the loop the Set replaces.
func reference(patterns []string, input string) []int {
	var idx []int
	for i, p := range patterns {
		if p != "" && strings.Contains(input, p) {
			idx = append(idx, i)
		}
	}
	return idx
}

func TestFindMatchesContainsLoop(t *testing.T) {
	patterns := []string{"he", "she", "his", "hers", "__class__", "os.popen", "popen(", "", "e", "hers"}
	set := New(patterns)
	for _, in := range []string{"", "ushers", "__class__.__mro__", "x=os.popen(cmd)", "nothing here!", "hhhhshe", "e"} {
		if got, want := set.Find(in), reference(patterns, in); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", in, got, want)
		}
		if got, want := set.Contains(in), len(reference(patterns, in)) > 0; got != want {
			t.Errorf("Contains(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFindRandomizedAgainstReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := "ab_.(c"
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		return string(b)
	}
	for range 2000 {
		patterns := make([]string, 1+r.IntN(8))
		for i := range patterns {
			patterns[i] = word(r.IntN(5))
		}
		set := New(patterns)
		in := word(r.IntN(40))
		if got, want := set.Find(in), reference(patterns, in); !slices.Equal(got, want) {
			t.Fatalf("patterns %q input %q: Find = %v, want %v", patterns, in, got, want)
		}
	}
}

func FuzzFind(f *testing.F) {
	f.Add("__class__,popen(,os.", "x.__class__ popen(1)")
	f.Fuzz(func(t *testing.T, list, input string) {
		patterns := strings.Split(list, ",")
		if len(patterns) > 32 {
			return
		}
		if got, want := New(patterns).Find(input), reference(patterns, input); !slices.Equal(got, want) {
			t.Fatalf("patterns %q input %q: Find = %v, want %v", patterns, input, got, want)
		}
	})
}

func BenchmarkFindVsContains(b *testing.B) {
	patterns := []string{"__class__", "__mro__", "__subclasses__", "__globals__", "os.popen", "subprocess", "popen(", "getruntime().exec", "t(java.lang.runtime", ".getclass().forname("}
	input := strings.Repeat("lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 20000)
	set := New(patterns)
	b.Run("set", func(b *testing.B) {
		b.SetBytes(int64(len(input)))
		for range b.N {
			_ = set.Find(input)
		}
	})
	b.Run("contains", func(b *testing.B) {
		b.SetBytes(int64(len(input)))
		for range b.N {
			_ = reference(patterns, input)
		}
	})
}
