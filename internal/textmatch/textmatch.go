// Package textmatch finds which of a fixed set of byte patterns occur in an
// input, in one pass (Aho-Corasick). Detectors used to call strings.Contains
// once per pattern, which reads a large body dozens of times.
package textmatch

// Set is an immutable Aho-Corasick automaton over a list of patterns. It is
// safe for concurrent use.
type Set struct {
	patterns []string
	goTo     [][256]int32 // full transition table (failure links folded in)
	out      [][]int32    // pattern indices ending at each state
}

// New builds a Set. Empty patterns never match.
func New(patterns []string) *Set {
	s := &Set{patterns: patterns, goTo: [][256]int32{{}}, out: [][]int32{nil}}
	for i, p := range patterns {
		if p == "" {
			continue
		}
		state := int32(0)
		for j := range len(p) {
			c := p[j]
			next := s.goTo[state][c]
			if next == 0 {
				s.goTo = append(s.goTo, [256]int32{})
				s.out = append(s.out, nil)
				next = int32(len(s.goTo) - 1)
				s.goTo[state][c] = next
			}
			state = next
		}
		s.out[state] = append(s.out[state], int32(i))
	}

	// Breadth-first failure links, folding them into goTo so matching is a
	// single table lookup per input byte.
	fail := make([]int32, len(s.goTo))
	queue := make([]int32, 0, len(s.goTo))
	for c := range 256 {
		if next := s.goTo[0][c]; next != 0 {
			queue = append(queue, next)
		}
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		s.out[state] = append(s.out[state], s.out[fail[state]]...)
		for c := range 256 {
			next := s.goTo[state][c]
			if next == 0 {
				s.goTo[state][c] = s.goTo[fail[state]][c]
				continue
			}
			fail[next] = s.goTo[fail[state]][c]
			queue = append(queue, next)
		}
	}
	return s
}

// Find returns the indices of the patterns that occur in input, each once and
// in ascending order, matching a loop of strings.Contains over the list.
func (s *Set) Find(input string) []int {
	if len(s.goTo) == 1 {
		return nil
	}
	var seen []bool
	found := 0
	state := int32(0)
	for i := range len(input) {
		state = s.goTo[state][input[i]]
		for _, p := range s.out[state] {
			if seen == nil {
				seen = make([]bool, len(s.patterns))
			}
			if !seen[p] {
				seen[p] = true
				found++
			}
		}
		if found == len(s.patterns) {
			break
		}
	}
	if found == 0 {
		return nil
	}
	idx := make([]int, 0, found)
	for i, ok := range seen {
		if ok {
			idx = append(idx, i)
		}
	}
	return idx
}

// Contains reports whether any pattern occurs in input.
func (s *Set) Contains(input string) bool {
	state := int32(0)
	for i := range len(input) {
		state = s.goTo[state][input[i]]
		if len(s.out[state]) > 0 {
			return true
		}
	}
	return false
}

// Patterns returns the pattern list the Set was built from.
func (s *Set) Patterns() []string { return s.patterns }
