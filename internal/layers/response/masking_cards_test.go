package response

import (
	"strings"
	"testing"
)

// Regression: MaskCreditCards advanced past the ENTIRE separator-joined digit
// run whenever the run as a whole failed the Luhn check. Two valid cards
// separated by a single space (or concatenated outright) formed a 32-digit
// run, the 32-digit Luhn failed, and both cards leaked unmasked.
func TestMaskCreditCardsAdjacentCards(t *testing.T) {
	card := "4111111111111111" // canonical Luhn-valid Visa test number
	cases := []struct {
		name  string
		input string
	}{
		{"space-separated pair", card + " " + card},
		{"dash-separated pair", card + "-" + card},
		{"concatenated pair", card + card},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskCreditCards(tc.input)
			wantMasked := strings.Repeat("*", 12)
			// Both cards must lose their first 12 digits (last 4 kept).
			want := wantMasked + card[12:] + sepOf(tc.input) + wantMasked + card[12:]
			if got != want {
				t.Fatalf("FAIL: got %q, want %q — cards leaked or mangled", got, want)
			}
		})
	}
}

// TestMaskCreditCardsSingleSpacedCard pins the original intent: one card
// written with space separators is detected and masked.
func TestMaskCreditCardsSingleSpacedCard(t *testing.T) {
	card := "4111111111111111"
	input := card[0:4] + " " + card[4:8] + " " + card[8:12] + " " + card[12:16]
	got := MaskCreditCards(input)
	want := "**** **** **** " + card[12:]
	if got != want {
		t.Fatalf("FAIL: single spaced card got %q, want %q", got, want)
	}
}

// TestMaskCreditCardsNonCardDigits pins the false-positive guard: digit runs
// that never contain a Luhn-valid 13-19 window pass through untouched.
func TestMaskCreditCardsNonCardDigits(t *testing.T) {
	input := "order 12345 total 67890 items 42"
	got := MaskCreditCards(input)
	if got != input {
		t.Fatalf("FAIL: non-card digits mangled: %q -> %q", input, got)
	}
}

func sepOf(s string) string {
	for _, r := range s {
		if r == ' ' || r == '-' {
			return string(r)
		}
	}
	return ""
}
