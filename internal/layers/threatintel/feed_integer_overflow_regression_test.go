package threatintel

import (
	"strconv"
	"strings"
	"testing"
)

func TestFeedIntegerParserRejectsOverflowBeforeArithmetic(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	maximum := strconv.Itoa(maxInt)
	for _, tc := range []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"42", 42, false},
		{"-42", -42, false},
		{"0", 0, false},
		{"", 0, false}, // Existing empty-field compatibility.
		{"-", 0, false},
		{maximum, maxInt, false},
		{"-" + maximum, -maxInt, false},
		{strconv.FormatUint(uint64(maxInt)+1, 10), 0, true},
		{"26000000000000000000", 0, true},
		{"-" + maximum + "0", 0, true},
		{strings.Repeat("9", 40), 0, true},
		{"42x", 0, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			for range 2 {
				got, err := parseInt(tc.value)
				if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
					t.Fatalf("parseInt(%q) = %d, %v; want %d, error=%v", tc.value, got, err, tc.want, tc.wantErr)
				}
			}
		})
	}
}
