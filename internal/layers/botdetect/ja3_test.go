package botdetect

import (
	"testing"
)

func TestComputeJA3_Basic(t *testing.T) {
	fp := ComputeJA3(771, []uint16{49195, 49199, 49196}, []uint16{0, 23, 65281}, []uint16{29, 23, 24}, []uint8{0})

	if fp.Hash == "" {
		t.Fatal("expected non-empty JA3 hash")
	}
	if fp.Raw == "" {
		t.Fatal("expected non-empty JA3 raw string")
	}

	// Verify raw format: TLSVersion,Ciphers,Extensions,Curves,Points
	// 771,49195-49199-49196,0-23-65281,29-23-24,0
	expected := "771,49195-49199-49196,0-23-65281,29-23-24,0"
	if fp.Raw != expected {
		t.Errorf("expected raw %q, got %q", expected, fp.Raw)
	}
}

func TestComputeJA3_Empty(t *testing.T) {
	fp := ComputeJA3(0, nil, nil, nil, nil)

	if fp.Hash == "" {
		t.Fatal("expected non-empty JA3 hash even with empty params")
	}
	if fp.Raw != "0,,,," {
		t.Errorf("expected raw %q, got %q", "0,,,,", fp.Raw)
	}
}

func TestComputeJA3_Deterministic(t *testing.T) {
	ciphers := []uint16{49195, 49199}
	exts := []uint16{0, 23}

	fp1 := ComputeJA3(771, ciphers, exts, nil, nil)
	fp2 := ComputeJA3(771, ciphers, exts, nil, nil)

	if fp1.Hash != fp2.Hash {
		t.Errorf("JA3 should be deterministic: %s != %s", fp1.Hash, fp2.Hash)
	}
}

func TestComputeJA3_DifferentParams(t *testing.T) {
	fp1 := ComputeJA3(771, []uint16{49195}, nil, nil, nil)
	fp2 := ComputeJA3(772, []uint16{49195}, nil, nil, nil)

	if fp1.Hash == fp2.Hash {
		t.Error("different TLS versions should produce different JA3 hashes")
	}
}

func TestJoinUint16(t *testing.T) {
	tests := []struct {
		input    []uint16
		expected string
	}{
		{nil, ""},
		{[]uint16{}, ""},
		{[]uint16{1}, "1"},
		{[]uint16{1, 2, 3}, "1-2-3"},
		{[]uint16{65535, 0, 256}, "65535-0-256"},
	}

	for _, tc := range tests {
		got := joinUint16(tc.input)
		if got != tc.expected {
			t.Errorf("joinUint16(%v) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestJoinUint8(t *testing.T) {
	tests := []struct {
		input    []uint8
		expected string
	}{
		{nil, ""},
		{[]uint8{0}, "0"},
		{[]uint8{0, 1, 2}, "0-1-2"},
	}

	for _, tc := range tests {
		got := joinUint8(tc.input)
		if got != tc.expected {
			t.Errorf("joinUint8(%v) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
