package tracing

import "testing"

func TestParseTraceparent(t *testing.T) {
	const tid, pid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	valid := map[string]bool{
		"00-" + tid + "-" + pid + "-01":                                true,
		"00-" + tid + "-" + pid + "-00":                                true,
		" 00-" + tid + "-" + pid + "-01 ":                              true,
		"01-" + tid + "-" + pid + "-01-future":                         true, // future version, extra field
		"01-" + tid + "-" + pid + "-01":                                true,
		"00-" + tid + "-" + pid + "-01-extra":                          false, // version 00 has exactly 4 fields
		"01-" + tid + "-" + pid + "-01x":                               false,
		"ff-" + tid + "-" + pid + "-01":                                false,
		"00-" + "00000000000000000000000000000000" + "-" + pid + "-01": false,
		"00-" + tid + "-" + "0000000000000000" + "-01":                 false,
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-" + pid + "-01":           false, // uppercase
		"00-" + tid + "-" + pid:                                        false,
		"00_" + tid + "-" + pid + "-01":                                false,
		"zz-" + tid + "-" + pid + "-01":                                false,
		"00-" + tid[:31] + "g-" + pid + "-01":                          false,
		"":                                                             false,
	}
	for h, want := range valid {
		gotT, gotP, ok := ParseTraceparent(h)
		if ok != want {
			t.Errorf("ParseTraceparent(%q) ok = %v, want %v", h, ok, want)
			continue
		}
		if ok && (gotT != tid || gotP != pid) {
			t.Errorf("ParseTraceparent(%q) = %q, %q", h, gotT, gotP)
		}
	}
	if got := FormatTraceparent(tid, pid); got != "00-"+tid+"-"+pid+"-01" {
		t.Fatalf("FormatTraceparent = %q", got)
	}
	if _, _, ok := ParseTraceparent(FormatTraceparent(tid, pid)); !ok {
		t.Fatal("FormatTraceparent output does not parse")
	}
}

func FuzzParseTraceparent(f *testing.F) {
	f.Add("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	f.Add("cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x")
	f.Fuzz(func(t *testing.T, h string) {
		tid, pid, ok := ParseTraceparent(h)
		if !ok {
			return
		}
		if len(tid) != 32 || len(pid) != 16 || !isLowerHex(tid) || !isLowerHex(pid) || allZero(tid) || allZero(pid) {
			t.Fatalf("accepted invalid ids %q %q from %q", tid, pid, h)
		}
	})
}
