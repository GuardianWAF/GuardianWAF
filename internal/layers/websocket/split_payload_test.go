package websocket

import (
	"strings"
	"testing"
)

// Regression: inspectAndForward scanned each data frame's payload
// independently. A signature split across fragment boundaries — "' UNION" in
// the OpText frame, " SELECT password FROM users --" in the continuation —
// matched neither per-frame scan, so the assembled injection reached the
// backend undetected. The message-level scan at FIN must see the assembled
// payload, and the final fragment must be withheld pending that verdict.
func TestSplitPayloadAssembledBeforeInspection(t *testing.T) {
	srcFrames := []*Frame{
		{FIN: false, Opcode: OpText, Payload: []byte("' UNION")},
		{FIN: true, Opcode: OpContinuation, Payload: []byte(" SELECT password FROM users --")},
	}

	assembledSeen := false
	inspected, out := runInspector(t, srcFrames, func(p string) (int, bool) {
		if strings.Contains(p, "UNION SELECT password") {
			assembledSeen = true
			return 100, true
		}
		return 0, false
	})

	if !assembledSeen {
		t.Fatalf("FAIL: CheckPayload never saw the assembled message (inspected: %v) — the split-payload injection evaded detection", inspected)
	}

	// The final fragment must be withheld pending the assembled verdict: the
	// backend must not receive the completed injection.
	for _, f := range out {
		if strings.Contains(string(f.Payload), "password") {
			t.Fatalf("FAIL: the final injection fragment was forwarded to the backend: %q", f.Payload)
		}
	}
}

// The benign fragmented message must still relay intact: non-final fragments
// forward immediately, and the assembled scan passes clean payloads through.
func TestSplitPayloadBenignFragmentedRelaysIntact(t *testing.T) {
	srcFrames := []*Frame{
		{FIN: false, Opcode: OpText, Payload: []byte("hello ")},
		{FIN: true, Opcode: OpContinuation, Payload: []byte("world")},
	}

	inspected, out := runInspector(t, srcFrames, func(p string) (int, bool) {
		return 0, false
	})

	if !assembledContains(inspected, "hello world") {
		t.Fatalf("FAIL: CheckPayload never saw the assembled benign message (inspected: %v)", inspected)
	}

	var relayed []string
	for _, f := range out {
		if f.Opcode == OpText || f.Opcode == OpContinuation {
			relayed = append(relayed, string(f.Payload))
		}
	}
	if len(relayed) != 2 || relayed[0] != "hello " || relayed[1] != "world" {
		t.Fatalf("FAIL: benign fragments not relayed intact: %v", relayed)
	}
}

func assembledContains(inspected []string, needle string) bool {
	for _, p := range inspected {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
