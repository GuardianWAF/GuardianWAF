package websocket

import (
	"bytes"
	"strings"
	"testing"
)

// Regression tests: inspectAndForward must inspect data-frame payloads for
// BOTH OpText and OpContinuation. RFC 6455 §5.4 fragmentation splits messages
// across frames; the previous OpText-only check let an attacker move the
// payload into continuation frames, bypassing CheckPayload entirely.

type recordingWriter struct {
	buf bytes.Buffer
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func parseFrames(t *testing.T, data []byte) []*Frame {
	t.Helper()
	fr := NewFrameReader(bytes.NewReader(data), MaxPayloadSize)
	var frames []*Frame
	for data != nil {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		frames = append(frames, f)
	}
	return frames
}

// Drives inspectAndForward with the given source frames and returns the
// payloads CheckPayload saw plus the frames written to the destination.
func runInspector(t *testing.T, srcFrames []*Frame, check func(payload string) (int, bool)) (inspected []string, outFrames []*Frame) {
	t.Helper()

	var srcBuf bytes.Buffer
	for _, f := range srcFrames {
		if err := WriteFrame(&srcBuf, f); err != nil {
			t.Fatalf("WriteFrame(src): %v", err)
		}
	}

	dst := &recordingWriter{}
	l := NewLayer(&Config{
		Enabled:      true,
		ScanPayloads: true,
		CheckPayload: func(clientIP, path string, payload []byte) (int, bool) {
			inspected = append(inspected, string(payload))
			return check(string(payload))
		},
	})

	l.inspectAndForward(bytes.NewReader(srcBuf.Bytes()), dst, "1.2.3.4", "/ws", true)

	return inspected, parseFrames(t, dst.buf.Bytes())
}

func TestInspectAndForwardInspectsContinuationFrames(t *testing.T) {
	evil := "EVIL-PAYLOAD-SQLI"
	srcFrames := []*Frame{
		{FIN: false, Opcode: OpText, Payload: []byte("benign")},
		{FIN: true, Opcode: OpContinuation, Payload: []byte(evil)},
	}

	inspected, out := runInspector(t, srcFrames, func(p string) (int, bool) {
		if strings.Contains(p, "EVIL") {
			return 100, true
		}
		return 0, false
	})

	sawEvil := false
	for _, p := range inspected {
		if p == evil {
			sawEvil = true
		}
	}
	if !sawEvil {
		t.Fatalf("FAIL: CheckPayload never saw the continuation payload (inspected: %v)", inspected)
	}

	// The blocked payload must not be forwarded; the benign first frame and
	// the 1008 close must be.
	var forwarded, sawClose []string
	for _, f := range out {
		if f.Opcode == OpClose {
			sawClose = append(sawClose, "close")
			continue
		}
		forwarded = append(forwarded, string(f.Payload))
	}
	for _, p := range forwarded {
		if strings.Contains(p, "EVIL") {
			t.Fatalf("FAIL: blocked continuation payload was forwarded to the backend: %q", p)
		}
	}
	if len(sawClose) == 0 {
		t.Fatalf("FAIL: no 1008 close frame was written after blocking")
	}
}

func TestInspectAndForwardForwardsBenignFragmentedMessage(t *testing.T) {
	srcFrames := []*Frame{
		{FIN: false, Opcode: OpText, Payload: []byte("hello ")},
		{FIN: true, Opcode: OpContinuation, Payload: []byte("world")},
	}

	inspected, out := runInspector(t, srcFrames, func(p string) (int, bool) {
		return 0, false
	})

	if len(inspected) != 2 {
		t.Fatalf("FAIL: expected both fragment payloads inspected, got %v", inspected)
	}
	dataPayloads := []string{}
	for _, f := range out {
		if f.Opcode.IsControl() {
			continue
		}
		dataPayloads = append(dataPayloads, string(f.Payload))
	}
	if len(dataPayloads) != 2 || dataPayloads[0] != "hello " || dataPayloads[1] != "world" {
		t.Fatalf("FAIL: benign fragmented message not relayed intact: %v", dataPayloads)
	}
}

func TestInspectAndForwardControlFramesStillForwarded(t *testing.T) {
	srcFrames := []*Frame{
		{FIN: true, Opcode: OpPing, Payload: []byte("keepalive")},
	}

	_, out := runInspector(t, srcFrames, func(p string) (int, bool) {
		return 0, false
	})

	if len(out) != 1 || out[0].Opcode != OpPing || string(out[0].Payload) != "keepalive" {
		t.Fatalf("FAIL: control frame not forwarded intact: %+v", out)
	}
}
