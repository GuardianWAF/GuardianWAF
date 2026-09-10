package websocket

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Regression: inspectAndForward unmasked every frame it read (frame readers
// strip the client's masking key) and then relayed frames via WriteFrame,
// which writes MASK=0 with no key. RFC 6455 §5.1 requires "a client MUST mask
// all frames that it sends to the server" — the proxy is the client toward
// the backend — so every inspected client→backend message went on the wire
// unmasked: a protocol violation that RFC-compliant backends must reject.
// The leg toward the backend must be (re-)masked with a fresh per-frame key;
// the backend→client leg must stay unmasked (a server MUST NOT mask).

// maskedTestFrame hand-assembles one masked wire frame as ground truth.
func maskedTestFrame(fin bool, opcode Opcode, payload, key []byte) []byte {
	hdr0 := byte(opcode)
	if fin {
		hdr0 |= 0x80
	}
	out := []byte{hdr0, byte(len(payload)) | 0x80, key[0], key[1], key[2], key[3]}
	for i, b := range payload {
		out = append(out, b^key[i%4])
	}
	return out
}

// wireView is a parsed frame with its mask bits and key left visible.
type wireView struct {
	fin     bool
	opcode  Opcode
	masked  bool
	key     [4]byte
	payload []byte
}

// parseFirstWireFrame parses the first complete frame in data, failing the
// test on truncation or a missing mask key.
func parseFirstWireFrame(t *testing.T, data []byte) wireView {
	t.Helper()
	if len(data) < 2 {
		t.Fatalf("wire data too short for a frame header: %d bytes", len(data))
	}
	v := wireView{fin: data[0]&0x80 != 0, opcode: Opcode(data[0] & 0x0F), masked: data[1]&0x80 != 0}
	l := int(data[1] & 0x7F)
	off := 2
	if l == 126 {
		if len(data) < 4 {
			t.Fatalf("truncated 16-bit length")
		}
		l = int(binary.BigEndian.Uint16(data[2:4]))
		off = 4
	}
	if v.masked {
		if len(data) < off+4 {
			t.Fatalf("MASK=1 but masking key missing/truncated")
		}
		copy(v.key[:], data[off:off+4])
		off += 4
	}
	if len(data) < off+l {
		t.Fatalf("truncated payload: have %d bytes, header declares %d", len(data)-off, l)
	}
	v.payload = data[off : off+l]
	return v
}

func unmaskView(t *testing.T, v wireView) []byte {
	t.Helper()
	if !v.masked {
		return v.payload
	}
	dec := append([]byte(nil), v.payload...)
	for i := range dec {
		dec[i] ^= v.key[i%4]
	}
	return dec
}

// sinkWriter collects relayed wire bytes.
type sinkWriter struct{ buf bytes.Buffer }

func (w *sinkWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func newMaskingTestLayer(block bool) *Layer {
	return NewLayer(&Config{
		Enabled:      true,
		ScanPayloads: true,
		CheckPayload: func(clientIP, path string, payload []byte) (int, bool) {
			if block {
				return 100, true
			}
			return 0, false
		},
	})
}

func TestInspectAndForward_MasksClientToBackendFrames(t *testing.T) {
	l := newMaskingTestLayer(false)
	srcKey := []byte{0x11, 0x22, 0x33, 0x44}
	payload := []byte("' UNION SELECT password FROM users --")
	src := maskedTestFrame(true, OpText, payload, srcKey)

	dst := &sinkWriter{}
	l.inspectAndForward(bytes.NewReader(src), dst, "1.2.3.4", "/ws", true)

	v := parseFirstWireFrame(t, dst.buf.Bytes())
	if v.opcode != OpText || !v.fin {
		t.Fatalf("opcode/FIN not preserved: opcode=%v fin=%v", v.opcode, v.fin)
	}
	if !v.masked {
		t.Fatal("client→backend frame relayed with MASK=0 and no masking key — RFC 6455 §5.1 violation")
	}
	if got := unmaskView(t, v); string(got) != string(payload) {
		t.Fatalf("unmask(key) = %q, want original payload %q", got, payload)
	}
}

func TestInspectAndForward_MasksControlAndSynthesizedFrames(t *testing.T) {
	t.Run("forwarded ping stays masked", func(t *testing.T) {
		l := newMaskingTestLayer(false)
		src := maskedTestFrame(true, OpPing, []byte("ka"), []byte{0x0A, 0x0B, 0x0C, 0x0D})
		dst := &sinkWriter{}
		l.inspectAndForward(bytes.NewReader(src), dst, "1.2.3.4", "/ws", true)

		v := parseFirstWireFrame(t, dst.buf.Bytes())
		if v.opcode != OpPing {
			t.Fatalf("opcode = %v, want OpPing", v.opcode)
		}
		if !v.masked {
			t.Fatal("control frame toward backend relayed unmasked — RFC 6455 §5.1 violation")
		}
		if got := unmaskView(t, v); string(got) != "ka" {
			t.Fatalf("unmask(key) = %q, want %q", got, "ka")
		}
	})

	t.Run("synthesized policy close toward backend is masked", func(t *testing.T) {
		l := newMaskingTestLayer(true)
		src := maskedTestFrame(true, OpText, []byte("attack payload"), []byte{0x55, 0x66, 0x77, 0x88})
		dst := &sinkWriter{}
		l.inspectAndForward(bytes.NewReader(src), dst, "1.2.3.4", "/ws", true)

		v := parseFirstWireFrame(t, dst.buf.Bytes())
		if v.opcode != OpClose {
			t.Fatalf("opcode = %v, want OpClose", v.opcode)
		}
		if !v.masked {
			t.Fatal("synthesized close toward backend written unmasked — RFC 6455 §5.1 violation")
		}
		dec := unmaskView(t, v)
		if len(dec) < 2 || int(dec[0])<<8|int(dec[1]) != 1008 {
			t.Fatalf("close code = %v, want 1008", dec)
		}
	})
}

func TestInspectAndForward_BackendToClientStaysUnmasked(t *testing.T) {
	l := newMaskingTestLayer(false)
	// Server→client frames MUST NOT be masked (RFC 6455 §5.1).
	src := []byte{0x81, byte(len("server says hi"))}
	src = append(src, []byte("server says hi")...)

	dst := &sinkWriter{}
	l.inspectAndForward(bytes.NewReader(src), dst, "1.2.3.4", "/ws", false)

	v := parseFirstWireFrame(t, dst.buf.Bytes())
	if v.masked {
		t.Fatal("backend→client frame was masked — a server MUST NOT mask (RFC 6455 §5.1)")
	}
	if string(v.payload) != "server says hi" {
		t.Fatalf("payload = %q, want verbatim relay", v.payload)
	}
}

func TestWriteFrameMasked_RoundTripAndEmptyPayload(t *testing.T) {
	// 16-bit extended length + mask: key must sit between ext length and payload.
	payload := bytes.Repeat([]byte{'A'}, 300)
	var buf bytes.Buffer
	if err := WriteFrameMasked(&buf, &Frame{FIN: true, Opcode: OpText, Payload: payload}); err != nil {
		t.Fatalf("WriteFrameMasked: %v", err)
	}
	wire := buf.Bytes()
	if wire[1]&0x80 == 0 {
		t.Fatal("MASK bit not set on masked frame")
	}
	if wire[1]&0x7F != 126 {
		t.Fatalf("extended length marker = %d, want 126", wire[1]&0x7F)
	}
	if int(binary.BigEndian.Uint16(wire[2:4])) != len(payload) {
		t.Fatalf("declared length = %d, want %d", binary.BigEndian.Uint16(wire[2:4]), len(payload))
	}

	fr := NewMaskedFrameReader(bytes.NewReader(wire), MaxPayloadSize)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(frame.Payload) != string(payload) {
		t.Fatalf("round-trip payload = %q, want original", frame.Payload)
	}

	// Empty payload: MASK=1 still requires the 4-byte key on the wire.
	buf.Reset()
	if err := WriteFrameMasked(&buf, &Frame{FIN: true, Opcode: OpPing, Payload: nil}); err != nil {
		t.Fatalf("WriteFrameMasked(empty): %v", err)
	}
	if buf.Len() != 2+4 {
		t.Fatalf("empty masked frame = %d bytes, want 6 (header + key)", buf.Len())
	}
	if buf.Bytes()[1]&0x80 == 0 {
		t.Fatal("MASK bit not set on empty masked frame")
	}
	fr = NewMaskedFrameReader(bytes.NewReader(buf.Bytes()), MaxPayloadSize)
	if frame, err := fr.ReadFrame(); err != nil || len(frame.Payload) != 0 {
		t.Fatalf("empty masked frame read back: frame=%+v err=%v", frame, err)
	}
}
