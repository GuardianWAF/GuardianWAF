package websocket

// Regression: RFC 6455 §5.5 control-frame constraints must be enforced.
//
//	All control frames MUST have a payload length of 125 bytes or less and
//	MUST NOT be fragmented.
//
// ReadFrame already refused the other protocol violations it owns — the §5.1
// mask direction (ErrMaskViolation -> 1002) and an oversized payload
// (ErrFrameTooLarge -> 1009) — but accepted control frames of any size and any
// fragmentation state. That matters because layer.go forwards every frame whose
// opcode satisfies IsControl() WITHOUT inspecting its payload, so the missing
// check widened the deliberately-uninspected channel from the spec's 125-byte
// ceiling to cfg.MaxFrameSize (1 MiB by default), and let a peer relay
// fragmented control frames that a conforming endpoint must reject.
//
// These tests drive ReadFrame over an in-memory buffer (not a net.Pipe pair):
// the relay refuses the connection on a parse error, and a two-pipe harness
// deadlocks unless both legs are drained concurrently with deadlines.

import (
	"bytes"
	"errors"
	"testing"
)

// buildMaskedClientFrame assembles a client->server (masked) frame per RFC 6455.
func buildMaskedClientFrame(fin bool, op Opcode, payload []byte) []byte {
	var buf []byte
	b0 := byte(op & 0x0F)
	if fin {
		b0 |= 0x80
	}
	buf = append(buf, b0)

	switch n := len(payload); {
	case n < 126:
		buf = append(buf, 0x80|byte(n))
	case n <= 0xFFFF:
		buf = append(buf, 0x80|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, 0x80|127)
		for shift := 56; shift >= 0; shift -= 8 {
			buf = append(buf, byte(n>>uint(shift)))
		}
	}

	mask := []byte{0x11, 0x22, 0x33, 0x44}
	buf = append(buf, mask...)
	for i, b := range payload {
		buf = append(buf, b^mask[i%4])
	}
	return buf
}

// TestReadFrameRejectsOversizedControlFrames covers the size MUST across all
// three control opcodes.
func TestReadFrameRejectsOversizedControlFrames(t *testing.T) {
	for _, op := range []Opcode{OpClose, OpPing, OpPong} {
		t.Run(string(rune('0'+byte(op))), func(t *testing.T) {
			payload := bytes.Repeat([]byte("A"), 126) // one over the §5.5 ceiling
			fr := NewMaskedFrameReader(bytes.NewReader(buildMaskedClientFrame(true, op, payload)), 1<<20)

			frame, err := fr.ReadFrame()
			if err == nil {
				t.Fatalf("ReadFrame accepted a %d-byte control frame (opcode 0x%X); "+
					"RFC 6455 §5.5 caps control frames at 125 bytes", len(frame.Payload), byte(op))
			}
			if !errors.Is(err, ErrControlFrameViolation) {
				t.Fatalf("err = %v, want ErrControlFrameViolation", err)
			}
		})
	}
}

// TestReadFrameRejectsFragmentedControlFrames covers the fragmentation MUST.
func TestReadFrameRejectsFragmentedControlFrames(t *testing.T) {
	for _, op := range []Opcode{OpClose, OpPing, OpPong} {
		fr := NewMaskedFrameReader(
			bytes.NewReader(buildMaskedClientFrame(false, op, []byte("x"))), 1<<20)

		if frame, err := fr.ReadFrame(); err == nil {
			t.Fatalf("ReadFrame accepted a FRAGMENTED control frame (opcode 0x%X, FIN=0); "+
				"RFC 6455 §5.5 forbids fragmenting control frames", byte(frame.Opcode))
		}
	}
}

// TestReadFrameControlFrameBoundary pins the exact §5.5 ceiling: 125 is legal,
// 126 is not. A fix that clamps at the wrong boundary fails here.
func TestReadFrameControlFrameBoundary(t *testing.T) {
	for _, tc := range []struct {
		size    int
		wantErr bool
	}{
		{0, false},
		{1, false},
		{125, false}, // RFC maximum — must keep working
		{126, true},
		{1000, true},
	} {
		payload := bytes.Repeat([]byte("A"), tc.size)
		fr := NewMaskedFrameReader(bytes.NewReader(buildMaskedClientFrame(true, OpPing, payload)), 1<<20)

		_, err := fr.ReadFrame()
		if gotErr := err != nil; gotErr != tc.wantErr {
			t.Errorf("control frame of %d bytes: rejected=%v, want rejected=%v (err=%v)",
				tc.size, gotErr, tc.wantErr, err)
		}
	}
}

// TestReadFrameDataFramesUnaffected is the control: §5.5 constrains control
// frames ONLY. Data frames stay freely fragmentable and freely sizeable, so a
// fix cannot over-reject legitimate traffic.
func TestReadFrameDataFramesUnaffected(t *testing.T) {
	cases := []struct {
		name string
		fin  bool
		op   Opcode
		body []byte
	}{
		{"fragmented text start", false, OpText, []byte("hello ")},
		{"continuation end", true, OpContinuation, []byte("world")},
		{"large binary frame", true, OpBinary, bytes.Repeat([]byte("B"), 70_000)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fr := NewMaskedFrameReader(bytes.NewReader(buildMaskedClientFrame(c.fin, c.op, c.body)), 1<<20)
			frame, err := fr.ReadFrame()
			if err != nil {
				t.Fatalf("conforming data frame rejected: %v", err)
			}
			if frame.Opcode != c.op || frame.FIN != c.fin {
				t.Errorf("got opcode=0x%X fin=%v, want opcode=0x%X fin=%v",
					byte(frame.Opcode), frame.FIN, byte(c.op), c.fin)
			}
			if !bytes.Equal(frame.Payload, c.body) {
				t.Errorf("payload mismatch: %d bytes, want %d", len(frame.Payload), len(c.body))
			}
		})
	}
}

// TestReadFramePayloadRoundTripUnchanged pins that the un-masking still
// produces the exact original bytes for a conforming 125-byte ping.
func TestReadFramePayloadRoundTripUnchanged(t *testing.T) {
	want := bytes.Repeat([]byte("p"), 125)
	fr := NewMaskedFrameReader(bytes.NewReader(buildMaskedClientFrame(true, OpPing, want)), 1<<20)

	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("125-byte ping rejected: %v", err)
	}
	if !bytes.Equal(frame.Payload, want) {
		t.Errorf("un-masked payload does not round-trip: got %d bytes, want %d",
			len(frame.Payload), len(want))
	}
}
