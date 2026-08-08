package websocket

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

// FuzzFrameReader tests the frame parser against arbitrary byte sequences.
// The parser must never panic, regardless of input.
func FuzzFrameReader(f *testing.F) {
	// Seed with valid frames + edge cases.
	seeds := [][]byte{
		{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}, // text "hello"
		{0x82, 0x00},                          // empty binary
		{0x88, 0x00},                          // close
		{0x89, 0x00},                          // ping
		{0x81, 126, 0x01, 0x2C},               // extended length 300
		{0x81, 127},                           // 64-bit length (truncated)
		{0x00, 0x00},                          // continuation empty
		{},                                    // empty input
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fr := NewFrameReader(bytes.NewReader(data), 1<<20)
		frame, err := fr.ReadFrame()
		if err != nil {
			// Errors are expected for random input — just make sure we didn't panic.
			return
		}
		// If we got a frame, it should be well-formed.
		if frame == nil {
			t.Fatal("frame is nil without error")
		}
		// Payload should not exceed max size.
		if int64(len(frame.Payload)) > 1<<20 {
			t.Errorf("payload %d exceeds max size", len(frame.Payload))
		}
	})
}

// FuzzFrameRoundTrip tests that WriteFrame → ReadFrame round-trips correctly
// for arbitrary payloads.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add(bytes.Repeat([]byte{0x00}, 125))
	f.Add(bytes.Repeat([]byte{0xFF}, 126))
	f.Add(bytes.Repeat([]byte("A"), 65536))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			return // skip oversized
		}

		original := &Frame{
			FIN:     true,
			Opcode:  OpText,
			Payload: payload,
		}

		var buf bytes.Buffer
		if err := WriteFrame(&buf, original); err != nil {
			return
		}

		fr := NewFrameReader(&buf, 1<<20)
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Errorf("ReadFrame failed after WriteFrame: %v", err)
			return
		}

		if !bytes.Equal(frame.Payload, payload) {
			t.Errorf("payload mismatch: got %d bytes, want %d", len(frame.Payload), len(payload))
		}
	})
}

// FuzzMaskUnmask tests that masked payloads are correctly unmasked.
func FuzzMaskUnmask(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, []byte("hello"))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte("test"))
	f.Add([]byte{0, 0, 0, 0}, bytes.Repeat([]byte("x"), 100))

	f.Fuzz(func(t *testing.T, maskBytes []byte, payload []byte) {
		if len(maskBytes) != 4 || len(payload) > 1<<20 {
			return
		}
		var mask [4]byte
		copy(mask[:], maskBytes)

		// Build a masked frame.
		maskedPayload := make([]byte, len(payload))
		for i, b := range payload {
			maskedPayload[i] = b ^ mask[i%4]
		}

		data := []byte{0x81, 0x80 | byte(len(payload))}
		data = append(data, mask[:]...)
		data = append(data, maskedPayload...)

		fr := NewMaskedFrameReader(bytes.NewReader(data), 1<<20)
		frame, err := fr.ReadFrame()
		if err != nil {
			// If the payload is small enough, the parse should succeed.
			if len(payload) < 126 {
				t.Errorf("ReadFrame failed for small masked frame: %v (data=%v)", err, data)
			}
			return
		}

		if !bytes.Equal(frame.Payload, payload) {
			t.Errorf("unmasked payload mismatch: got %v, want %v", frame.Payload, payload)
		}
	})
}

// Ensure the random source is used (avoids unused import in some build configs).
var _ = rand.Reader
var _ = io.EOF
var _ = binary.BigEndian
