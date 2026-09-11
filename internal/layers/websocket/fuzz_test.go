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

		// Build a masked frame using the RFC 6455 §5.2 length encoding:
		// 7-bit inline below 126, 16-bit BE up to 65535, 64-bit BE above.
		// The previous construction (0x80|byte(len)) emitted malformed
		// frames from 126 bytes up — at len==126 it wrote the 126
		// extended-length marker, so the reader consumed the first two
		// mask bytes as the length and the assertion compared a 48-byte
		// payload against the 126-byte input.
		maskedPayload := make([]byte, len(payload))
		for i, b := range payload {
			maskedPayload[i] = b ^ mask[i%4]
		}

		hdr := []byte{0x81, 0x80}
		plen := len(payload)
		switch {
		case plen < 126:
			hdr[1] = 0x80 | byte(plen)
		case plen <= 0xFFFF:
			hdr[1] = 0x80 | 126
			var ext [2]byte
			binary.BigEndian.PutUint16(ext[:], uint16(plen))
			hdr = append(hdr, ext[:]...)
		default:
			hdr[1] = 0x80 | 127
			var ext [8]byte
			binary.BigEndian.PutUint64(ext[:], uint64(plen))
			hdr = append(hdr, ext[:]...)
		}

		data := append(hdr, mask[:]...)
		data = append(data, maskedPayload...)

		fr := NewMaskedFrameReader(bytes.NewReader(data), 1<<20)
		frame, err := fr.ReadFrame()
		if err != nil {
			// A well-formed frame of any size up to the cap must parse.
			t.Errorf("ReadFrame failed for well-formed masked frame (len=%d): %v", plen, err)
			return
		}

		if !bytes.Equal(frame.Payload, payload) {
			t.Errorf("unmasked payload mismatch (len=%d): got %d bytes", plen, len(frame.Payload))
		}
	})
}

// Ensure the random source is used (avoids unused import in some build configs).
var _ = rand.Reader
var _ = io.EOF
var _ = binary.BigEndian
