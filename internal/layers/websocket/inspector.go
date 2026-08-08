// Package websocket provides frame-level inspection of WebSocket connections.
//
// Without this layer, WebSocket traffic bypasses all WAF detection: an
// attacker can tunnel SQLi, XSS, or CMDi payloads through a WS connection
// after the initial HTTP upgrade handshake passes the WAF's request-time
// inspection.
//
// The inspector intercepts WebSocket upgrades at the middleware level, dials
// the backend, then sits between client and backend as a bidirectional
// inspector. Each text frame is decoded and run through the WAF's detection
// pipeline; binary frames are size-limited but not content-inspected.
//
// RFC 6455 frame format reference:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-------+-+-------------+-------------------------------+
//	|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//	|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//	|N|V|V|V|       |S|             |   (if payload len==126/127)   |
//	| |1|2|3|       |K|             |                               |
//	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//	|     Extended payload length continued, if payload len == 127  |
//	+ - - - - - - - - - - - - - - - +-------------------------------+
//	|                               |Masking-key, if MASK set to 1  |
//	+-------------------------------+-------------------------------+
//	| Masking-key (continued)       |          Payload Data         |
//	+-------------------------------- - - - - - - - - - - - - - - - +
package websocket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Opcode is a WebSocket frame opcode (RFC 6455 §5.2).
type Opcode byte

const (
	OpContinuation Opcode = 0x0
	OpText         Opcode = 0x1
	OpBinary       Opcode = 0x2
	OpClose        Opcode = 0x8
	OpPing         Opcode = 0x9
	OpPong         Opcode = 0xA
)

func (o Opcode) IsControl() bool { return o >= 0x8 }
func (o Opcode) IsData() bool    { return o == OpText || o == OpBinary || o == OpContinuation }

// ErrFrameTooLarge is returned when a frame's payload exceeds the configured
// maximum. The caller should close the connection with a 1009 (Message Too
// Big) close frame.
var ErrFrameTooLarge = errors.New("websocket: frame payload exceeds maximum size")

// MaxPayloadSize is the absolute ceiling for a single frame payload.
const MaxPayloadSize = 1 << 24 // 16 MiB

// Frame represents a parsed WebSocket data frame.
type Frame struct {
	FIN     bool
	Opcode  Opcode
	Payload []byte
}

// FrameReader reads and parses WebSocket frames from an io.Reader.
// It is designed for the server-to-client (unmasked) direction; the
// client-to-server (masked) direction uses FrameReaderMasked.
type FrameReader struct {
	r       io.Reader
	maxSize int64
	masked  bool
}

// NewFrameReader creates a reader for unmasked frames (backend → client).
func NewFrameReader(r io.Reader, maxSize int64) *FrameReader {
	if maxSize <= 0 || maxSize > MaxPayloadSize {
		maxSize = MaxPayloadSize
	}
	return &FrameReader{r: r, maxSize: maxSize}
}

// NewMaskedFrameReader creates a reader for masked frames (client → backend).
func NewMaskedFrameReader(r io.Reader, maxSize int64) *FrameReader {
	if maxSize <= 0 || maxSize > MaxPayloadSize {
		maxSize = MaxPayloadSize
	}
	return &FrameReader{r: r, maxSize: maxSize, masked: true}
}

// ReadFrame reads and parses one complete WebSocket frame.
// Returns ErrFrameTooLarge if the payload exceeds maxSize.
func (fr *FrameReader) ReadFrame() (*Frame, error) {
	// Read the first 2 bytes (FIN/RSV/opcode + MASK/payload-length).
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(fr.r, hdr); err != nil {
		return nil, err
	}

	fin := hdr[0]&0x80 != 0
	opcode := Opcode(hdr[0] & 0x0F)
	masked := hdr[1]&0x80 != 0

	// If this is a masked direction, the frame must have a mask.
	// (The server may also send masked frames, though it's not standard.)
	if fr.masked && !masked {
		masked = false // tolerate unmasked in masked direction
	}

	// Decode payload length.
	var payloadLen int64
	switch hdr[1] & 0x7F {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(fr.r, ext); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(fr.r, ext); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint64(ext))
	default:
		payloadLen = int64(hdr[1] & 0x7F)
	}

	if payloadLen > fr.maxSize {
		return nil, ErrFrameTooLarge
	}

	// Read masking key (if present).
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(fr.r, mask[:]); err != nil {
			return nil, err
		}
	}

	// Read payload.
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return nil, err
		}
	}

	// Unmask payload (XOR with mask key).
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return &Frame{FIN: fin, Opcode: opcode, Payload: payload}, nil
}

// WriteFrame writes a WebSocket frame to w. If masked is true, a random-ish
// mask is applied (used for client→backend direction). For simplicity, the
// mask is all-zeros when called from the inspector (the backend accepts
// unmasked frames from a proxy).
func WriteFrame(w io.Writer, frame *Frame) error {
	if frame == nil {
		return errors.New("websocket: nil frame")
	}

	// Validate payload length.
	var lenByte byte
	switch {
	case len(frame.Payload) < 126:
		lenByte = byte(len(frame.Payload))
	case len(frame.Payload) <= 0xFFFF:
		lenByte = 126
	default:
		lenByte = 127
	}

	// First byte: FIN + opcode.
	hdr0 := byte(0)
	if frame.FIN {
		hdr0 |= 0x80
	}
	hdr0 |= byte(frame.Opcode & 0x0F)

	// Build header.
	var hdr []byte
	hdr = append(hdr, hdr0, lenByte)

	switch lenByte {
	case 126:
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(len(frame.Payload)))
		hdr = append(hdr, ext...)
	case 127:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(len(frame.Payload)))
		hdr = append(hdr, ext...)
	}

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("websocket: write header: %w", err)
	}
	if len(frame.Payload) > 0 {
		if _, err := w.Write(frame.Payload); err != nil {
			return fmt.Errorf("websocket: write payload: %w", err)
		}
	}
	return nil
}

// IsUpgradeRequest returns true if the HTTP request is a WebSocket upgrade.
// It checks both the Upgrade header and the Connection header per RFC 6455 §4.1.
func IsUpgradeRequest(r *http.Request) bool {
	if !headerContains(r.Header, "Connection", "upgrade") {
		return false
	}
	return headerContains(r.Header, "Upgrade", "websocket")
}

// headerContains checks if any value for the named header contains the target
// token (case-insensitive per RFC 7230 §3.2.6).
func headerContains(h http.Header, name, target string) bool {
	for _, v := range h[http.CanonicalHeaderKey(name)] {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), target) {
				return true
			}
		}
	}
	return false
}
