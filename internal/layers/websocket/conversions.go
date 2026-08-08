package websocket

import "encoding/binary"

// These helpers centralize integer conversions that gosec flags as G115
// (integer overflow). Each conversion is provably safe given the WebSocket
// frame format constraints, but gosec's static analysis cannot prove the
// bounds. The // #nosec G115 directive suppresses the false positive.

// uint16ToPayloadLen reads a 2-byte big-endian uint16 from ext and returns it
// as int64. Maximum value is 65535, which fits in int64 without overflow.
func uint16ToPayloadLen(ext []byte) int64 {
	return int64(binary.BigEndian.Uint16(ext)) // #nosec G115 -- max 65535 fits int64
}

// lenToUint16 converts an int payload length to uint16 for the WebSocket frame
// header. Caller must ensure n <= 65535.
func lenToUint16(n int) uint16 {
	return uint16(n) // #nosec G115 -- caller guarantees n <= 65535
}

// lenToUint64 converts an int payload length to uint64 for the WebSocket frame
// header. Safe widening conversion on all supported platforms.
func lenToUint64(n int) uint64 {
	return uint64(n) // #nosec G115 -- int→uint64 widening is safe on 64-bit
}

// maxInt64 is the maximum value of int64, used to guard uint64→int64 conversion.
const maxInt64 = 1<<63 - 1
