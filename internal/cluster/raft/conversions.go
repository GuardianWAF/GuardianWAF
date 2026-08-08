package raft

// These helpers centralize integer conversions that gosec flags as G115
// (integer overflow). Each conversion is provably safe given the Raft log
// size constraints (bounded by memory), but gosec's static analysis cannot
// prove the bounds. The // #nosec G115 directive suppresses the false positive.

// lenToUint64 converts an int length to uint64. Safe widening conversion on
// all supported platforms.
func lenToUint64(n int) uint64 {
	return uint64(n) // #nosec G115 -- int→uint64 widening is safe on 64-bit
}

// uint64ToInt converts a uint64 log index to int for slice indexing.
// The value is always bounded by len(entries) (in-memory log), which is
// itself bounded by available memory. On 64-bit platforms int is 64 bits.
func uint64ToInt(n uint64) int {
	return int(n) // #nosec G115 -- bounded by len(entries), safe on 64-bit
}
