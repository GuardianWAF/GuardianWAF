package tracing

import "strings"

// TraceparentHeader is the W3C Trace Context request header.
const TraceparentHeader = "Traceparent"

// ParseTraceparent extracts the trace and parent span IDs from a W3C
// traceparent header ("00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>").
// It rejects malformed values, all-zero IDs and version ff. Headers of a
// future version are accepted when their first four fields have the version
// 00 shape, as the specification requires.
func ParseTraceparent(h string) (traceID, parentID string, ok bool) {
	h = strings.TrimSpace(h)
	if len(h) < 55 {
		return "", "", false
	}
	version := h[:2]
	if !isLowerHex(version) || version == "ff" {
		return "", "", false
	}
	if len(h) > 55 && (version == "00" || h[55] != '-') {
		return "", "", false
	}
	if h[2] != '-' || h[35] != '-' || h[52] != '-' {
		return "", "", false
	}
	traceID, parentID, flags := h[3:35], h[36:52], h[53:55]
	if !isLowerHex(traceID) || !isLowerHex(parentID) || !isLowerHex(flags) {
		return "", "", false
	}
	if allZero(traceID) || allZero(parentID) {
		return "", "", false
	}
	return traceID, parentID, true
}

// FormatTraceparent builds a version 00 traceparent for a sampled span.
func FormatTraceparent(traceID, spanID string) string {
	return "00-" + traceID + "-" + spanID + "-01"
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

func allZero(s string) bool {
	return strings.Trim(s, "0") == ""
}
