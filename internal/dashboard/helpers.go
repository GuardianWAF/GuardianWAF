package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Helpers ---

func handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON marshals v before writing the status code so that an encoding
// failure can still produce a proper 500 instead of a 200 with a truncated,
// invalid body. Encoding failures are logged rather than silently dropped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		dashboardLog.Error("response encode failed", "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal encoding error"}`)) // nolint:errcheck // error response; error ignored
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf) // nolint:errcheck // download write; error ignored
}

// writeError writes a JSON error response with the standard {"error": ...}
// envelope used across the dashboard API.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

const maxRequestBody = 1 << 20 // 1MB max request body for API endpoints

// decodeJSON limits the request body size and decodes JSON.
func limitedDecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeDashboardJSONDecodeError(w, err)
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeDashboardJSONDecodeError(w, err)
		return false
	}
	return true
}

func writeDashboardJSONDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid JSON")
}

func formatFindings(findings []engine.Finding) []map[string]any {
	result := make([]map[string]any, len(findings))
	for i, f := range findings {
		result[i] = map[string]any{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
			"confidence":  f.Confidence,
		}
	}
	return result
}

// clampInt clamps v to [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampInt64 clamps v to [lo, hi].
func clampInt64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampFloat clamps v to [lo, hi].
func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// sanitizeErr strips potentially sensitive details from error messages
// before returning them to clients. It targets absolute file paths and
// stack traces while preserving useful context like network errors and
// relative paths.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip stack trace indicators
	if strings.Contains(msg, "goroutine") || strings.Contains(msg, "runtime/") {
		return "internal error"
	}
	// Redact absolute file system paths (Unix and Windows)
	msg = redactFilePaths(msg)
	// Truncate very long errors
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// redactFilePaths replaces absolute filesystem paths with a placeholder.
// Matches common Unix prefixes (/etc/, /home/, /var/, /tmp/, /usr/, /opt/)
// and Windows drive-letter paths (C:\, D:\, etc.).
var pathPrefixes = []string{
	"/etc/", "/home/", "/var/", "/tmp/", "/usr/", "/opt/", "/root/",
	"/proc/", "/sys/", "/dev/",
}

func redactFilePaths(msg string) string {
	for _, prefix := range pathPrefixes {
		if idx := strings.Index(msg, prefix); idx >= 0 {
			// Find the end of the path (next space or end of string)
			end := idx + len(prefix)
			for end < len(msg) && msg[end] != ' ' && msg[end] != '"' && msg[end] != '\'' {
				end++
			}
			msg = msg[:idx] + "<redacted>" + msg[end:]
		}
	}
	// Windows paths: C:\... D:\... etc.
	if len(msg) >= 3 && msg[1] == ':' && (msg[2] == '\\' || msg[2] == '/') {
		for i := 0; i < len(msg)-3; i++ {
			if i > 0 && msg[i-1] == ' ' && isASCIILetter(msg[i]) && msg[i+1] == ':' && (msg[i+2] == '\\' || msg[i+2] == '/') {
				end := i + 3
				for end < len(msg) && msg[end] != ' ' && msg[end] != '"' && msg[end] != '\'' {
					end++
				}
				msg = msg[:i] + "<redacted>" + msg[end:]
			}
		}
	}
	return msg
}

func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// deepCopyConfig creates a deep copy of the config using the generated
// DeepCopy method. This prevents shared mutable state between the dashboard
// and engine without the allocation overhead of JSON round-trip.
func deepCopyConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	return cfg.DeepCopy()
}
