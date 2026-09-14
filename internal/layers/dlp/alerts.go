package dlp

import (
	"strconv"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// maxAlerts bounds the in-layer alert history; the oldest alerts drop first.
const maxAlerts = 1000

// Alert is one recorded DLP detection, surfaced by the dashboard and MCP
// alert endpoints. MatchedValue carries the pattern's MASKED form only —
// echoing the raw value would leak exactly the data DLP exists to protect.
type Alert struct {
	ID           string
	Timestamp    int64
	PatternType  string
	PatternName  string
	ClientIP     string
	Path         string
	MatchedValue string
	Action       string
}

// recordAlerts appends one alert per detection to the bounded history under
// the layer lock. Only scans that produced matches call this. The pattern
// name mirrors the dashboard's own pattern mapping: built-in patterns are
// identified by their type string, and custom patterns share the "custom"
// type.
func (l *Layer) recordAlerts(matches []Match, action, clientIP, path string) {
	if len(matches) == 0 {
		return
	}
	now := time.Now().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range matches {
		l.alertSeq++
		l.alerts = append(l.alerts, Alert{
			ID:           "dlp-" + strconv.FormatUint(l.alertSeq, 10),
			Timestamp:    now,
			PatternType:  string(m.Type),
			PatternName:  string(m.Type),
			ClientIP:     clientIP,
			Path:         path,
			MatchedValue: m.Masked,
			Action:       action,
		})
	}
	if len(l.alerts) > maxAlerts {
		l.alerts = l.alerts[len(l.alerts)-maxAlerts:]
	}
}

// GetAlerts returns a copy of the recorded alert history, optionally
// filtered by pattern type ("" = all), oldest-first, tail-limited to the
// limit most recent entries when limit is positive.
func (l *Layer) GetAlerts(limit int, patternType string) []Alert {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Alert, 0, len(l.alerts))
	for _, a := range l.alerts {
		if patternType != "" && a.PatternType != patternType {
			continue
		}
		out = append(out, a)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// clientIPString renders the engine-resolved client IP, or "" when absent.
func clientIPString(ctx *engine.RequestContext) string {
	if ctx == nil || ctx.ClientIP == nil {
		return ""
	}
	return ctx.ClientIP.String()
}
