// Package clientside provides client-side protection against Magecart and other client-side attacks.
package clientside

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer implements the engine.Layer interface for client-side protection.
type Layer struct {
	config    *Config
	patterns  *CompiledPatterns
	stats     Stats
	mu        sync.RWMutex
	enabled   bool
}

// Stats holds client-side protection statistics.
type Stats struct {
	ScannedResponses  int
	ThreatsDetected   int
	ScriptsInjected   int
	CSPEnforced       int
	BlockedRequests   int
}

// NewLayer creates a new client-side protection layer.
func NewLayer(cfg *Config) *Layer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Ensure known skimming domains are loaded
	if len(cfg.MagecartDetection.KnownSkimmingDomains) == 0 {
		cfg.MagecartDetection.KnownSkimmingDomains = DefaultKnownSkimmingDomains()
	}

	return &Layer{
		config:   cfg,
		patterns: CompilePatterns(&cfg.MagecartDetection),
		enabled:  cfg.Enabled,
	}
}

// Name returns "clientside".
func (l *Layer) Name() string { return "clientside" }

// SetEnabled enables or disables the layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.enabled = enabled
}

// Process analyzes requests for client-side threats and registers response hooks.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Check exclusions
	for _, path := range l.config.Exclusions {
		if strings.HasPrefix(ctx.Path, path) {
			return engine.LayerResult{Action: engine.ActionPass}
		}
	}

	// Initialize metadata
	if ctx.Metadata == nil {
		ctx.Metadata = make(map[string]any)
	}

	// Register CSP headers if enabled
	if l.config.CSP.Enabled {
		headerName, headerValue := l.GetCSPHeader()
		ctx.Metadata["csp_header_name"] = headerName
		ctx.Metadata["csp_header_value"] = headerValue

		// Register hook for applying CSP headers
		ctx.Metadata["clientside_csp_hook"] = func(w http.ResponseWriter) {
			if headerName != "" && headerValue != "" {
				w.Header().Set(headerName, headerValue)
				l.mu.Lock()
				l.stats.CSPEnforced++
				l.mu.Unlock()
			}
		}
	}

	// Register response body processing hook if enabled
	if l.config.MagecartDetection.Enabled || l.config.AgentInjection.Enabled {
		ctx.Metadata["clientside_response_hook"] = func(body []byte, contentType string) ([]byte, bool) {
			return l.processResponse(body, contentType, ctx.Path)
		}
	}

	return engine.LayerResult{
		Action: engine.ActionPass,
	}
}

// processResponse processes the response body for threats and injections.
func (l *Layer) processResponse(body []byte, contentType, path string) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}

	l.mu.Lock()
	l.stats.ScannedResponses++
	l.mu.Unlock()

	modified := false

	// Check content type
	ct := strings.ToLower(contentType)
	isHTML := strings.Contains(ct, "text/html")
	isJS := strings.Contains(ct, "application/javascript") || strings.Contains(ct, "text/javascript")

	// Analyze for Magecart threats in JS/HTML content
	if l.config.MagecartDetection.Enabled && (isHTML || isJS) {
		detectionResult := l.analyzeResponseBody(body)
		if detectionResult.Detected {
			l.mu.Lock()
			l.stats.ThreatsDetected++
			l.mu.Unlock()

			// In block mode, we don't return the body
			if l.config.Mode == "block" {
				l.mu.Lock()
				l.stats.BlockedRequests++
				l.mu.Unlock()
				return []byte("<!-- Blocked by Client-Side Protection -->"), true
			}
		}
	}

	// Inject security agent into HTML responses
	if l.config.AgentInjection.Enabled && isHTML && l.shouldInject(path) {
		body = l.InjectAgent(body)
		modified = true
		l.mu.Lock()
		l.stats.ScriptsInjected++
		l.mu.Unlock()
	}

	return body, modified
}

// analyzeResponseBody scans response body for Magecart threats.
func (l *Layer) analyzeResponseBody(body []byte) DetectionResult {
	result := DetectionResult{
		Detected:  false,
		Matches:   make([]PatternMatch, 0),
		Timestamp: time.Now(),
	}

	bodyStr := string(body)
	score := 0

	// Check for obfuscated JavaScript
	if l.config.MagecartDetection.DetectObfuscatedJS {
		for _, pattern := range l.patterns.ObfuscationPatterns {
			if matches := pattern.FindAllStringIndex(bodyStr, -1); matches != nil {
				for _, match := range matches {
					matchedText := bodyStr[match[0]:minInt(match[1], match[0]+50)]
					result.Matches = append(result.Matches, PatternMatch{
						Pattern:     "obfuscated_js",
						MatchedText: matchedText,
						Position:    match[0],
						Severity:    "medium",
					})
					score += 10
				}
			}
		}
	}

	// Check for suspicious domains
	if l.config.MagecartDetection.DetectSuspiciousDomains {
		for _, pattern := range l.patterns.SkimmingPatterns {
			if matches := pattern.FindAllStringIndex(bodyStr, -1); matches != nil {
				for _, match := range matches {
					matched := bodyStr[match[0]:minInt(match[1], match[0]+100)]
					severity := "medium"
					if l.isKnownSkimmingDomain(matched) {
						severity = "critical"
						score += 30
					} else {
						score += 15
					}

					result.Matches = append(result.Matches, PatternMatch{
						Pattern:     "suspicious_domain",
						MatchedText: matched,
						Position:    match[0],
						Severity:    severity,
					})
				}
			}
		}
	}

	// Check for keyloggers
	if l.config.MagecartDetection.DetectKeyloggers {
		for _, pattern := range l.patterns.KeyloggerPatterns {
			if matches := pattern.FindAllStringIndex(bodyStr, -1); matches != nil {
				for _, match := range matches {
					matchedText := bodyStr[match[0]:minInt(match[1], match[0]+50)]
					result.Matches = append(result.Matches, PatternMatch{
						Pattern:     "keylogger",
						MatchedText: matchedText,
						Position:    match[0],
						Severity:    "high",
					})
					score += 25
				}
			}
		}
	}

	// Check for form exfiltration
	if l.config.MagecartDetection.DetectFormExfiltration {
		for _, pattern := range l.patterns.FormExfilPatterns {
			if matches := pattern.FindAllStringIndex(bodyStr, -1); matches != nil {
				for _, match := range matches {
					matchedText := bodyStr[match[0]:minInt(match[1], match[0]+50)]
					result.Matches = append(result.Matches, PatternMatch{
						Pattern:     "form_exfiltration",
						MatchedText: matchedText,
						Position:    match[0],
						Severity:    "high",
					})
					score += 20
				}
			}
		}
	}

	if score > 0 {
		result.Detected = true
		result.Score = minInt(score, 100)

		// Determine threat type
		if len(result.Matches) > 0 {
			result.ThreatType = result.Matches[0].Pattern
			for _, m := range result.Matches {
				if m.Severity == "critical" {
					result.ThreatType = "magecart_attack"
					break
				}
			}
		}
	}

	return result
}

// isKnownSkimmingDomain checks if the text contains a known skimming domain.
func (l *Layer) isKnownSkimmingDomain(text string) bool {
	for domain := range l.patterns.KnownSkimmingDomains {
		if strings.Contains(text, domain) {
			return true
		}
	}
	return false
}

// shouldInject checks if we should inject the agent for this path.
func (l *Layer) shouldInject(path string) bool {
	if len(l.config.AgentInjection.ProtectedPaths) == 0 {
		return true
	}

	for _, protected := range l.config.AgentInjection.ProtectedPaths {
		if strings.HasPrefix(path, protected) {
			return true
		}
	}
	return false
}

// InjectAgent injects the security monitoring agent into HTML responses.
func (l *Layer) InjectAgent(body []byte) []byte {
	if !l.config.AgentInjection.Enabled {
		return body
	}

	bodyStr := string(body)

	// Check if already injected
	if strings.Contains(bodyStr, l.config.AgentInjection.ScriptURL) {
		return body
	}

	// Generate agent script
	agentScript := l.generateAgentScript()

	// Inject based on position
	switch l.config.AgentInjection.InjectPosition {
	case "head":
		// Inject before </head>
		if idx := strings.Index(bodyStr, "</head>"); idx != -1 {
			return []byte(bodyStr[:idx] + agentScript + bodyStr[idx:])
		}
	case "body-end":
		// Inject before </body>
		if idx := strings.Index(bodyStr, "</body>"); idx != -1 {
			return []byte(bodyStr[:idx] + agentScript + bodyStr[idx:])
		}
	default:
		// Default: inject after <head> or at start of <body>
		if idx := strings.Index(bodyStr, "<head>"); idx != -1 {
			headEnd := idx + len("<head>")
			return []byte(bodyStr[:headEnd] + agentScript + bodyStr[headEnd:])
		}
	}

	// If no suitable injection point found, prepend to body
	return append([]byte(agentScript), body...)
}

// generateAgentScript generates the security monitoring agent JavaScript.
func (l *Layer) generateAgentScript() string {
	if !l.config.AgentInjection.Enabled {
		return ""
	}

	script := `<script data-guardian="security-agent">(function(){`

	// DOM monitoring
	if l.config.AgentInjection.MonitorDOM {
		script += `
		var observer = new MutationObserver(function(mutations) {
			mutations.forEach(function(mutation) {
				if (mutation.type === 'childList') {
					mutation.addedNodes.forEach(function(node) {
						if (node.tagName === 'SCRIPT') {
							console.log('[GuardianWAF] Script injected:', node.src || 'inline');
						}
					});
				}
			});
		});
		if (document.body) observer.observe(document.body, { childList: true, subtree: true });
		`
	}

	// Form monitoring
	if l.config.AgentInjection.MonitorForms {
		script += `
		document.querySelectorAll('form').forEach(function(form) {
			form.addEventListener('submit', function(e) {
				console.log('[GuardianWAF] Form submit:', form.action);
			});
		});
		`
	}

	// Network monitoring
	if l.config.AgentInjection.MonitorNetwork {
		script += `
		var originalFetch = window.fetch;
		window.fetch = function(...args) {
			console.log('[GuardianWAF] Fetch:', args[0]);
			return originalFetch.apply(this, args);
		};
		if (window.XMLHttpRequest) {
			var originalXHROpen = XMLHttpRequest.prototype.open;
			XMLHttpRequest.prototype.open = function(...args) {
				console.log('[GuardianWAF] XHR:', args[1]);
				return originalXHROpen.apply(this, args);
			};
		}
		`
	}

	script += `})();</script>`

	return script
}

// GetCSPHeader returns the CSP header value.
func (l *Layer) GetCSPHeader() (headerName, headerValue string) {
	if !l.config.CSP.Enabled {
		return "", ""
	}

	directives := make([]string, 0)

	// Build directives
	if len(l.config.CSP.DefaultSrc) > 0 {
		directives = append(directives, "default-src "+strings.Join(l.config.CSP.DefaultSrc, " "))
	}
	if len(l.config.CSP.ScriptSrc) > 0 {
		directives = append(directives, "script-src "+strings.Join(l.config.CSP.ScriptSrc, " "))
	}
	if len(l.config.CSP.StyleSrc) > 0 {
		directives = append(directives, "style-src "+strings.Join(l.config.CSP.StyleSrc, " "))
	}
	if len(l.config.CSP.ImgSrc) > 0 {
		directives = append(directives, "img-src "+strings.Join(l.config.CSP.ImgSrc, " "))
	}
	if len(l.config.CSP.ConnectSrc) > 0 {
		directives = append(directives, "connect-src "+strings.Join(l.config.CSP.ConnectSrc, " "))
	}
	if len(l.config.CSP.FontSrc) > 0 {
		directives = append(directives, "font-src "+strings.Join(l.config.CSP.FontSrc, " "))
	}
	if len(l.config.CSP.ObjectSrc) > 0 {
		directives = append(directives, "object-src "+strings.Join(l.config.CSP.ObjectSrc, " "))
	}
	if len(l.config.CSP.MediaSrc) > 0 {
		directives = append(directives, "media-src "+strings.Join(l.config.CSP.MediaSrc, " "))
	}
	if len(l.config.CSP.FrameSrc) > 0 {
		directives = append(directives, "frame-src "+strings.Join(l.config.CSP.FrameSrc, " "))
	}
	if len(l.config.CSP.FrameAncestors) > 0 {
		directives = append(directives, "frame-ancestors "+strings.Join(l.config.CSP.FrameAncestors, " "))
	}
	if len(l.config.CSP.FormAction) > 0 {
		directives = append(directives, "form-action "+strings.Join(l.config.CSP.FormAction, " "))
	}
	if len(l.config.CSP.BaseURI) > 0 {
		directives = append(directives, "base-uri "+strings.Join(l.config.CSP.BaseURI, " "))
	}
	if l.config.CSP.ReportURI != "" {
		directives = append(directives, "report-uri "+l.config.CSP.ReportURI)
	}
	if l.config.CSP.UpgradeInsecure {
		directives = append(directives, "upgrade-insecure-requests")
	}

	if l.config.CSP.ReportOnly {
		return "Content-Security-Policy-Report-Only", strings.Join(directives, "; ")
	}
	return "Content-Security-Policy", strings.Join(directives, "; ")
}

// GetStats returns current statistics.
func (l *Layer) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.stats
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
