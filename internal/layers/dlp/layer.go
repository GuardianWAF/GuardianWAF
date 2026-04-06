package dlp

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer provides DLP scanning for request and response bodies.
type Layer struct {
	registry    *PatternRegistry
	config      *Config
	scanRequest bool
	scanResponse bool
}

// Config for DLP layer.
type Config struct {
	Enabled             bool     `yaml:"enabled"`
	ScanRequest         bool     `yaml:"scan_request"`          // Scan incoming request bodies
	ScanResponse        bool     `yaml:"scan_response"`         // Scan outgoing response bodies
	BlockOnMatch        bool     `yaml:"block_on_match"`        // Block request/response if PII detected
	MaskResponse        bool     `yaml:"mask_response"`         // Mask PII in response bodies
	MaxBodySize         int      `yaml:"max_body_size"`         // Max body size to scan (default: 1MB)
	MaxFileSize         int64    `yaml:"max_file_size"`         // Max file upload size (default: 10MB)
	Patterns            []string `yaml:"patterns"`              // Enabled pattern types
	ScanFileUploads     bool     `yaml:"scan_file_uploads"`     // Scan multipart file uploads
	BlockExecutableFiles bool    `yaml:"block_executable_files"` // Block executable file uploads
	BlockArchiveFiles   bool     `yaml:"block_archive_files"`   // Block archive file uploads
	CustomPatterns      map[string]string `yaml:"custom_patterns"` // Custom regex patterns
}

// DefaultConfig returns default DLP configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:              false,
		ScanRequest:          true,
		ScanResponse:         true,
		BlockOnMatch:         false,
		MaskResponse:         true,
		MaxBodySize:          1024 * 1024, // 1MB
		MaxFileSize:          10 << 20,    // 10MB
		Patterns:             []string{"credit_card", "ssn", "api_key", "private_key"},
		ScanFileUploads:      true,
		BlockExecutableFiles: true,
		BlockArchiveFiles:    false,
		CustomPatterns:       make(map[string]string),
	}
}

// NewLayer creates a new DLP layer.
func NewLayer(cfg *Config) *Layer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1024 * 1024
	}

	l := &Layer{
		registry:     NewPatternRegistry(),
		config:       cfg,
		scanRequest:  cfg.ScanRequest,
		scanResponse: cfg.ScanResponse,
	}

	// Enable configured patterns only
	l.configurePatterns(cfg.Patterns)

	return l
}

// configurePatterns enables only the specified patterns.
func (l *Layer) configurePatterns(patterns []string) {
	// First disable all
	for _, pt := range []PatternType{
		PatternCreditCard, PatternSSN, PatternIBAN, PatternEmail,
		PatternPhone, PatternAPIKey, PatternPrivateKey, PatternPassport, PatternTaxID,
	} {
		l.registry.SetEnabled(pt, false)
	}

	// Enable requested patterns
	for _, name := range patterns {
		switch name {
		case "credit_card":
			l.registry.SetEnabled(PatternCreditCard, true)
		case "ssn":
			l.registry.SetEnabled(PatternSSN, true)
		case "iban":
			l.registry.SetEnabled(PatternIBAN, true)
		case "email":
			l.registry.SetEnabled(PatternEmail, true)
		case "phone":
			l.registry.SetEnabled(PatternPhone, true)
		case "api_key":
			l.registry.SetEnabled(PatternAPIKey, true)
		case "private_key":
			l.registry.SetEnabled(PatternPrivateKey, true)
		case "passport":
			l.registry.SetEnabled(PatternPassport, true)
		case "tax_id":
			l.registry.SetEnabled(PatternTaxID, true)
		}
	}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "dlp"
}

// Order returns the layer order (runs after detection, before response).
func (l *Layer) Order() int {
	return 550
}

// Process implements the engine.Layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	result := engine.LayerResult{
		Action: engine.ActionPass,
	}

	// Scan request if enabled and request body exists
	if l.scanRequest && ctx.Request != nil {
		req := ctx.Request.Clone(ctx.Request.Context())
		scanResult, err := l.ScanRequest(req)
		if err == nil && !scanResult.Safe {
			result.Score = scanResult.RiskScore
			for _, m := range scanResult.Matches {
				result.Findings = append(result.Findings, engine.Finding{
					DetectorName: "dlp",
					Category:     "PII/PCI",
					Severity:     severityToEngine(m.Severity),
					Score:        severityScore(m.Severity),
					Description:  string(m.Type) + " detected",
					Location:     "body",
				})
			}
			if l.config.BlockOnMatch {
				result.Action = engine.ActionBlock
			}
		}
	}

	return result
}

// severityToEngine converts DLP severity to engine severity.
func severityToEngine(s Severity) engine.Severity {
	switch s {
	case SeverityCritical:
		return engine.SeverityCritical
	case SeverityHigh:
		return engine.SeverityHigh
	case SeverityMedium:
		return engine.SeverityMedium
	default:
		return engine.SeverityLow
	}
}

// severityScore returns a score based on severity.
func severityScore(s Severity) int {
	switch s {
	case SeverityCritical:
		return 40
	case SeverityHigh:
		return 30
	case SeverityMedium:
		return 15
	default:
		return 5
	}
}

// ScanRequest scans an HTTP request body for sensitive data.
func (l *Layer) ScanRequest(r *http.Request) (*ScanResult, error) {
	if !l.config.Enabled || !l.scanRequest {
		return &ScanResult{Safe: true}, nil
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if !isScannableContent(contentType) {
		return &ScanResult{Safe: true}, nil
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(l.config.MaxBodySize)))
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// Scan body
	return l.scanContent(string(body)), nil
}

// ScanResponse scans an HTTP response body for sensitive data.
func (l *Layer) ScanResponse(body []byte, contentType string) (*ScanResult, []byte) {
	if !l.config.Enabled || !l.scanResponse {
		return &ScanResult{Safe: true}, body
	}

	if !isScannableContent(contentType) {
		return &ScanResult{Safe: true}, body
	}

	if len(body) > l.config.MaxBodySize {
		// Body too large, skip scanning
		return &ScanResult{Safe: true}, body
	}

	result := l.scanContent(string(body))

	// Mask response if configured
	if l.config.MaskResponse && len(result.Matches) > 0 {
		masked := l.maskContent(string(body), result.Matches)
		return result, []byte(masked)
	}

	return result, body
}

// ScanResult contains the results of a DLP scan.
type ScanResult struct {
	Safe      bool
	Matches   []Match
	RiskScore int
}

// scanContent scans text content for sensitive patterns.
func (l *Layer) scanContent(content string) *ScanResult {
	matches := l.registry.Scan(content)

	if len(matches) == 0 {
		return &ScanResult{Safe: true, Matches: []Match{}}
	}

	// Calculate risk score based on severity
	riskScore := 0
	for _, m := range matches {
		switch m.Severity {
		case SeverityCritical:
			riskScore += 40
		case SeverityHigh:
			riskScore += 30
		case SeverityMedium:
			riskScore += 15
		case SeverityLow:
			riskScore += 5
		}
	}

	return &ScanResult{
		Safe:      false,
		Matches:   matches,
		RiskScore: riskScore,
	}
}

// maskContent masks sensitive data in content.
func (l *Layer) maskContent(content string, matches []Match) string {
	result := content

	// Sort matches by position (descending) to avoid offset issues
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		if m.Position < len(result) && m.Position+m.Length <= len(result) {
			result = result[:m.Position] + m.Masked + result[m.Position+m.Length:]
		}
	}

	return result
}

// isScannableContent checks if the content type should be scanned.
func isScannableContent(contentType string) bool {
	contentType = strings.ToLower(contentType)

	// Text-based content types
	scannable := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/x-www-form-urlencoded",
		"application/graphql",
		"multipart/form-data",
	}

	for _, prefix := range scannable {
		if strings.Contains(contentType, prefix) {
			return true
		}
	}

	return false
}

// GetRegistry returns the pattern registry for configuration.
func (l *Layer) GetRegistry() *PatternRegistry {
	return l.registry
}

// EnablePattern enables a specific pattern.
func (l *Layer) EnablePattern(patternType PatternType) {
	l.registry.SetEnabled(patternType, true)
}

// DisablePattern disables a specific pattern.
func (l *Layer) DisablePattern(patternType PatternType) {
	l.registry.SetEnabled(patternType, false)
}

// AddCustomPattern adds a custom pattern to the registry.
func (l *Layer) AddCustomPattern(name string, pattern *Pattern) {
	l.registry.AddCustomPattern(name, pattern.Regex, pattern.Severity, pattern.MaskFormat)
}

// ScanFileUploads scans multipart file uploads for sensitive content.
func (l *Layer) ScanFileUploads(body []byte, contentType string) (*ScanResult, error) {
	if !l.config.Enabled || !l.config.ScanFileUploads {
		return &ScanResult{Safe: true}, nil
	}

	// Parse multipart form
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return &ScanResult{Safe: true}, nil
	}

	boundary := params["boundary"]
	if boundary == "" {
		return &ScanResult{Safe: true}, nil
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	allMatches := make([]Match, 0)
	totalRiskScore := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		filename := part.FileName()
		if filename == "" {
			continue // Not a file upload
		}

		// Check file type restrictions
		if l.config.BlockExecutableFiles && isExecutableFile(filename) {
			allMatches = append(allMatches, Match{
				Type:     PatternCustom,
				Severity: SeverityHigh,
				Value:    filename,
				Masked:   "[EXECUTABLE_FILE_BLOCKED]",
			})
			totalRiskScore += 50
			continue
		}

		if l.config.BlockArchiveFiles && isArchiveFile(filename) {
			allMatches = append(allMatches, Match{
				Type:     PatternCustom,
				Severity: SeverityMedium,
				Value:    filename,
				Masked:   "[ARCHIVE_FILE_BLOCKED]",
			})
			totalRiskScore += 30
			continue
		}

		// Read file content
		partData, err := io.ReadAll(io.LimitReader(part, l.config.MaxFileSize+1))
		if err != nil {
			continue
		}

		if int64(len(partData)) > l.config.MaxFileSize {
			allMatches = append(allMatches, Match{
				Type:     PatternCustom,
				Severity: SeverityLow,
				Value:    filename,
				Masked:   "[FILE_TOO_LARGE]",
			})
			continue
		}

		// Scan file content
		if isTextContent(part.Header.Get("Content-Type")) || isTextFile(filename) {
			result := l.scanContent(string(partData))
			if !result.Safe {
				allMatches = append(allMatches, result.Matches...)
				totalRiskScore += result.RiskScore
			}
		}
	}

	if len(allMatches) > 0 {
		return &ScanResult{
			Safe:      false,
			Matches:   allMatches,
			RiskScore: totalRiskScore,
		}, nil
	}

	return &ScanResult{Safe: true}, nil
}

// isExecutableFile checks if a file is executable based on extension.
func isExecutableFile(filename string) bool {
	exeExts := []string{".exe", ".dll", ".bat", ".cmd", ".sh", ".bin", ".msi", ".apk", ".app", ".dmg", ".pkg", ".deb", ".rpm"}
	lowerName := strings.ToLower(filename)
	for _, ext := range exeExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

// isArchiveFile checks if a file is an archive based on extension.
func isArchiveFile(filename string) bool {
	archiveExts := []string{".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz", ".tar.gz", ".tgz", ".tar.bz2"}
	lowerName := strings.ToLower(filename)
	for _, ext := range archiveExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

// isTextContent checks if the content type is text-based.
func isTextContent(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "application/javascript")
}

// isTextFile checks if the file is a text file based on extension.
func isTextFile(filename string) bool {
	textExts := []string{".txt", ".json", ".xml", ".csv", ".log", ".md", ".yaml", ".yml", ".properties", ".conf", ".ini", ".html", ".htm", ".js", ".css"}
	lowerName := strings.ToLower(filename)
	for _, ext := range textExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}
