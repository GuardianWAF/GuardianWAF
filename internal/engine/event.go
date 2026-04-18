package engine

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UAParser is a function type for parsing User-Agent strings into structured data.
// Set via SetUAParser to avoid circular imports with the botdetect package.
type UAParser func(ua string) (browser, brVersion, os, deviceType string, isBot bool)

// GeoIPLookup is a function type for looking up country by IP.
// Set via SetGeoIPLookup to avoid circular imports with the geoip package.
type GeoIPLookup func(ip string) (countryCode, countryName string)

var (
	uaParserMu    sync.RWMutex
	uaParser      UAParser
	geoIPLookupMu sync.RWMutex
	geoIPLookup   GeoIPLookup
)

// SetUAParser registers a User-Agent parser function.
// Called once at startup from the main package after importing botdetect.
func SetUAParser(parser UAParser) {
	uaParserMu.Lock()
	defer uaParserMu.Unlock()
	uaParser = parser
}

func getUAParser() UAParser {
	uaParserMu.RLock()
	defer uaParserMu.RUnlock()
	return uaParser
}

// SetGeoIPLookup registers a GeoIP lookup function.
// Called once at startup from the main package after importing geoip.
func SetGeoIPLookup(fn GeoIPLookup) {
	geoIPLookupMu.Lock()
	defer geoIPLookupMu.Unlock()
	geoIPLookup = fn
}

func getGeoIPLookup() GeoIPLookup {
	geoIPLookupMu.RLock()
	defer geoIPLookupMu.RUnlock()
	return geoIPLookup
}

// Event represents a WAF event for logging and storage.
type Event struct {
	ID         string        `json:"id"`
	Timestamp  time.Time     `json:"timestamp"`
	RequestID  string        `json:"request_id"`
	ClientIP   string        `json:"client_ip"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	Query      string        `json:"query"`
	Action     Action        `json:"action"`
	Score      int           `json:"score"`
	Findings   []Finding     `json:"findings"`
	Duration   time.Duration `json:"duration_ns"`
	StatusCode int           `json:"status_code"`
	UserAgent  string        `json:"user_agent"`

	// Parsed User-Agent fields (populated by NewEvent)
	Browser    string `json:"browser"`
	BrVersion  string `json:"browser_version"`
	OS         string `json:"os"`
	DeviceType string `json:"device_type"`
	IsBot      bool   `json:"is_bot"`

	// GeoIP information
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`

	// Request metadata
	ContentType string `json:"content_type,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Host        string `json:"host,omitempty"`

	// Tenant identification (multi-tenancy)
	TenantID string `json:"tenant_id,omitempty"`

	// TLS information
	TLSVersion     string `json:"tls_version,omitempty"`
	TLSCipherSuite string `json:"tls_cipher,omitempty"`
	JA3Hash        string `json:"ja3_hash,omitempty"`
	JA4Fingerprint string `json:"ja4_fingerprint,omitempty"`
	ServerName     string `json:"sni,omitempty"`
}

// sensitiveQueryParamNames are redacted from event query strings to prevent
// credential leakage in logs and dashboard displays. Case-insensitive matching.
var sensitiveQueryParamNames = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"api_key": true, "apikey": true, "secret": true, "password": true, "passwd": true,
	"credential": true, "private_key": true, "auth": true, "session_id": true,
	"sessionid": true, "csrf_token": true, "xsrf_token": true, "jwt": true,
	"authorization": true, "client_secret": true, "redirect_uri": true,
}

// redactSensitiveQueryParams replaces values of sensitive query parameters with "[REDACTED]".
func redactSensitiveQueryParams(rawQuery string) string {
	if rawQuery == "" || !strings.ContainsAny(rawQuery, "=") {
		return rawQuery
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery // malformed — return as-is
	}
	changed := false
	for key := range vals {
		if sensitiveQueryParamNames[strings.ToLower(key)] {
			vals[key] = []string{"[REDACTED]"}
			changed = true
		}
	}
	if !changed {
		return rawQuery
	}
	return vals.Encode()
}// NewEvent creates an Event from a RequestContext after pipeline processing.
// statusCode is the HTTP response status code returned to the client.
func NewEvent(ctx *RequestContext, statusCode int) Event {
	var clientIP string
	if ctx.ClientIP != nil {
		clientIP = ctx.ClientIP.String()
	}

	var query string
	if ctx.Request != nil {
		query = redactSensitiveQueryParams(ctx.Request.URL.RawQuery)
	}

	var userAgent string
	if vals, ok := ctx.Headers["User-Agent"]; ok && len(vals) > 0 {
		userAgent = vals[0]
	}

	var findings []Finding
	var score int
	if ctx.Accumulator != nil {
		findings = make([]Finding, len(ctx.Accumulator.Findings()))
		copy(findings, ctx.Accumulator.Findings())
		score = ctx.Accumulator.Total()
	}

	ev := Event{
		ID:         generateRequestID(),
		Timestamp:  ctx.StartTime,
		RequestID:  ctx.RequestID,
		ClientIP:   clientIP,
		Method:     ctx.Method,
		Path:       ctx.Path,
		Query:      query,
		Action:     ctx.Action,
		Score:      score,
		Findings:   findings,
		Duration:   time.Since(ctx.StartTime),
		StatusCode: statusCode,
		UserAgent:  userAgent,
		TenantID:   ctx.TenantID,
	}

	// Parse User-Agent into structured fields
	if parser := getUAParser(); parser != nil && userAgent != "" {
		ev.Browser, ev.BrVersion, ev.OS, ev.DeviceType, ev.IsBot = parser(userAgent)
	}

	// Lookup GeoIP country information
	if lookup := getGeoIPLookup(); lookup != nil && clientIP != "" {
		ev.CountryCode, ev.CountryName = lookup(clientIP)
	}

	// Extract additional request metadata
	if vals, ok := ctx.Headers["Content-Type"]; ok && len(vals) > 0 {
		ev.ContentType = vals[0]
	}
	if vals, ok := ctx.Headers["Referer"]; ok && len(vals) > 0 {
		ev.Referer = vals[0]
	}
	if ctx.Request != nil {
		ev.Host = ctx.Request.Host
	}

	// Extract TLS information
	if ctx.TLSVersion > 0 {
		ev.TLSVersion = tlsVersionString(ctx.TLSVersion)
		ev.TLSCipherSuite = tlsCipherString(ctx.TLSCipherSuite)
		ev.ServerName = ctx.ServerName

		// Compute JA3 from available data
		if ctx.TLSCipherSuite > 0 {
			// Note: Full JA3 requires complete ClientHello data
			// This is a partial fingerprint using available info
			ev.JA3Hash = computePartialJA3(ctx.TLSVersion, ctx.TLSCipherSuite)
		}

		// Compute JA4 if we have full ClientHello data
		if len(ctx.JA4Ciphers) > 0 {
			ev.JA4Fingerprint = computeJA4FromContext(ctx)
		}
	}

	return ev
}

// tlsVersionString converts a TLS version uint16 to a human-readable string.
func tlsVersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	case 0xfeff:
		return "DTLS 1.0"
	case 0xfefd:
		return "DTLS 1.2"
	default:
		return "Unknown"
	}
}

// tlsCipherString converts a TLS cipher suite uint16 to a human-readable string.
var tlsCipherNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

func tlsCipherString(c uint16) string {
	if name, ok := tlsCipherNames[c]; ok {
		return name
	}
	return "Unknown"
}

// computePartialJA3 computes a partial JA3 hash from limited TLS info.
// This is not a full JA3 - just a fingerprint of what we have.
func computePartialJA3(version, cipher uint16) string {
	// Simple hash of version + cipher for basic fingerprinting
	// Full JA3 would require complete ClientHello data
	h := uint32(version)<<16 | uint32(cipher)
	s := strconv.FormatUint(uint64(h), 16)
		for len(s) < 8 {
			s = "0" + s
		}
		return s
}

// computeJA4FromContext computes JA4 fingerprint from RequestContext.
func computeJA4FromContext(ctx *RequestContext) string {
	// Import cycle prevention - this is a simplified version
	// The actual JA4 computation happens in the botdetect layer
	// Here we just return the pre-computed value if available
	// The full implementation would need to call the botdetect package

	// For now, construct a basic JA4 string from available data
	protocol := ctx.JA4Protocol
	if protocol == "" {
		protocol = "t"
	}

	version := "13"
	if ctx.JA4Ver > 0 {
		switch ctx.JA4Ver {
		case 0x0304:
			version = "13"
		case 0x0303:
			version = "12"
		case 0x0302:
			version = "11"
		case 0x0301:
			version = "10"
		}
	} else {
		switch ctx.TLSVersion {
		case 0x0304:
			version = "13"
		case 0x0303:
			version = "12"
		case 0x0302:
			version = "11"
		case 0x0301:
			version = "10"
		}
	}

	sni := "i"
	if ctx.JA4SNI || ctx.ServerName != "" {
		sni = "d"
	}

	cipherCount := min(len(ctx.JA4Ciphers), 99)
	extCount := min(len(ctx.JA4Exts), 99)

	alpn := ctx.JA4ALPN
	alpnCode := "00"
	if len(alpn) >= 1 {
		if len(alpn) == 1 {
			alpnCode = alpn + alpn
		} else {
			alpnCode = string(alpn[0]) + string(alpn[len(alpn)-1])
		}
	}

	// Return partial JA4 (without hashes since we need crypto package)
	return protocol + version + sni +
		padInt2(cipherCount) + padInt2(extCount) + alpnCode
}

// padInt2 zero-pads an int to 2 digits.
func padInt2(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	b := [2]byte{byte('0' + n/10), byte('0' + n%10)}
	return string(b[:])
}
