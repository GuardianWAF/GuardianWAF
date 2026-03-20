package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ValidationError holds all config validation errors.
type ValidationError struct {
	Errors []FieldError
}

// Error implements the error interface, formatting all collected validation errors.
func (ve *ValidationError) Error() string {
	n := len(ve.Errors)
	var b strings.Builder
	fmt.Fprintf(&b, "config validation failed: %d error", n)
	if n != 1 {
		b.WriteByte('s')
	}
	for _, fe := range ve.Errors {
		b.WriteString("\n  - ")
		b.WriteString(fe.Error())
	}
	return b.String()
}

// HasErrors returns true if there are any validation errors.
func (ve *ValidationError) HasErrors() bool { return len(ve.Errors) > 0 }

// FieldError represents a single validation error with its field path.
type FieldError struct {
	Field   string // e.g. "waf.detection.threshold.block"
	Message string
}

// Error implements the error interface.
func (fe FieldError) Error() string { return fmt.Sprintf("%s: %s", fe.Field, fe.Message) }

// addError is a helper to append a FieldError.
func (ve *ValidationError) addError(field, message string) {
	ve.Errors = append(ve.Errors, FieldError{Field: field, Message: message})
}

// LoadFile reads a YAML config file, parses it, and returns a populated Config.
// Starts with defaults, then overlays values from the file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	node, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		return nil, fmt.Errorf("populating config: %w", err)
	}

	return cfg, nil
}

// LoadEnv overlays environment variables onto the config.
// Env var format: GWAF_<SECTION>_<KEY>=<value>
// Examples:
//
//	GWAF_MODE=monitor
//	GWAF_LISTEN=:9090
//	GWAF_WAF_DETECTION_THRESHOLD_BLOCK=60
//	GWAF_LOGGING_LEVEL=debug
func LoadEnv(cfg *Config) {
	envMap := map[string]func(string){
		"GWAF_MODE":   func(v string) { cfg.Mode = v },
		"GWAF_LISTEN": func(v string) { cfg.Listen = v },

		"GWAF_LOGGING_LEVEL":  func(v string) { cfg.Logging.Level = v },
		"GWAF_LOGGING_FORMAT": func(v string) { cfg.Logging.Format = v },
		"GWAF_LOGGING_OUTPUT": func(v string) { cfg.Logging.Output = v },

		"GWAF_WAF_DETECTION_THRESHOLD_BLOCK": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.WAF.Detection.Threshold.Block = i
			}
		},
		"GWAF_WAF_DETECTION_THRESHOLD_LOG": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.WAF.Detection.Threshold.Log = i
			}
		},

		"GWAF_DASHBOARD_LISTEN":  func(v string) { cfg.Dashboard.Listen = v },
		"GWAF_DASHBOARD_API_KEY": func(v string) { cfg.Dashboard.APIKey = v },
		"GWAF_DASHBOARD_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Dashboard.Enabled = b
			}
		},

		"GWAF_EVENTS_STORAGE":   func(v string) { cfg.Events.Storage = v },
		"GWAF_EVENTS_FILE_PATH": func(v string) { cfg.Events.FilePath = v },
		"GWAF_EVENTS_MAX_EVENTS": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.Events.MaxEvents = i
			}
		},

		"GWAF_TLS_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.TLS.Enabled = b
			}
		},
		"GWAF_TLS_LISTEN":    func(v string) { cfg.TLS.Listen = v },
		"GWAF_TLS_CERT_FILE": func(v string) { cfg.TLS.CertFile = v },
		"GWAF_TLS_KEY_FILE":  func(v string) { cfg.TLS.KeyFile = v },
	}
	for key, setter := range envMap {
		if val := os.Getenv(key); val != "" {
			setter(val)
		}
	}
}

// Validate checks the config for errors and returns all errors at once.
// Errors are collected rather than failing on the first issue.
func Validate(cfg *Config) error {
	ve := &ValidationError{}

	// Mode validation
	validateMode(cfg, ve)

	// Listen address validation
	validateListenAddr(cfg.Listen, "listen", ve)

	// TLS validation
	validateTLS(&cfg.TLS, ve)

	// Upstream validation
	validateUpstreams(cfg.Upstreams, ve)

	// Route validation (cross-reference upstream names)
	validateRoutes(cfg.Routes, cfg.Upstreams, ve)

	// WAF validation
	validateWAF(&cfg.WAF, ve)

	// Dashboard validation
	validateDashboard(&cfg.Dashboard, ve)

	// Logging validation
	validateLogging(&cfg.Logging, ve)

	// Events validation
	validateEvents(&cfg.Events, ve)

	// Virtual hosts validation
	validateVirtualHosts(cfg.VirtualHosts, cfg.Upstreams, ve)

	if ve.HasErrors() {
		return ve
	}
	return nil
}

// --- Validation helper functions ---

func validateMode(cfg *Config, ve *ValidationError) {
	switch cfg.Mode {
	case "enforce", "monitor", "disabled":
		// valid
	default:
		ve.addError("mode", fmt.Sprintf("must be one of: enforce, monitor, disabled; got %q", cfg.Mode))
	}
}

func validateListenAddr(addr, field string, ve *ValidationError) {
	if addr == "" {
		ve.addError(field, "must not be empty")
		return
	}
	// net.SplitHostPort handles ":8088", "0.0.0.0:8088", "[::1]:8088", etc.
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		ve.addError(field, fmt.Sprintf("invalid host:port format %q: %v", addr, err))
		return
	}
	if port == "" {
		ve.addError(field, "port must not be empty")
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		ve.addError(field, fmt.Sprintf("port must be a number between 0 and 65535; got %q", port))
	}
}

func validateTLS(tls *TLSConfig, ve *ValidationError) {
	if !tls.Enabled {
		return
	}

	// If ACME is not enabled, cert/key files are required
	if !tls.ACME.Enabled {
		if tls.CertFile == "" {
			ve.addError("tls.cert_file", "must not be empty when TLS is enabled without ACME")
		}
		if tls.KeyFile == "" {
			ve.addError("tls.key_file", "must not be empty when TLS is enabled without ACME")
		}
	}

	// If ACME is enabled, email and domains are required
	if tls.ACME.Enabled {
		if tls.ACME.Email == "" {
			ve.addError("tls.acme.email", "must not be empty when ACME is enabled")
		}
		if len(tls.ACME.Domains) == 0 {
			ve.addError("tls.acme.domains", "must have at least one domain when ACME is enabled")
		}
	}

	// Validate TLS listen address if present
	if tls.Listen != "" {
		validateListenAddr(tls.Listen, "tls.listen", ve)
	}
}

func validateUpstreams(upstreams []UpstreamConfig, ve *ValidationError) {
	for i, u := range upstreams {
		prefix := fmt.Sprintf("upstreams[%d]", i)
		if u.Name == "" {
			ve.addError(prefix+".name", "must not be empty")
		}
		for j, t := range u.Targets {
			tPrefix := fmt.Sprintf("%s.targets[%d]", prefix, j)
			if t.URL == "" {
				ve.addError(tPrefix+".url", "must not be empty")
			}
			if t.Weight <= 0 {
				ve.addError(tPrefix+".weight", fmt.Sprintf("must be > 0; got %d", t.Weight))
			}
		}
	}
}

func validateRoutes(routes []RouteConfig, upstreams []UpstreamConfig, ve *ValidationError) {
	// Build set of known upstream names
	upstreamNames := make(map[string]bool, len(upstreams))
	for _, u := range upstreams {
		upstreamNames[u.Name] = true
	}

	for i, r := range routes {
		prefix := fmt.Sprintf("routes[%d]", i)
		if r.Path == "" {
			ve.addError(prefix+".path", "must not be empty")
		} else if !strings.HasPrefix(r.Path, "/") {
			ve.addError(prefix+".path", fmt.Sprintf("must start with '/'; got %q", r.Path))
		}
		if r.Upstream != "" && len(upstreams) > 0 && !upstreamNames[r.Upstream] {
			ve.addError(prefix+".upstream", fmt.Sprintf("references unknown upstream %q", r.Upstream))
		}
	}
}

func validateWAF(waf *WAFConfig, ve *ValidationError) {
	validateDetection(&waf.Detection, ve)
	validateRateLimit(&waf.RateLimit, ve)
	validateIPACL(&waf.IPACL, ve)
	validateSanitizer(&waf.Sanitizer, ve)
}

func validateDetection(det *DetectionConfig, ve *ValidationError) {
	if !det.Enabled {
		return
	}
	if det.Threshold.Block <= 0 {
		ve.addError("waf.detection.threshold.block", fmt.Sprintf("must be > 0; got %d", det.Threshold.Block))
	}
	if det.Threshold.Log <= 0 {
		ve.addError("waf.detection.threshold.log", fmt.Sprintf("must be > 0; got %d", det.Threshold.Log))
	}
	if det.Threshold.Block > 0 && det.Threshold.Log > 0 && det.Threshold.Block <= det.Threshold.Log {
		ve.addError("waf.detection.threshold.block",
			fmt.Sprintf("must be greater than log threshold (%d); got %d", det.Threshold.Log, det.Threshold.Block))
	}
	for name, dc := range det.Detectors {
		if dc.Multiplier < 0 {
			ve.addError(fmt.Sprintf("waf.detection.detectors.%s.multiplier", name),
				fmt.Sprintf("must be >= 0; got %g", dc.Multiplier))
		}
	}
}

func validateRateLimit(rl *RateLimitConfig, ve *ValidationError) {
	if !rl.Enabled {
		return
	}
	for i, rule := range rl.Rules {
		prefix := fmt.Sprintf("waf.rate_limit.rules[%d]", i)
		if rule.ID == "" {
			ve.addError(prefix+".id", "must not be empty")
		}
		if rule.Limit <= 0 {
			ve.addError(prefix+".limit", fmt.Sprintf("must be > 0; got %d", rule.Limit))
		}
		if rule.Window <= 0 {
			ve.addError(prefix+".window", fmt.Sprintf("must be > 0; got %v", rule.Window))
		}
		switch rule.Scope {
		case "ip", "ip+path":
			// valid
		default:
			ve.addError(prefix+".scope", fmt.Sprintf("must be one of: ip, ip+path; got %q", rule.Scope))
		}
		switch rule.Action {
		case "block", "log":
			// valid
		default:
			ve.addError(prefix+".action", fmt.Sprintf("must be one of: block, log; got %q", rule.Action))
		}
	}
}

func validateIPACL(acl *IPACLConfig, ve *ValidationError) {
	if !acl.Enabled {
		return
	}
	for i, entry := range acl.Whitelist {
		if !isValidIPOrCIDR(entry) {
			ve.addError(fmt.Sprintf("waf.ip_acl.whitelist[%d]", i),
				fmt.Sprintf("invalid IP or CIDR: %q", entry))
		}
	}
	for i, entry := range acl.Blacklist {
		if !isValidIPOrCIDR(entry) {
			ve.addError(fmt.Sprintf("waf.ip_acl.blacklist[%d]", i),
				fmt.Sprintf("invalid IP or CIDR: %q", entry))
		}
	}
}

func validateSanitizer(san *SanitizerConfig, ve *ValidationError) {
	if !san.Enabled {
		return
	}
	if san.MaxURLLength <= 0 {
		ve.addError("waf.sanitizer.max_url_length", fmt.Sprintf("must be > 0; got %d", san.MaxURLLength))
	}
	if san.MaxHeaderSize <= 0 {
		ve.addError("waf.sanitizer.max_header_size", fmt.Sprintf("must be > 0; got %d", san.MaxHeaderSize))
	}
	if san.MaxHeaderCount <= 0 {
		ve.addError("waf.sanitizer.max_header_count", fmt.Sprintf("must be > 0; got %d", san.MaxHeaderCount))
	}
	if san.MaxBodySize <= 0 {
		ve.addError("waf.sanitizer.max_body_size", fmt.Sprintf("must be > 0; got %d", san.MaxBodySize))
	}
	if san.MaxCookieSize <= 0 {
		ve.addError("waf.sanitizer.max_cookie_size", fmt.Sprintf("must be > 0; got %d", san.MaxCookieSize))
	}
}

func validateDashboard(dash *DashboardConfig, ve *ValidationError) {
	if !dash.Enabled {
		return
	}
	if dash.Listen != "" {
		validateListenAddr(dash.Listen, "dashboard.listen", ve)
	}
}

func validateLogging(log *LogConfig, ve *ValidationError) {
	switch log.Level {
	case "debug", "info", "warn", "error":
		// valid
	default:
		ve.addError("logging.level", fmt.Sprintf("must be one of: debug, info, warn, error; got %q", log.Level))
	}
	switch log.Format {
	case "json", "text":
		// valid
	default:
		ve.addError("logging.format", fmt.Sprintf("must be one of: json, text; got %q", log.Format))
	}
}

func validateEvents(ev *EventsConfig, ve *ValidationError) {
	switch ev.Storage {
	case "memory", "file":
		// valid
	default:
		ve.addError("events.storage", fmt.Sprintf("must be one of: memory, file; got %q", ev.Storage))
	}
	if ev.Storage == "file" && ev.FilePath == "" {
		ve.addError("events.file_path", "must not be empty when storage is \"file\"")
	}
	if ev.MaxEvents <= 0 {
		ve.addError("events.max_events", fmt.Sprintf("must be > 0; got %d", ev.MaxEvents))
	}
}

func validateVirtualHosts(vhosts []VirtualHostConfig, upstreams []UpstreamConfig, ve *ValidationError) {
	if len(vhosts) == 0 {
		return
	}

	upstreamNames := make(map[string]bool, len(upstreams))
	for _, u := range upstreams {
		upstreamNames[u.Name] = true
	}

	seenDomains := make(map[string]int) // domain -> vhost index

	for i, vh := range vhosts {
		prefix := fmt.Sprintf("virtual_hosts[%d]", i)

		if len(vh.Domains) == 0 {
			ve.addError(prefix+".domains", "must have at least one domain")
		}

		for _, domain := range vh.Domains {
			if domain == "" {
				ve.addError(prefix+".domains", "domain must not be empty")
				continue
			}
			if prev, dup := seenDomains[domain]; dup {
				ve.addError(prefix+".domains", fmt.Sprintf("domain %q is already defined in virtual_hosts[%d]", domain, prev))
			}
			seenDomains[domain] = i
		}

		for j, route := range vh.Routes {
			rPrefix := fmt.Sprintf("%s.routes[%d]", prefix, j)
			if route.Path == "" {
				ve.addError(rPrefix+".path", "must not be empty")
			}
			if route.Upstream != "" && !upstreamNames[route.Upstream] {
				ve.addError(rPrefix+".upstream", fmt.Sprintf("references unknown upstream %q", route.Upstream))
			}
		}

		// TLS cert validation: if one is set, both must be set
		if (vh.TLS.CertFile != "") != (vh.TLS.KeyFile != "") {
			ve.addError(prefix+".tls", "both cert_file and key_file must be set together")
		}
	}
}

// ValidateUpstreamsExported validates upstream configs (exported for dashboard).
func ValidateUpstreamsExported(upstreams []UpstreamConfig, ve *ValidationError) {
	validateUpstreams(upstreams, ve)
}

// ValidateRoutesExported validates route configs (exported for dashboard).
func ValidateRoutesExported(routes []RouteConfig, upstreams []UpstreamConfig, ve *ValidationError) {
	validateRoutes(routes, upstreams, ve)
}

// ValidateVirtualHostsExported validates virtual host configs (exported for dashboard).
func ValidateVirtualHostsExported(vhosts []VirtualHostConfig, upstreams []UpstreamConfig, ve *ValidationError) {
	validateVirtualHosts(vhosts, upstreams, ve)
}

// isValidIPOrCIDR returns true if s is a valid IP address or CIDR notation.
func isValidIPOrCIDR(s string) bool {
	// Try CIDR first
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	// Try plain IP
	return net.ParseIP(s) != nil
}
