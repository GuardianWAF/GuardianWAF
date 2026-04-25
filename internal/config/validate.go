package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// ResolveConfigPath determines the config file path based on environment.
// Resolution order:
//   1. Explicit path argument (if non-empty)
//   2. GWAF_CONFIG_PATH environment variable
//   3. GWAF_ENV environment variable -> guardianwaf.{env}.yaml
//   4. guardianwaf.yaml (default)
func ResolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("GWAF_CONFIG_PATH"); p != "" {
		return p
	}
	if env := os.Getenv("GWAF_ENV"); env != "" {
		name := "guardianwaf." + env + ".yaml"
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return "guardianwaf.yaml"
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

// LoadDir loads configuration from a directory structure:
//   - {dir}/guardianwaf.yaml (main config)
//   - {dir}/rules.d/*.yaml (appended to custom rules, rate limits, IP ACL)
//   - {dir}/domains.d/*.yaml (appended to virtual hosts)
//   - {dir}/tenants.d/*.yaml (appended to tenant configs)
//
// Arrays are appended (not replaced) when loading from subdirectory files.
func LoadDir(dir string) (*Config, error) {
	// Load main config file
	mainPath := dir + string(os.PathSeparator) + "guardianwaf.yaml"
	cfg, err := LoadFile(mainPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading main config: %w", err)
	}
	if os.IsNotExist(err) {
		// No main config, start with defaults
		cfg = DefaultConfig()
	}

	// Scan and load subdirectory configs
	subdirs := map[string]func(path string, cfg *Config) error{
		"rules.d":   appendRulesFromDir,
		"domains.d":  appendDomainsFromDir,
		"tenants.d":  appendTenantsFromDir,
	}

	for subdir, loader := range subdirs {
		subdirPath := dir + string(os.PathSeparator) + subdir
		if entries, err := os.ReadDir(subdirPath); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
					filePath := subdirPath + string(os.PathSeparator) + entry.Name()
					if err := loader(filePath, cfg); err != nil {
						return nil, fmt.Errorf("loading %s: %w", filePath, err)
					}
				}
			}
		}
	}

	return cfg, nil
}

// appendRulesFromDir loads rules from a rules.d/*.yaml file and appends to config.
func appendRulesFromDir(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	node, err := Parse(data)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	// Append custom rules
	if n := node.Get("custom_rules"); n != nil && n.Kind == SequenceNode {
		for _, item := range n.Slice() {
			if item.Kind != MapNode {
				continue
			}
			rule := parseCustomRule(item)
			cfg.WAF.CustomRules.Rules = append(cfg.WAF.CustomRules.Rules, rule)
		}
	}

	// Append rate limit rules
	if n := node.Get("rate_limits"); n != nil && n.Kind == SequenceNode {
		for _, item := range n.Slice() {
			if item.Kind != MapNode {
				continue
			}
			rule := parseRateLimitRule(item)
			cfg.WAF.RateLimit.Rules = append(cfg.WAF.RateLimit.Rules, rule)
		}
	}

	// Append IP ACL whitelist/blacklist entries
	if n := node.Get("ipacl"); n != nil && n.Kind == MapNode {
		if wl := n.Get("whitelist"); wl != nil {
			cfg.WAF.IPACL.Whitelist = append(cfg.WAF.IPACL.Whitelist, nodeStringSlice(wl)...)
		}
		if bl := n.Get("blacklist"); bl != nil {
			cfg.WAF.IPACL.Blacklist = append(cfg.WAF.IPACL.Blacklist, nodeStringSlice(bl)...)
		}
	}

	return nil
}

// appendDomainsFromDir loads domain configs from domains.d/*.yaml and appends to virtual hosts.
func appendDomainsFromDir(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	node, err := Parse(data)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	vh := VirtualHostConfig{}

	if domains := node.Get("domains"); domains != nil {
		vh.Domains = nodeStringSlice(domains)
	}

	if tls := node.Get("tls"); tls != nil && tls.Kind == MapNode {
		if cert := tls.Get("cert_file"); cert != nil {
			vh.TLS.CertFile = cert.String()
		}
		if key := tls.Get("key_file"); key != nil {
			vh.TLS.KeyFile = key.String()
		}
	}

	if routes := node.Get("routes"); routes != nil && routes.Kind == SequenceNode {
		for _, item := range routes.Slice() {
			if item.Kind != MapNode {
				continue
			}
			rc := RouteConfig{}
			if p := item.Get("path"); p != nil {
				rc.Path = p.String()
			}
			if u := item.Get("upstream"); u != nil {
				rc.Upstream = u.String()
			}
			if sp := item.Get("strip_prefix"); sp != nil {
				if b, _ := sp.Bool(); b {
					rc.StripPrefix = true
				}
			}
			if m := item.Get("methods"); m != nil {
				rc.Methods = nodeStringSlice(m)
			}
			vh.Routes = append(vh.Routes, rc)
		}
	}

	// Load upstreams from this file
	if ups := node.Get("upstreams"); ups != nil && ups.Kind == SequenceNode {
		for _, item := range ups.Slice() {
			if item.Kind != MapNode {
				continue
			}
			u := UpstreamConfig{}
			if n := item.Get("name"); n != nil {
				u.Name = n.String()
			}
			if t := item.Get("targets"); t != nil && t.Kind == SequenceNode {
				for _, ti := range t.Slice() {
					if ti.Kind != MapNode {
						continue
					}
					tc := TargetConfig{Weight: 1}
					if url := ti.Get("url"); url != nil {
						tc.URL = url.String()
					}
					if w := ti.Get("weight"); w != nil {
						if i, _ := w.Int(); i > 0 {
							tc.Weight = i
						}
					}
					u.Targets = append(u.Targets, tc)
				}
			}
			cfg.Upstreams = append(cfg.Upstreams, u)
		}
	}

	// Load per-domain WAF override if present
	waf, err := loadVirtualHostWAF(node)
	if err != nil {
		return fmt.Errorf("loading domain waf config: %w", err)
	}
	vh.WAF = waf

	cfg.VirtualHosts = append(cfg.VirtualHosts, vh)
	return nil
}

// loadVirtualHostWAF loads the optional per-domain WAF override section.
// If present, returns a pointer to WAFConfig populated from the YAML node.
// If not present, returns nil (meaning use global WAF config).
func loadVirtualHostWAF(n *Node) (*WAFConfig, error) {
	if n == nil || n.Kind != MapNode {
		return nil, nil
	}
	wafNode := n.Get("waf")
	if wafNode == nil || wafNode.IsNull {
		return nil, nil
	}
	if wafNode.Kind != MapNode {
		return nil, fmt.Errorf("waf section must be a map")
	}

	// Start with default WAF config and overlay values from YAML
	wafDefaults := DefaultWAFConfig()
	waf := &wafDefaults

	// Parse detection override
	if det := wafNode.Get("detection"); det != nil && det.Kind == MapNode {
		if en := det.Get("enabled"); en != nil {
			if b, _ := en.Bool(); b {
				waf.Detection.Enabled = true
			}
		}
		if th := det.Get("threshold"); th != nil && th.Kind == MapNode {
			if block := th.Get("block"); block != nil {
				if i, _ := block.Int(); i > 0 {
					waf.Detection.Threshold.Block = i
				}
			}
			if log := th.Get("log"); log != nil {
				if i, _ := log.Int(); i > 0 {
					waf.Detection.Threshold.Log = i
				}
			}
		}
	}

	// Parse rate limit override
	if rl := wafNode.Get("rate_limit"); rl != nil && rl.Kind == MapNode {
		if en := rl.Get("enabled"); en != nil {
			if b, _ := en.Bool(); b {
				waf.RateLimit.Enabled = true
			}
		}
		if rules := rl.Get("rules"); rules != nil && rules.Kind == SequenceNode {
			for _, item := range rules.Slice() {
				if item.Kind != MapNode {
					continue
				}
				rule := parseRateLimitRule(item)
				waf.RateLimit.Rules = append(waf.RateLimit.Rules, rule)
			}
		}
	}

	// Parse bot detection override
	if bd := wafNode.Get("bot_detection"); bd != nil && bd.Kind == MapNode {
		if en := bd.Get("enabled"); en != nil {
			if b, _ := en.Bool(); b {
				waf.BotDetection.Enabled = true
			}
		}
		if mode := bd.Get("mode"); mode != nil {
			waf.BotDetection.Mode = mode.String()
		}
	}

	// Parse custom rules override
	if cr := wafNode.Get("custom_rules"); cr != nil && cr.Kind == MapNode {
		if rules := cr.Get("rules"); rules != nil && rules.Kind == SequenceNode {
			for _, item := range rules.Slice() {
				if item.Kind != MapNode {
					continue
				}
				rule := parseCustomRule(item)
				waf.CustomRules.Rules = append(waf.CustomRules.Rules, rule)
			}
		}
	}

	return waf, nil
}

// DefaultWAFConfig returns a default WAFConfig.
func DefaultWAFConfig() WAFConfig {
	return WAFConfig{
		Detection: DetectionConfig{
			Enabled: true,
			Threshold: ThresholdConfig{
				Block: 50,
				Log:   25,
			},
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
		},
		BotDetection: BotDetectionConfig{
			Enabled: true,
			Mode:    "monitor",
		},
	}
}

// appendTenantsFromDir loads tenant configs from tenants.d/*.yaml and appends.
func appendTenantsFromDir(dir string, cfg *Config) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read tenants directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read tenant file %s: %w", name, err)
		}

		node, err := Parse(data)
		if err != nil {
			return fmt.Errorf("parse tenant file %s: %w", name, err)
		}

		td := parseTenantDefinition(node)
		if td.ID != "" {
			cfg.Tenant.Tenants = append(cfg.Tenant.Tenants, td)
		}
	}

	return nil
}

// parseTenantDefinition parses a TenantDefinition from a YAML node.
func parseTenantDefinition(n *Node) TenantDefinition {
	td := TenantDefinition{Active: true}
	if id := n.Get("id"); id != nil {
		td.ID = id.String()
	}
	if name := n.Get("name"); name != nil {
		td.Name = name.String()
	}
	if desc := n.Get("description"); desc != nil {
		td.Description = desc.String()
	}
	if apiKey := n.Get("api_key"); apiKey != nil {
		td.APIKey = apiKey.String()
	}
	if active := n.Get("active"); active != nil {
		if b, _ := active.Bool(); !b {
			td.Active = false
		}
	}
	if domains := n.Get("domains"); domains != nil {
		for _, d := range domains.Items {
			td.Domains = append(td.Domains, d.String())
		}
	}
	return td
}

// parseCustomRule parses a single custom rule from a YAML node.
func parseCustomRule(n *Node) CustomRule {
	r := CustomRule{Enabled: true}
	if id := n.Get("id"); id != nil {
		r.ID = id.String()
	}
	if name := n.Get("name"); name != nil {
		r.Name = name.String()
	}
	if en := n.Get("enabled"); en != nil {
		if b, _ := en.Bool(); !b {
			r.Enabled = false
		}
	}
	if pri := n.Get("priority"); pri != nil {
		if i, _ := pri.Int(); i >= 0 {
			r.Priority = i
		}
	}
	if act := n.Get("action"); act != nil {
		r.Action = act.String()
	}
	if score := n.Get("score"); score != nil {
		if i, _ := score.Int(); i >= 0 {
			r.Score = i
		}
	}
	// Parse conditions
	if cond := n.Get("conditions"); cond != nil && cond.Kind == SequenceNode {
		for _, c := range cond.Slice() {
			if c.Kind != MapNode {
				continue
			}
			rc := RuleCondition{}
			if f := c.Get("field"); f != nil {
				rc.Field = f.String()
			}
			if o := c.Get("op"); o != nil {
				rc.Op = o.String()
			}
			if v := c.Get("value"); v != nil {
				rc.Value = parseNodeValue(v)
			}
			r.Conditions = append(r.Conditions, rc)
		}
	}
	return r
}

// parseRateLimitRule parses a single rate limit rule from a YAML node.
func parseRateLimitRule(n *Node) RateLimitRule {
	r := RateLimitRule{Action: "block"}
	if id := n.Get("id"); id != nil {
		r.ID = id.String()
	}
	if scope := n.Get("scope"); scope != nil {
		r.Scope = scope.String()
	}
	if paths := n.Get("paths"); paths != nil {
		r.Paths = nodeStringSlice(paths)
	}
	if limit := n.Get("limit"); limit != nil {
		if i, _ := limit.Int(); i > 0 {
			r.Limit = i
		}
	}
	if window := n.Get("window"); window != nil {
		if d, err := parseDuration(window.String()); err == nil {
			r.Window = d
		}
	}
	if burst := n.Get("burst"); burst != nil {
		if i, _ := burst.Int(); i >= 0 {
			r.Burst = i
		}
	}
	if act := n.Get("action"); act != nil {
		r.Action = act.String()
	}
	if ab := n.Get("auto_ban_after"); ab != nil {
		if i, _ := ab.Int(); i >= 0 {
			r.AutoBanAfter = i
		}
	}
	return r
}

// parseNodeValue extracts a value from a YAML node (string, int, bool, or slice).
func parseNodeValue(n *Node) any {
	if n == nil || n.IsNull {
		return nil
	}
	switch n.Kind {
	case ScalarNode:
		// Try int first
		if i, err := n.Int(); err == nil {
			return i
		}
		// Try float
		if f, err := n.Float64(); err == nil {
			return f
		}
		// Try bool
		if b, err := n.Bool(); err == nil {
			return b
		}
		return n.String()
	case SequenceNode:
		return nodeStringSlice(n)
	}
	return n.String()
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

		"GWAF_DASHBOARD_LISTEN":   func(v string) { cfg.Dashboard.Listen = v },
		"GWAF_DASHBOARD_API_KEY":  func(v string) { cfg.Dashboard.APIKey = v },
		"GWAF_DASHBOARD_ADMIN_KEY": func(v string) { cfg.Dashboard.AdminKey = v },
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

		"GWAF_TRACING_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Tracing.Enabled = b
			}
		},
		"GWAF_TRACING_SERVICE_NAME":  func(v string) { cfg.Tracing.ServiceName = v },
		"GWAF_TRACING_SAMPLING_RATE": func(v string) {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.Tracing.SamplingRate = f
			}
		},
		"GWAF_TRACING_EXPORTER_TYPE": func(v string) { cfg.Tracing.ExporterType = v },

		"GWAF_LOGGING_MAX_SIZE_MB": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.Logging.MaxSizeMB = i
			}
		},
		"GWAF_LOGGING_MAX_BACKUPS": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.Logging.MaxBackups = i
			}
		},
		"GWAF_LOGGING_MAX_AGE_DAYS": func(v string) {
			if i, err := strconv.Atoi(v); err == nil {
				cfg.Logging.MaxAgeDays = i
			}
		},

		// Compliance reporting
		"GWAF_COMPLIANCE_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Compliance.Enabled = b
			}
		},
		"GWAF_COMPLIANCE_FRAMEWORKS": func(v string) {
			cfg.Compliance.Frameworks = strings.Split(v, ",")
		},
		"GWAF_COMPLIANCE_REPORT_DIR": func(v string) {
			cfg.Compliance.ReportDir = v
		},
		"GWAF_COMPLIANCE_AUDIT_TRAIL_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Compliance.AuditTrail.Enabled = b
			}
		},
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
