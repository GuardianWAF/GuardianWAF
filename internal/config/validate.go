package config

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
//  1. Explicit path argument (if non-empty)
//  2. GWAF_CONFIG_PATH environment variable
//  3. GWAF_ENV environment variable -> guardianwaf.{env}.yaml
//  4. guardianwaf.yaml (default)
func ResolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("GWAF_CONFIG_PATH"); p != "" {
		return p
	}
	if env := os.Getenv("GWAF_ENV"); env != "" {
		if !safeConfigEnvName(env) {
			return "guardianwaf.yaml"
		}
		name := "guardianwaf." + env + ".yaml"
		// #nosec G703 -- env is restricted to a single filename-safe fragment above.
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return "guardianwaf.yaml"
}

func safeConfigEnvName(env string) bool {
	if env == "" {
		return false
	}
	for _, r := range env {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func cleanConfigPath(path string) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("config path contains NUL byte")
	}
	if path == "" {
		return ".", nil
	}
	return filepath.Clean(path), nil
}

func configChildFile(dir, name string, allowedExts ...string) (string, error) {
	dir, err := cleanConfigPath(dir)
	if err != nil {
		return "", err
	}
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid config file name %q", name)
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("config file name %q must not contain path separators", name)
	}
	if len(allowedExts) > 0 && !hasAllowedConfigExt(name, allowedExts) {
		return "", fmt.Errorf("config file %q has unsupported extension", name)
	}

	path := filepath.Join(dir, name)
	if !configPathWithinDir(dir, path) {
		return "", fmt.Errorf("config file %q escapes directory %q", name, dir)
	}
	return path, nil
}

func hasAllowedConfigExt(name string, allowedExts []string) bool {
	for _, ext := range allowedExts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func configPathWithinDir(dir, path string) bool {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// LoadFile reads a YAML config file, parses it, and returns a populated Config.
// Starts with defaults, then overlays values from the file.
func LoadFile(path string) (*Config, error) {
	path, err := cleanConfigPath(path)
	if err != nil {
		return nil, fmt.Errorf("validating config file path: %w", err)
	}
	// #nosec G304 -- config file path is operator-selected, NUL-rejected, and cleaned before use.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	node, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := validateKnownConfigKeys(node); err != nil {
		return nil, fmt.Errorf("validating config schema: %w", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		return nil, fmt.Errorf("populating config: %w", err)
	}
	cfg.setPlaceholderBindings(capturePlaceholderBindings(data, node))

	return cfg, nil
}

func validateKnownConfigKeys(node *Node) error {
	if node == nil {
		return nil
	}
	ve := &ValidationError{}
	validateKnownKeysForType(node, reflect.TypeOf(Config{}), "", ve)
	if ve.HasErrors() {
		return ve
	}
	return nil
}

func validateKnownKeysForType(node *Node, typ reflect.Type, path string, ve *ValidationError) {
	if node == nil || ve == nil {
		return
	}

	typ = unwrapSchemaType(typ)
	if !isStructuredNodeKind(node) || typ == nil {
		return
	}

	switch typ.Kind() {
	case reflect.Struct:
		validateKnownStructKeys(node, typ, path, ve)
	case reflect.Slice, reflect.Array:
		validateKnownSequenceKeys(node, typ.Elem(), path, ve)
	case reflect.Map:
		validateKnownMapValueKeys(node, typ.Elem(), path, ve)
	}
}

func validateKnownStructKeys(node *Node, typ reflect.Type, path string, ve *ValidationError) {
	if node.Kind != MapNode {
		return
	}

	fields := yamlSchemaFields(typ)
	for _, key := range node.MapKeys {
		childPath := joinSchemaPath(path, key)
		fieldType, ok := fields[key]
		if !ok {
			msg := "unknown key"
			if path == "" {
				msg = "unknown top-level key"
			}
			ve.addError(childPath, msg)
			continue
		}
		validateKnownKeysForType(node.Get(key), fieldType, childPath, ve)
	}
}

func validateKnownSequenceKeys(node *Node, elemType reflect.Type, path string, ve *ValidationError) {
	if node.Kind != SequenceNode {
		return
	}
	for i, item := range node.Slice() {
		validateKnownKeysForType(item, elemType, fmt.Sprintf("%s[%d]", path, i), ve)
	}
}

func validateKnownMapValueKeys(node *Node, elemType reflect.Type, path string, ve *ValidationError) {
	if node.Kind != MapNode {
		return
	}

	elemType = unwrapSchemaType(elemType)
	if elemType == nil || elemType.Kind() == reflect.Interface {
		return
	}
	for _, key := range node.MapKeys {
		childPath := joinSchemaPath(path, key)
		validateKnownKeysForType(node.Get(key), elemType, childPath, ve)
	}
}

func yamlSchemaFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		name := yamlFieldName(field)
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(field.Name)
		}
		fields[name] = field.Type
	}
	return fields
}

func yamlFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("yaml")
	if idx := strings.IndexByte(tag, ','); idx >= 0 {
		tag = tag[:idx]
	}
	return tag
}

func unwrapSchemaType(typ reflect.Type) reflect.Type {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

func joinSchemaPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func isStructuredNodeKind(node *Node) bool {
	return node.Kind == MapNode || node.Kind == SequenceNode
}

// LoadDir loads configuration from a directory structure:
//   - {dir}/guardianwaf.yaml (main config)
//   - {dir}/rules.d/*.yaml (appended to custom rules, rate limits, IP ACL)
//   - {dir}/domains.d/*.yaml (appended to virtual hosts)
//   - {dir}/tenants.d/*.yaml (appended to tenant configs)
//
// Arrays are appended (not replaced) when loading from subdirectory files.
func LoadDir(dir string) (*Config, error) {
	dir, err := cleanConfigPath(dir)
	if err != nil {
		return nil, fmt.Errorf("validating config directory path: %w", err)
	}

	// Load main config file
	mainPath := filepath.Join(dir, "guardianwaf.yaml")
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
		"domains.d": appendDomainsFromDir,
	}

	for subdir, loader := range subdirs {
		subdirPath := filepath.Join(dir, subdir)
		if entries, err := os.ReadDir(subdirPath); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
					filePath, err := configChildFile(subdirPath, entry.Name(), ".yaml")
					if err != nil {
						return nil, fmt.Errorf("loading %s: %w", subdirPath, err)
					}
					if err := loader(filePath, cfg); err != nil {
						return nil, fmt.Errorf("loading %s: %w", filePath, err)
					}
				}
			}
		}
	}

	if err := appendTenantsFromDir(filepath.Join(dir, "tenants.d"), cfg); err != nil {
		return nil, fmt.Errorf("loading tenants.d: %w", err)
	}

	return cfg, nil
}

// appendRulesFromDir loads rules from a rules.d/*.yaml file and appends to config.
func appendRulesFromDir(path string, cfg *Config) error {
	path, err := cleanConfigPath(path)
	if err != nil {
		return err
	}
	// #nosec G304 -- caller supplies a cleaned rules.d child file selected from directory entries.
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
			rule, err := parseCustomRule(item)
			if err != nil {
				return err
			}
			cfg.WAF.CustomRules.Rules = append(cfg.WAF.CustomRules.Rules, rule)
		}
	}

	// Append rate limit rules
	if n := node.Get("rate_limits"); n != nil && n.Kind == SequenceNode {
		for _, item := range n.Slice() {
			if item.Kind != MapNode {
				continue
			}
			rule, err := parseRateLimitRule(item)
			if err != nil {
				return fmt.Errorf("parsing rate limit rule in %s: %w", path, err)
			}
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
	path, err := cleanConfigPath(path)
	if err != nil {
		return err
	}
	// #nosec G304 -- caller supplies a cleaned domains.d child file selected from directory entries.
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
					if w := ti.Get("weight"); w != nil && !w.IsNull {
						i, werr := w.Int()
						if werr != nil {
							return fmt.Errorf("upstream %q target weight: %w", u.Name, werr)
						}
						if i > 0 {
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
			if block := th.Get("block"); block != nil && !block.IsNull {
				i, err := block.Int()
				if err != nil {
					return nil, fmt.Errorf("detection threshold block: %w", err)
				}
				if i > 0 {
					waf.Detection.Threshold.Block = i
				}
			}
			if log := th.Get("log"); log != nil && !log.IsNull {
				i, err := log.Int()
				if err != nil {
					return nil, fmt.Errorf("detection threshold log: %w", err)
				}
				if i > 0 {
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
				rule, err := parseRateLimitRule(item)
				if err != nil {
					return nil, fmt.Errorf("parsing rate limit rule in virtual host waf config: %w", err)
				}
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
				rule, err := parseCustomRule(item)
				if err != nil {
					return nil, fmt.Errorf("parsing custom rule in virtual host waf config: %w", err)
				}
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
	dir, err := cleanConfigPath(dir)
	if err != nil {
		return fmt.Errorf("validate tenants directory: %w", err)
	}

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

		path, err := configChildFile(dir, name, ".yaml", ".yml")
		if err != nil {
			return fmt.Errorf("tenant file %s: %w", name, err)
		}
		// #nosec G304 -- tenant file path is constrained to a cleaned tenants.d child file.
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read tenant file %s: %w", name, err)
		}

		node, err := Parse(data)
		if err != nil {
			return fmt.Errorf("parse tenant file %s: %w", name, err)
		}

		td, err := parseTenantDefinition(node)
		if err != nil {
			return fmt.Errorf("parse tenant file %s: %w", name, err)
		}
		if td.ID != "" {
			cfg.Tenant.Tenants = append(cfg.Tenant.Tenants, td)
		}
	}

	return nil
}

// parseTenantDefinition parses a TenantDefinition from a YAML node. A malformed
// "active" value is an error (rather than silently deactivating the tenant).
func parseTenantDefinition(n *Node) (TenantDefinition, error) {
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
	if active := n.Get("active"); active != nil && !active.IsNull {
		b, err := active.Bool()
		if err != nil {
			return td, fmt.Errorf("tenant %q: active: %w", td.ID, err)
		}
		td.Active = b
	}
	if domains := n.Get("domains"); domains != nil {
		for _, d := range domains.Items {
			td.Domains = append(td.Domains, d.String())
		}
	}
	return td, nil
}

// parseCustomRule parses a single custom rule from a YAML node. A malformed
// "enabled" value is an error (rather than silently disabling the rule).
func parseCustomRule(n *Node) (CustomRule, error) {
	r := CustomRule{Enabled: true}
	if id := n.Get("id"); id != nil {
		r.ID = id.String()
	}
	if name := n.Get("name"); name != nil {
		r.Name = name.String()
	}
	if en := n.Get("enabled"); en != nil && !en.IsNull {
		b, err := en.Bool()
		if err != nil {
			return r, fmt.Errorf("custom rule %q: enabled: %w", r.ID, err)
		}
		r.Enabled = b
	}
	if pri := n.Get("priority"); pri != nil && !pri.IsNull {
		i, err := pri.Int()
		if err != nil {
			return r, fmt.Errorf("custom rule %q: priority: %w", r.ID, err)
		}
		if i >= 0 {
			r.Priority = i
		}
	}
	if act := n.Get("action"); act != nil {
		r.Action = act.String()
	}
	if score := n.Get("score"); score != nil && !score.IsNull {
		i, err := score.Int()
		if err != nil {
			return r, fmt.Errorf("custom rule %q: score: %w", r.ID, err)
		}
		if i >= 0 {
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
	return r, nil
}

// parseRateLimitRule parses a single rate limit rule from a YAML node.
// Returns an error if required fields are missing or malformed.
func parseRateLimitRule(n *Node) (RateLimitRule, error) {
	r := RateLimitRule{Action: "block"}
	if id := n.Get("id"); id != nil {
		r.ID = id.String()
	}
	if r.ID == "" {
		return r, fmt.Errorf("rate limit rule missing required field: id")
	}
	if scope := n.Get("scope"); scope != nil {
		r.Scope = scope.String()
	}
	if paths := n.Get("paths"); paths != nil {
		r.Paths = nodeStringSlice(paths)
	}
	if limit := n.Get("limit"); limit != nil {
		i, err := limit.Int()
		if err != nil {
			return r, fmt.Errorf("rate limit rule %q: limit must be an integer, got %q", r.ID, limit.Value)
		}
		if i <= 0 {
			return r, fmt.Errorf("rate limit rule %q: limit must be > 0, got %d", r.ID, i)
		}
		r.Limit = i
	} else {
		return r, fmt.Errorf("rate limit rule %q: missing required field: limit", r.ID)
	}
	if window := n.Get("window"); window != nil && !window.IsNull {
		d, err := parseDuration(window.String())
		if err != nil {
			return r, fmt.Errorf("rate limit rule %q: window: %w", r.ID, err)
		}
		r.Window = d
	}
	if burst := n.Get("burst"); burst != nil {
		i, err := burst.Int()
		if err != nil {
			return r, fmt.Errorf("rate limit rule %q: burst must be an integer, got %q", r.ID, burst.Value)
		}
		if i < 0 {
			return r, fmt.Errorf("rate limit rule %q: burst must be >= 0, got %d", r.ID, i)
		}
		r.Burst = i
	}
	if act := n.Get("action"); act != nil {
		r.Action = act.String()
	}
	if ab := n.Get("auto_ban_after"); ab != nil {
		i, err := ab.Int()
		if err != nil {
			return r, fmt.Errorf("rate limit rule %q: auto_ban_after must be an integer, got %q", r.ID, ab.Value)
		}
		if i < 0 {
			return r, fmt.Errorf("rate limit rule %q: auto_ban_after must be >= 0, got %d", r.ID, i)
		}
		r.AutoBanAfter = i
	}
	return r, nil
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

// LoadEnv atomically overlays environment variables onto the config.
// Invalid typed values are returned as validation errors and no overrides are
// applied, preventing a misspelled production setting from silently falling
// back to a potentially unsafe default.
// Env var format: GWAF_<SECTION>_<KEY>=<value>
// Examples:
//
//	GWAF_MODE=monitor
//	GWAF_LISTEN=:9090
//	GWAF_WAF_DETECTION_THRESHOLD_BLOCK=60
//	GWAF_LOGGING_LEVEL=debug
func LoadEnv(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("load environment overrides: config is nil")
	}

	ve := &ValidationError{}
	for _, key := range []string{
		"GWAF_ALLOW_PRIVATE_UPSTREAMS",
		"GWAF_DASHBOARD_ENABLED",
		"GWAF_MCP_ENABLED",
		"GWAF_DOCKER_ENABLED",
		"GWAF_ALERTING_ENABLED",
		"GWAF_WAF_AI_ANALYSIS_ENABLED",
		"GWAF_TLS_ENABLED",
		"GWAF_TRACING_ENABLED",
		"GWAF_COMPLIANCE_ENABLED",
		"GWAF_COMPLIANCE_AUDIT_TRAIL_ENABLED",
	} {
		if value := os.Getenv(key); value != "" {
			if _, err := strconv.ParseBool(value); err != nil {
				ve.addError(key, "must be a valid boolean")
			}
		}
	}
	for _, key := range []string{
		"GWAF_WAF_DETECTION_THRESHOLD_BLOCK",
		"GWAF_WAF_DETECTION_THRESHOLD_LOG",
		"GWAF_EVENTS_MAX_EVENTS",
		"GWAF_LOGGING_MAX_SIZE_MB",
		"GWAF_LOGGING_MAX_BACKUPS",
		"GWAF_LOGGING_MAX_AGE_DAYS",
	} {
		if value := os.Getenv(key); value != "" {
			if _, err := strconv.Atoi(value); err != nil {
				ve.addError(key, "must be a valid integer")
			}
		}
	}
	if value := os.Getenv("GWAF_TRACING_SAMPLING_RATE"); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			ve.addError("GWAF_TRACING_SAMPLING_RATE", "must be a valid number")
		}
	}
	if ve.HasErrors() {
		return ve
	}

	envMap := map[string]func(string){
		"GWAF_MODE":   func(v string) { cfg.Mode = v },
		"GWAF_LISTEN": func(v string) { cfg.Listen = v },
		"GWAF_ALLOW_PRIVATE_UPSTREAMS": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.AllowPrivateUpstreams = &b
			}
		},
		"GWAF_ALLOWED_UPSTREAM_CIDRS": func(v string) {
			cfg.AllowedUpstreamCIDRs = splitCommaList(v)
		},
		"GWAF_TRUSTED_PROXIES": func(v string) {
			cfg.TrustedProxies = splitCommaList(v)
		},

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
		"GWAF_DASHBOARD_ADMIN_KEY": func(v string) {
			cfg.Dashboard.AdminKey = v
		},
		"GWAF_DASHBOARD_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Dashboard.Enabled = b
			}
		},
		"GWAF_MCP_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.MCP.Enabled = b
			}
		},
		"GWAF_MCP_TRANSPORT": func(v string) { cfg.MCP.Transport = v },
		"GWAF_DOCKER_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Docker.Enabled = b
			}
		},
		"GWAF_ALERTING_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.Alerting.Enabled = b
			}
		},
		"GWAF_WAF_AI_ANALYSIS_ENABLED": func(v string) {
			if b, err := strconv.ParseBool(v); err == nil {
				cfg.WAF.AIAnalysis.Enabled = b
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
		"GWAF_TRACING_SERVICE_NAME": func(v string) { cfg.Tracing.ServiceName = v },
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
	return nil
}

// Validate checks the config for errors and returns all errors at once.
// Errors are collected rather than failing on the first issue.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config validation failed: config is nil")
	}
	ve := &ValidationError{}

	// Mode validation
	validateMode(cfg, ve)

	// Listen address validation
	validateListenAddr(cfg.Listen, "listen", ve)

	// Trusted proxy validation
	validateTrustedProxies(cfg.TrustedProxies, ve)
	validateAllowedUpstreamCIDRs(cfg.AllowedUpstreamCIDRs, ve)

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

	// Docker discovery validation
	validateDocker(&cfg.Docker, ve)

	// Distributed tracing validation
	validateTracing(&cfg.Tracing, ve)

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
		if len(u.Targets) == 0 {
			ve.addError(prefix+".targets", "must have at least one target")
		}
		for j, t := range u.Targets {
			tPrefix := fmt.Sprintf("%s.targets[%d]", prefix, j)
			if t.URL == "" {
				ve.addError(tPrefix+".url", "must not be empty")
			} else if err := validateUpstreamTargetURL(t.URL); err != nil {
				ve.addError(tPrefix+".url", err.Error())
			}
			if t.Weight <= 0 {
				ve.addError(tPrefix+".weight", fmt.Sprintf("must be > 0; got %d", t.Weight))
			}
		}
	}
}

func validateUpstreamTargetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("scheme must be http or https; got %q", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("host must not be empty")
	}
	return nil
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

func validateTrustedProxies(proxies []string, ve *ValidationError) {
	for i, proxy := range proxies {
		field := fmt.Sprintf("trusted_proxies[%d]", i)
		if !isValidIPOrCIDR(proxy) {
			ve.addError(field, fmt.Sprintf("invalid IP or CIDR: %q", proxy))
			continue
		}
		if !strings.Contains(proxy, "/") {
			continue
		}
		ip, cidr, err := net.ParseCIDR(proxy)
		if err != nil {
			continue
		}
		ones, bits := cidr.Mask.Size()
		if ones == 0 {
			ve.addError(field, fmt.Sprintf("must not trust all clients with %q", proxy))
			continue
		}
		if ip.To4() != nil && bits == 32 && ones < 8 {
			ve.addError(field, fmt.Sprintf("CIDR %q is too broad for a trusted proxy range; configure the actual proxy or load-balancer subnet", proxy))
			continue
		}
		if ip.To4() == nil && bits == 128 && ones < 32 {
			ve.addError(field, fmt.Sprintf("CIDR %q is too broad for a trusted proxy range; configure the actual proxy or load-balancer subnet", proxy))
		}
	}
}

func validateAllowedUpstreamCIDRs(cidrs []string, ve *ValidationError) {
	for i, entry := range cidrs {
		field := fmt.Sprintf("allowed_upstream_cidrs[%d]", i)
		if !isValidIPOrCIDR(entry) {
			ve.addError(field, fmt.Sprintf("invalid IP or CIDR: %q", entry))
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				continue
			}
			if ip.IsUnspecified() || ip.IsMulticast() {
				ve.addError(field, fmt.Sprintf("must not allow unspecified or multicast address %q", entry))
			}
			continue
		}
		ip, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		ones, _ := cidr.Mask.Size()
		if ip.IsUnspecified() {
			ve.addError(field, fmt.Sprintf("must not allow unspecified range %q", entry))
			continue
		}
		if ones == 0 {
			ve.addError(field, fmt.Sprintf("must not allow all addresses: %q", entry))
		}
		if ip.IsMulticast() {
			ve.addError(field, fmt.Sprintf("must not allow multicast range %q", entry))
		}
	}
}

func splitCommaList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validateWAF(waf *WAFConfig, ve *ValidationError) {
	validateDetection(&waf.Detection, ve)
	validateRateLimit(&waf.RateLimit, ve)
	validateIPACL(&waf.IPACL, ve)
	validateSanitizer(&waf.Sanitizer, ve)
	validateGeoIP(&waf.GeoIP, ve)
	validateAIAnalysis(&waf.AIAnalysis, ve)
	validateRemovedLayers(waf, ve)
}

// validateRemovedLayers fails validation when a config enables a WAF layer that
// was removed from the binary. These config blocks are still parsed (so old
// configs don't error on an unknown key) but the layer no longer runs — a
// silent security gap if an operator believes the control is active. Erroring
// on `enabled: true` makes the removal loud instead.
func validateRemovedLayers(waf *WAFConfig, ve *ValidationError) {
	removed := []struct {
		path    string
		enabled bool
	}{
		{"waf.ml_anomaly", waf.MLAnomaly.Enabled},
		{"waf.api_discovery", waf.APIDiscovery.Enabled},
		{"waf.graphql", waf.GraphQL.Enabled},
		{"waf.grpc", waf.GRPC.Enabled},
		{"waf.zero_trust", waf.ZeroTrust.Enabled},
		{"waf.siem", waf.SIEM.Enabled},
		{"waf.cache", waf.Cache.Enabled},
		{"waf.replay", waf.Replay.Enabled},
		{"waf.canary", waf.Canary.Enabled},
		{"waf.analytics", waf.Analytics.Enabled},
		{"waf.cluster", waf.Cluster.Enabled},
		{"waf.websocket", waf.WebSocket.Enabled},
	}
	for _, r := range removed {
		if r.enabled {
			ve.addError(r.path+".enabled", "this WAF layer was removed and no longer runs; remove this block from your config (it provides no protection)")
		}
	}
}

func validateGeoIP(geo *GeoIPConfig, ve *ValidationError) {
	if geo.RequireReady && !geo.Enabled {
		ve.addError("waf.geoip.require_ready", "requires waf.geoip.enabled to be true")
	}
}

func validateAIAnalysis(ai *AIAnalysisConfig, ve *ValidationError) {
	if !ai.Enabled {
		return
	}
	if ai.BatchSize <= 0 {
		ve.addError("waf.ai_analysis.batch_size", fmt.Sprintf("must be > 0; got %d", ai.BatchSize))
	}
	if ai.BatchSize > 1000 {
		ve.addError("waf.ai_analysis.batch_size", fmt.Sprintf("must be <= 1000 to bound pending AI batch memory; got %d", ai.BatchSize))
	}
	if ai.BatchInterval <= 0 {
		ve.addError("waf.ai_analysis.batch_interval", fmt.Sprintf("must be > 0; got %v", ai.BatchInterval))
	}
	if ai.MinScore < 0 {
		ve.addError("waf.ai_analysis.min_score", fmt.Sprintf("must be >= 0; got %d", ai.MinScore))
	}
	if ai.MaxTokensPerHour < 0 {
		ve.addError("waf.ai_analysis.max_tokens_per_hour", fmt.Sprintf("must be >= 0; got %d", ai.MaxTokensPerHour))
	}
	if ai.MaxTokensPerDay < 0 {
		ve.addError("waf.ai_analysis.max_tokens_per_day", fmt.Sprintf("must be >= 0; got %d", ai.MaxTokensPerDay))
	}
	if ai.MaxRequestsHour < 0 {
		ve.addError("waf.ai_analysis.max_requests_per_hour", fmt.Sprintf("must be >= 0; got %d", ai.MaxRequestsHour))
	}
	if ai.AutoBlockTTL < 0 {
		ve.addError("waf.ai_analysis.auto_block_ttl", fmt.Sprintf("must be >= 0; got %v", ai.AutoBlockTTL))
	}
}

func validateDocker(dock *DockerConfig, ve *ValidationError) {
	if !dock.Enabled {
		return
	}
	if dock.SocketPath == "" {
		ve.addError("docker.socket_path", "must not be empty when Docker discovery is enabled")
		return
	}
	if strings.ContainsAny(dock.SocketPath, "\x00\r\n\t") {
		ve.addError("docker.socket_path", "must not contain control characters")
		return
	}

	if strings.HasPrefix(dock.SocketPath, "tcp://") {
		u, err := url.Parse(dock.SocketPath)
		if err != nil || u.Host == "" {
			ve.addError("docker.socket_path", fmt.Sprintf("invalid Docker TCP endpoint %q", dock.SocketPath))
			return
		}
		if u.User != nil {
			ve.addError("docker.socket_path", "must not include credentials")
		}
		if !dock.TLSVerify {
			ve.addError("docker.tls_verify", "must be true for tcp:// Docker endpoints")
		}
		if dock.TLSCACert == "" {
			ve.addError("docker.tls_ca_cert", "must not be empty for tcp:// Docker endpoints")
		}
		if dock.TLSCert == "" {
			ve.addError("docker.tls_cert", "must not be empty for tcp:// Docker endpoints")
		}
		if dock.TLSKey == "" {
			ve.addError("docker.tls_key", "must not be empty for tcp:// Docker endpoints")
		}
		return
	}

	if dock.TLSVerify || dock.TLSCACert != "" || dock.TLSCert != "" || dock.TLSKey != "" {
		ve.addError("docker.tls_verify", "remote Docker TLS fields are only supported with tcp:// Docker endpoints")
	}
}

func validateTracing(trace *TracingConfig, ve *ValidationError) {
	if math.IsNaN(trace.SamplingRate) || math.IsInf(trace.SamplingRate, 0) || trace.SamplingRate < 0 || trace.SamplingRate > 1 {
		ve.addError("tracing.sampling_rate", "must be a finite number between 0 and 1")
	}
	switch trace.ExporterType {
	case "", "noop", "stdout":
		// Empty is the disabled/default no-op exporter.
	default:
		ve.addError("tracing.exporter_type", "must be one of: noop, stdout")
	}
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
	if dash.TLS {
		ve.addError("dashboard.tls", "built-in dashboard TLS termination is not implemented; keep this false and terminate TLS at an ingress or reverse proxy")
	}
	validateDashboardSecret("dashboard.api_key", dash.APIKey, ve)
	validateDashboardSecret("dashboard.admin_key", dash.AdminKey, ve)
	if dash.AuditPath != "" && !strings.Contains(dash.AuditPath, "${") && !filepath.IsAbs(dash.AuditPath) {
		ve.addError("dashboard.audit_path", "must be an absolute path so restart durability does not depend on the process working directory")
	}
}

func validateDashboardSecret(field, value string, ve *ValidationError) {
	if value == "" || strings.Contains(value, "${") {
		return
	}
	if strings.TrimSpace(value) != value {
		ve.addError(field, "must not contain leading or trailing whitespace")
		return
	}
	if len(value) < 16 {
		ve.addError(field, "must be at least 16 characters when explicitly configured; leave empty to generate a strong random secret at startup")
		return
	}
	switch strings.ToLower(value) {
	case "password", "password123", "admin", "admin123", "changeme", "secret", "secret123", "testsecret":
		ve.addError(field, "must not use a common or default secret")
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
