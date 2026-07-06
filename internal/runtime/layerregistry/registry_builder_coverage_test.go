package layerregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/layers/apisecurity"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/layers/threatintel"
)

func TestBuildCustomRules_UsesGeoIPContextAndCopiesRules(t *testing.T) {
	tmp := t.TempDir()
	dbPath := tmp + "/geoip.csv"
	if err := os.WriteFile(dbPath, []byte("1.2.3.0/24,US\n"), 0o600); err != nil {
		t.Fatalf("write geoip db: %v", err)
	}
	geodb, err := geoip.LoadCSV(dbPath)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.WAF.CustomRules.Enabled = true
	cfg.WAF.CustomRules.Rules = []config.CustomRule{{
		ID:       "geo-rule",
		Name:     "geo lookup",
		Enabled:  true,
		Priority: 7,
		Action:   "log",
		Score:    12,
		Conditions: []config.RuleCondition{{
			Field: "country",
			Op:    "equals",
			Value: "US",
		}},
	}}

	layer, err := buildCustomRules(&BuildContext{GeoIPDB: geodb}, cfg)
	if err != nil {
		t.Fatalf("buildCustomRules: %v", err)
	}
	rulesLayer, ok := layer.(*rules.Layer)
	if !ok {
		t.Fatalf("buildCustomRules built %T, want *rules.Layer", layer)
	}

	cfg.WAF.CustomRules.Rules[0].Name = "mutated"
	cfg.WAF.CustomRules.Rules[0].Conditions[0].Field = "path"

	builtRules := rulesLayer.Rules()
	if len(builtRules) != 1 {
		t.Fatalf("Rules() len = %d, want 1", len(builtRules))
	}
	if builtRules[0].Name != "geo lookup" {
		t.Fatalf("rule name = %q, want original copy", builtRules[0].Name)
	}
	if builtRules[0].Conditions[0].Field != "country" {
		t.Fatalf("condition field = %q, want original copy", builtRules[0].Conditions[0].Field)
	}

	ev := engine.NewEvent(&engine.RequestContext{
		ClientIP:  net.ParseIP("1.2.3.4"),
		StartTime: time.Now(),
		Headers:   map[string][]string{},
	}, 200)
	if ev.CountryCode != "US" || ev.CountryName == "" {
		t.Fatalf("GeoIP lookup not wired, got country=%q name=%q", ev.CountryCode, ev.CountryName)
	}
}

func TestBuildThreatIntel_CopiesFeedsAndRegistersHook(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ThreatIntel.Enabled = true
	cfg.WAF.ThreatIntel.Feeds = []config.ThreatFeedConfig{{
		Type:    "file",
		Path:    t.TempDir() + "/missing-feed.txt",
		Refresh: time.Second,
		Format:  "text",
	}}

	ctx := &BuildContext{}
	layer, err := buildThreatIntel(ctx, cfg)
	if err != nil {
		t.Fatalf("buildThreatIntel: %v", err)
	}
	threatLayer, ok := layer.(*threatintel.Layer)
	if !ok {
		t.Fatalf("buildThreatIntel built %T, want *threatintel.Layer", layer)
	}
	if len(ctx.StartHooks) != 1 || ctx.StartHooks[0].Name != "threat_intelligence" || ctx.StartHooks[0].Run == nil {
		t.Fatalf("unexpected start hooks: %#v", ctx.StartHooks)
	}

	cfg.WAF.ThreatIntel.Feeds[0].Path = "mutated"
	cfg.WAF.ThreatIntel.Feeds[0].Format = "csv"

	stored := unexportedField[threatintel.Config](t, threatLayer, "config")
	if len(stored.Feeds) != 1 {
		t.Fatalf("stored feeds len = %d, want 1", len(stored.Feeds))
	}
	if stored.Feeds[0].Path == "mutated" || stored.Feeds[0].Format != "text" {
		t.Fatalf("stored feed = %#v, want original copy", stored.Feeds[0])
	}
}

func TestBuildAPISecurity_CopiesAPIKeysAndSkipPaths(t *testing.T) {
	plainKey := "secret-key"
	cfg := config.DefaultConfig()
	cfg.WAF.APISecurity.Enabled = true
	cfg.WAF.APISecurity.SkipPaths = []string{"/healthz", "/public/*"}
	cfg.WAF.APISecurity.APIKeys.Enabled = true
	cfg.WAF.APISecurity.APIKeys.HeaderName = "X-API-Key"
	cfg.WAF.APISecurity.APIKeys.Keys = []config.APIKeyConfig{{
		Name:         "primary",
		KeyHash:      sha256Hex(plainKey),
		KeyPrefix:    "secret",
		RateLimit:    10,
		AllowedPaths: []string{"/secure"},
		Enabled:      true,
	}}

	layer, err := buildAPISecurity(cfg)
	if err != nil {
		t.Fatalf("buildAPISecurity: %v", err)
	}
	apiLayer, ok := layer.(*apisecurity.Layer)
	if !ok {
		t.Fatalf("buildAPISecurity built %T, want *apisecurity.Layer", layer)
	}

	cfg.WAF.APISecurity.SkipPaths[0] = "/mutated"
	cfg.WAF.APISecurity.APIKeys.Keys[0].KeyHash = sha256Hex("different")

	skipResult := apiLayer.Process(&engine.RequestContext{
		Path:     "/healthz",
		Headers:  map[string][]string{},
		Metadata: map[string]any{},
	})
	if skipResult.Action != engine.ActionPass {
		t.Fatalf("skip path action = %v, want pass", skipResult.Action)
	}

	authResult := apiLayer.Process(&engine.RequestContext{
		Path: "/secure",
		Headers: map[string][]string{
			"X-API-Key": {plainKey},
		},
		QueryParams: map[string][]string{},
		Metadata:    map[string]any{},
	})
	if authResult.Action != engine.ActionPass {
		t.Fatalf("api key action = %v, want pass with original copied key", authResult.Action)
	}
}

func TestBuildAPIValidation_CopiesSchemas(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation.Enabled = true
	cfg.WAF.APIValidation.ValidateRequest = true
	cfg.WAF.APIValidation.ValidateResponse = true
	cfg.WAF.APIValidation.StrictMode = true
	cfg.WAF.APIValidation.BlockOnViolation = true
	cfg.WAF.APIValidation.ViolationScore = 55
	cfg.WAF.APIValidation.CacheSize = 321
	cfg.WAF.APIValidation.Schemas = []config.SchemaSourceConfig{{
		Path:      "/tmp/openapi.yaml",
		Type:      "openapi",
		AutoLearn: true,
	}}

	layer, err := buildAPIValidation(cfg)
	if err != nil {
		t.Fatalf("buildAPIValidation: %v", err)
	}
	validationLayer, ok := layer.(*apivalidation.Layer)
	if !ok {
		t.Fatalf("buildAPIValidation built %T, want *apivalidation.Layer", layer)
	}

	cfg.WAF.APIValidation.Schemas[0].Path = "/mutated"
	cfg.WAF.APIValidation.Schemas[0].Type = "jsonschema"
	cfg.WAF.APIValidation.Schemas[0].AutoLearn = false

	stored := unexportedField[*apivalidation.Config](t, validationLayer, "config")
	if stored == nil {
		t.Fatal("validation config is nil")
	}
	if stored.CacheSize != 321 || !stored.Enabled || !stored.ValidateRequest || !stored.ValidateResponse || !stored.StrictMode || !stored.BlockOnViolation || stored.ViolationScore != 55 {
		t.Fatalf("stored config mismatch: %#v", stored)
	}
	if len(stored.Schemas) != 1 {
		t.Fatalf("stored schemas len = %d, want 1", len(stored.Schemas))
	}
	if stored.Schemas[0].Path != "/tmp/openapi.yaml" || stored.Schemas[0].Type != "openapi" || !stored.Schemas[0].AutoLearn {
		t.Fatalf("stored schema = %#v, want original copy", stored.Schemas[0])
	}
}

func TestBuildLayerWithContext_RateLimitAutoBanClampsTTL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.AutoBan.Enabled = true
	cfg.WAF.IPACL.AutoBan.DefaultTTL = 10 * time.Minute
	cfg.WAF.IPACL.AutoBan.MaxTTL = time.Minute
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []config.RateLimitRule{{
		ID:           "global",
		Scope:        "ip",
		Limit:        1,
		Window:       time.Minute,
		Burst:        1,
		Action:       "block",
		AutoBanAfter: 1,
	}}

	ctx := &BuildContext{}
	if _, ok, err := BuildLayerWithContext("ip_acl", cfg, ctx); err != nil || !ok || ctx.IPACLLayer == nil {
		t.Fatalf("BuildLayerWithContext ip_acl = ok:%v err:%v ctx:%#v", ok, err, ctx)
	}
	layer, ok, err := BuildLayerWithContext("rate_limit", cfg, ctx)
	if err != nil || !ok {
		t.Fatalf("BuildLayerWithContext rate_limit = ok:%v err:%v", ok, err)
	}
	rateLayer := layer.Layer.(*ratelimit.Layer)
	rateLayer.OnAutoBan("203.0.113.99", "ttl-clamp")
	bans := ctx.IPACLLayer.ActiveBans()
	if len(bans) != 1 {
		t.Fatalf("active bans = %#v, want one", bans)
	}
	if ttl := time.Until(bans[0].ExpiresAt); ttl > 2*time.Minute {
		t.Fatalf("ban ttl = %v, want clamped near %v", ttl, time.Minute)
	}
}

func TestBuildIPACL_InvalidCIDRReturnsError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"not-a-cidr"}

	layer, err := buildIPACL(&BuildContext{}, cfg)
	if err == nil {
		t.Fatalf("expected buildIPACL error, got layer=%v", layer)
	}
}

func TestBuildDetection_CopiesDetectorsAndExclusions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Detectors = map[string]config.DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 2.5},
	}
	cfg.WAF.Detection.Exclusions = []config.ExclusionConfig{{
		Path:      "/healthz",
		Detectors: []string{"sqli"},
		Reason:    "health check",
	}}

	layer, err := buildDetection(cfg)
	if err != nil {
		t.Fatalf("buildDetection: %v", err)
	}
	if layer.Name() != "detection" {
		t.Fatalf("layer name = %q, want detection", layer.Name())
	}
}

func sha256Hex(value string) string {
	hash := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func unexportedField[T any](t *testing.T, obj any, name string) T {
	t.Helper()
	field := reflect.ValueOf(obj).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("field %q not found on %T", name, obj)
	}
	value := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
	cast, ok := value.(T)
	if !ok {
		t.Fatalf("field %q type = %T, want %T", name, value, *new(T))
	}
	return cast
}
