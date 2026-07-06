package layerregistry

import (
	"reflect"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
)

func TestEffectivePipeline_DefaultConfigIsOrdered(t *testing.T) {
	cfg := config.DefaultConfig()

	entries := EffectivePipeline(cfg)
	if len(entries) == 0 {
		t.Fatal("default pipeline is empty")
	}

	for i := 1; i < len(entries); i++ {
		prev, current := entries[i-1], entries[i]
		if prev.Order > current.Order {
			t.Fatalf("pipeline not ordered: %s(%d) before %s(%d)", prev.Name, prev.Order, current.Name, current.Order)
		}
	}
}

func TestEffectivePipeline_ReflectsEnabledConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.Detection.Enabled = false

	entries := EffectivePipeline(cfg)
	assertPipelineContains(t, entries, "ip_acl", engine.OrderIPACL)
	assertPipelineContains(t, entries, "rate_limit", engine.OrderRateLimit)
	assertPipelineContains(t, entries, "response", engine.OrderResponse)
	assertPipelineOmits(t, entries, "detection")
}

func TestEffectivePipeline_ResponseIsAlwaysActive(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Response.SecurityHeaders.Enabled = false
	cfg.WAF.Response.DataMasking.Enabled = false
	cfg.WAF.Response.ErrorPages.Mode = ""

	assertPipelineContains(t, EffectivePipeline(cfg), "response", engine.OrderResponse)
}

func TestEffectivePipeline_NilConfig(t *testing.T) {
	if got := EffectivePipeline(nil); got != nil {
		t.Fatalf("EffectivePipeline(nil) = %#v, want nil", got)
	}
}

func TestDefaultRegistryHasUniqueNames(t *testing.T) {
	seen := map[string]struct{}{}
	for _, descriptor := range DefaultRegistry() {
		if descriptor.Name == "" {
			t.Fatal("registry contains descriptor with empty name")
		}
		if descriptor.RuntimeName == "" {
			t.Fatalf("descriptor %q has empty runtime name", descriptor.Name)
		}
		if _, ok := seen[descriptor.Name]; ok {
			t.Fatalf("duplicate descriptor name %q", descriptor.Name)
		}
		seen[descriptor.Name] = struct{}{}
		if descriptor.Enabled == nil {
			t.Fatalf("descriptor %q has nil Enabled function", descriptor.Name)
		}
	}
}

func TestDefaultRegistryDescriptorInventoryIsIntentional(t *testing.T) {
	descriptors := DefaultRegistry()
	got := make([]PipelineEntry, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Build == nil && descriptor.ContextBuild == nil {
			t.Fatalf("descriptor %q has no builder", descriptor.Name)
		}
		if descriptor.Build != nil && descriptor.ContextBuild != nil {
			t.Fatalf("descriptor %q has both Build and ContextBuild; choose one construction path", descriptor.Name)
		}
		got = append(got, PipelineEntry{
			Name:        descriptor.Name,
			RuntimeName: descriptor.RuntimeName,
			Order:       descriptor.Order,
		})
	}

	want := []PipelineEntry{
		{Name: "ip_acl", RuntimeName: "ipacl", Order: engine.OrderIPACL},
		{Name: "threat_intelligence", RuntimeName: "threat_intel", Order: engine.OrderThreatIntel},
		{Name: "cors", RuntimeName: "cors", Order: engine.OrderCORS},
		{Name: "custom_rules", RuntimeName: "rules", Order: engine.OrderRules},
		{Name: "rate_limit", RuntimeName: "ratelimit", Order: engine.OrderRateLimit},
		{Name: "ato_protection", RuntimeName: "ato_protection", Order: engine.OrderATO},
		{Name: "api_security", RuntimeName: "api_security", Order: engine.OrderAPISecurity},
		{Name: "api_validation", RuntimeName: "apivalidation", Order: engine.OrderAPIValidation},
		{Name: "sanitizer", RuntimeName: "sanitizer", Order: engine.OrderSanitizer},
		{Name: "crs", RuntimeName: "crs", Order: engine.OrderCRS},
		{Name: "detection", RuntimeName: "detection", Order: engine.OrderDetection},
		{Name: "virtual_patch", RuntimeName: "virtualpatch", Order: engine.OrderVirtualPatch},
		{Name: "dlp", RuntimeName: "dlp", Order: engine.OrderDLP},
		{Name: "bot_detection", RuntimeName: "botdetect", Order: engine.OrderBotDetect},
		{Name: "client_side", RuntimeName: "clientside", Order: engine.OrderClientSide},
		{Name: "response", RuntimeName: "response", Order: engine.OrderResponse},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registry descriptor inventory changed\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPipelineSummaryMatchesEffectivePipelineShape(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.Detection.Enabled = false

	entries := EffectivePipeline(cfg)
	summary := PipelineSummary(cfg)
	if len(summary) != len(entries) {
		t.Fatalf("summary length = %d, want %d", len(summary), len(entries))
	}
	for i, entry := range entries {
		got := summary[i]
		want := map[string]any{
			"name":         entry.Name,
			"runtime_name": entry.RuntimeName,
			"order":        entry.Order,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("summary[%d] = %#v, want %#v", i, got, want)
		}
		if len(got) != 3 {
			t.Fatalf("summary[%d] has unexpected fields: %#v", i, got)
		}
	}
}

func TestBuildLayer_BuildsMigratedLayers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.ThreatIntel.Enabled = true
	cfg.WAF.ATOProtection.Enabled = true
	cfg.WAF.APISecurity.Enabled = true
	cfg.WAF.APISecurity.JWT.Enabled = false
	cfg.WAF.APISecurity.APIKeys.Enabled = false
	cfg.WAF.APIValidation.Enabled = true
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CustomRules.Enabled = true
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.VirtualPatch.Enabled = true
	cfg.WAF.VirtualPatch.AutoUpdate = false
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.BotDetection.Enabled = true
	cfg.WAF.ClientSide.Enabled = true

	for _, tc := range []struct {
		name        string
		runtimeName string
		order       int
	}{
		{name: "ip_acl", runtimeName: "ipacl", order: engine.OrderIPACL},
		{name: "threat_intelligence", runtimeName: "threat_intel", order: engine.OrderThreatIntel},
		{name: "ato_protection", runtimeName: "ato_protection", order: engine.OrderATO},
		{name: "api_security", runtimeName: "api_security", order: engine.OrderAPISecurity},
		{name: "api_validation", runtimeName: "apivalidation", order: engine.OrderAPIValidation},
		{name: "cors", runtimeName: "cors", order: engine.OrderCORS},
		{name: "custom_rules", runtimeName: "rules", order: engine.OrderRules},
		{name: "rate_limit", runtimeName: "ratelimit", order: engine.OrderRateLimit},
		{name: "crs", runtimeName: "crs", order: engine.OrderCRS},
		{name: "sanitizer", runtimeName: "sanitizer", order: engine.OrderSanitizer},
		{name: "detection", runtimeName: "detection", order: engine.OrderDetection},
		{name: "virtual_patch", runtimeName: "virtualpatch", order: engine.OrderVirtualPatch},
		{name: "dlp", runtimeName: "dlp", order: engine.OrderDLP},
		{name: "bot_detection", runtimeName: "botdetect", order: engine.OrderBotDetect},
		{name: "client_side", runtimeName: "clientside", order: engine.OrderClientSide},
		{name: "response", runtimeName: "response", order: engine.OrderResponse},
	} {
		layer, ok, err := BuildLayer(tc.name, cfg)
		if err != nil {
			t.Fatalf("BuildLayer(%q) returned error: %v", tc.name, err)
		}
		if !ok {
			t.Fatalf("BuildLayer(%q) ok=false", tc.name)
		}
		if layer.Order != tc.order {
			t.Fatalf("BuildLayer(%q) order = %d, want %d", tc.name, layer.Order, tc.order)
		}
		if layer.Layer == nil || layer.Layer.Name() != tc.runtimeName {
			t.Fatalf("BuildLayer(%q) runtime layer = %#v, want %q", tc.name, layer.Layer, tc.runtimeName)
		}
	}
}

func TestBuildLayerWithContext_RegistersThreatIntelStartHook(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ThreatIntel.Enabled = true

	ctx := &BuildContext{}
	layer, ok, err := BuildLayerWithContext("threat_intelligence", cfg, ctx)
	if err != nil {
		t.Fatalf("BuildLayerWithContext threat_intelligence returned error: %v", err)
	}
	if !ok {
		t.Fatal("BuildLayerWithContext threat_intelligence ok=false")
	}
	if layer.Layer == nil || layer.Layer.Name() != "threat_intel" {
		t.Fatalf("threat_intelligence layer = %#v", layer.Layer)
	}
	if len(ctx.StartHooks) != 1 {
		t.Fatalf("start hooks = %#v, want one hook", ctx.StartHooks)
	}
	if ctx.StartHooks[0].Name != "threat_intelligence" || ctx.StartHooks[0].Run == nil {
		t.Fatalf("unexpected start hook %#v", ctx.StartHooks[0])
	}
	ctx.RunStartHooks()
	ctx.RunStartHooks()
}

func TestBuildLayerWithContext_WiresRateLimitAutoBanToIPACL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.AutoBan.Enabled = true
	cfg.WAF.IPACL.AutoBan.DefaultTTL = time.Minute
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
	if err != nil {
		t.Fatalf("BuildLayerWithContext rate_limit returned error: %v", err)
	}
	if !ok {
		t.Fatal("BuildLayerWithContext rate_limit ok=false")
	}
	rateLayer, ok := layer.Layer.(*ratelimit.Layer)
	if !ok {
		t.Fatalf("rate_limit built %T, want *ratelimit.Layer", layer.Layer)
	}
	if rateLayer.OnAutoBan == nil {
		t.Fatal("rate limit auto-ban callback was not wired")
	}
	rateLayer.OnAutoBan("203.0.113.10", "test")
	if bans := ctx.IPACLLayer.ActiveBans(); len(bans) != 1 || bans[0].IP != "203.0.113.10" {
		t.Fatalf("auto-ban callback wrote bans %#v", bans)
	}
}

func TestBuildLayer_DisabledLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = false

	if layer, ok, err := BuildLayer("sanitizer", cfg); err != nil || ok || layer.Layer != nil {
		t.Fatalf("BuildLayer disabled sanitizer = (%#v, %v, %v), want empty/false/nil", layer, ok, err)
	}
}

func TestBuildLayer_UnknownLayer(t *testing.T) {
	if _, _, err := BuildLayer("does_not_exist", config.DefaultConfig()); err == nil {
		t.Fatal("expected unknown descriptor error")
	}
}

func TestBuildLayerWithContext_NilConfig(t *testing.T) {
	layer, ok, err := BuildLayerWithContext("ip_acl", nil, &BuildContext{})
	if ok || err != nil {
		t.Fatalf("expected ok=false, err=nil with nil config; got ok=%v, err=%v", ok, err)
	}
	if layer.Layer != nil {
		t.Error("expected nil layer")
	}
}

func TestRunStartHooks_NilReceiver(t *testing.T) {
	var ctx *BuildContext
	ctx.RunStartHooks() // should not panic
}

func TestRunStartHooks_NilRun(t *testing.T) {
	ctx := &BuildContext{
		StartHooks: []StartHook{
			{Name: "nil-run", Run: nil},
		},
	}
	ctx.RunStartHooks() // should not panic
}

func assertPipelineContains(t *testing.T, entries []PipelineEntry, name string, order int) {
	t.Helper()
	for _, entry := range entries {
		if entry.Name == name {
			if entry.Order != order {
				t.Fatalf("entry %q order = %d, want %d", name, entry.Order, order)
			}
			return
		}
	}
	t.Fatalf("pipeline does not contain %q: %#v", name, entries)
}

func assertPipelineOmits(t *testing.T, entries []PipelineEntry, name string) {
	t.Helper()
	for _, entry := range entries {
		if entry.Name == name {
			t.Fatalf("pipeline contains %q: %#v", name, entries)
		}
	}
}
