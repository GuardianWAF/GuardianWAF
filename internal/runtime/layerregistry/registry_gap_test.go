package layerregistry

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/layers/threatintel"
)

func TestBuildLayerWithRegistry_DescriptorEdgeCases(t *testing.T) {
	cfg := config.DefaultConfig()
	enabled := func(*config.Config) bool { return true }

	t.Run("missing builder", func(t *testing.T) {
		layer, ok, err := buildLayerWithRegistry("empty", cfg, nil, []Descriptor{{
			Name:    "empty",
			Enabled: enabled,
		}})
		if err != nil || ok || layer.Layer != nil {
			t.Fatalf("buildLayerWithRegistry missing builder = (%#v, %v, %v), want empty/false/nil", layer, ok, err)
		}
	})

	t.Run("builder error", func(t *testing.T) {
		wantErr := errors.New("constructor failed")
		_, ok, err := buildLayerWithRegistry("broken", cfg, nil, []Descriptor{{
			Name:    "broken",
			Enabled: enabled,
			Build: func(*config.Config) (engine.Layer, error) {
				return nil, wantErr
			},
		}})
		if ok || !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "build broken layer") {
			t.Fatalf("buildLayerWithRegistry builder error = ok:%v err:%v", ok, err)
		}
	})

	t.Run("nil layer", func(t *testing.T) {
		_, ok, err := buildLayerWithRegistry("nil", cfg, nil, []Descriptor{{
			Name:    "nil",
			Enabled: enabled,
			Build: func(*config.Config) (engine.Layer, error) {
				return nil, nil
			},
		}})
		if ok || err == nil || !strings.Contains(err.Error(), "nil layer") {
			t.Fatalf("buildLayerWithRegistry nil layer = ok:%v err:%v", ok, err)
		}
	})
}

func TestEffectivePipeline_EqualOrdersUseNames(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CustomRules.Enabled = true

	entries := EffectivePipeline(cfg)
	corsIndex, rulesIndex := -1, -1
	for i, entry := range entries {
		switch entry.Name {
		case "cors":
			corsIndex = i
		case "custom_rules":
			rulesIndex = i
		}
	}
	if corsIndex < 0 || rulesIndex < 0 || corsIndex >= rulesIndex {
		t.Fatalf("equal-order entries not sorted by name: %#v", entries)
	}
}

func TestBuildCustomRules_InvalidGeoIPInputReturnsEmpty(t *testing.T) {
	t.Cleanup(func() { engine.SetGeoIPLookup(nil) })

	cfg := config.DefaultConfig()
	cfg.WAF.CustomRules.Enabled = true
	if _, err := buildCustomRules(&BuildContext{GeoIPDB: geoip.New()}, cfg); err != nil {
		t.Fatalf("buildCustomRules: %v", err)
	}

	ev := engine.NewEvent(&engine.RequestContext{
		ClientIP:  net.IP{1, 2},
		Headers:   map[string][]string{},
		StartTime: time.Unix(1, 0),
	}, 200)
	if ev.CountryCode != "" || ev.CountryName != "" {
		t.Fatalf("invalid IP GeoIP result = (%q, %q), want empty", ev.CountryCode, ev.CountryName)
	}
}

func TestBuildThreatIntel_ConstructorError(t *testing.T) {
	wantErr := errors.New("threat constructor failed")
	original := newThreatIntelLayer
	newThreatIntelLayer = func(*threatintel.Config) (*threatintel.Layer, error) {
		return nil, wantErr
	}
	t.Cleanup(func() { newThreatIntelLayer = original })

	layer, err := buildThreatIntel(&BuildContext{}, config.DefaultConfig())
	if layer != nil || !errors.Is(err, wantErr) {
		t.Fatalf("buildThreatIntel constructor error = layer:%v err:%v", layer, err)
	}
}
