package guardianwaf

import (
	"github.com/ersinkoc/guardianwaf/internal/config"
)

// Option is a functional option for configuring the WAF engine.
type Option func(*config.Config)

// WithMode sets the WAF operation mode.
// Valid values: ModeEnforce, ModeMonitor, ModeDisabled.
func WithMode(mode string) Option {
	return func(cfg *config.Config) {
		cfg.Mode = mode
	}
}

// WithThreshold sets the block and log score thresholds.
// Block threshold must be greater than log threshold.
func WithThreshold(block, log int) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Detection.Threshold.Block = block
		cfg.WAF.Detection.Threshold.Log = log
	}
}

// WithDetector enables or disables a specific detector with the given multiplier.
// Valid detector names: "sqli", "xss", "lfi", "cmdi", "xxe", "ssrf".
func WithDetector(name string, enabled bool, multiplier float64) Option {
	return func(cfg *config.Config) {
		if cfg.WAF.Detection.Detectors == nil {
			cfg.WAF.Detection.Detectors = make(map[string]config.DetectorConfig)
		}
		cfg.WAF.Detection.Detectors[name] = config.DetectorConfig{
			Enabled:    enabled,
			Multiplier: multiplier,
		}
	}
}

// WithMaxBodySize sets the maximum allowed request body size in bytes.
func WithMaxBodySize(size int64) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Sanitizer.MaxBodySize = size
	}
}

// WithMaxURLLength sets the maximum allowed URL length in bytes.
func WithMaxURLLength(length int) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Sanitizer.MaxURLLength = length
	}
}

// WithMaxHeaderSize sets the maximum allowed total header size in bytes.
func WithMaxHeaderSize(size int) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Sanitizer.MaxHeaderSize = size
	}
}

// WithIPWhitelist sets the IP whitelist.
func WithIPWhitelist(ips ...string) Option {
	return func(cfg *config.Config) {
		cfg.WAF.IPACL.Whitelist = append(cfg.WAF.IPACL.Whitelist, ips...)
	}
}

// WithIPBlacklist sets the IP blacklist.
func WithIPBlacklist(ips ...string) Option {
	return func(cfg *config.Config) {
		cfg.WAF.IPACL.Blacklist = append(cfg.WAF.IPACL.Blacklist, ips...)
	}
}

// WithBotDetection enables or disables bot detection.
func WithBotDetection(enabled bool) Option {
	return func(cfg *config.Config) {
		cfg.WAF.BotDetection.Enabled = enabled
	}
}

// WithSecurityHeaders enables or disables security header injection.
func WithSecurityHeaders(enabled bool) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Response.SecurityHeaders.Enabled = enabled
	}
}

// WithDataMasking enables or disables response data masking.
func WithDataMasking(enabled bool) Option {
	return func(cfg *config.Config) {
		cfg.WAF.Response.DataMasking.Enabled = enabled
	}
}

// WithMaxEvents sets the maximum number of events to keep in memory.
func WithMaxEvents(n int) Option {
	return func(cfg *config.Config) {
		cfg.Events.MaxEvents = n
	}
}
