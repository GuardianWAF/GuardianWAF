// Package main is the CLI entry point for GuardianWAF.
// It supports subcommands: serve, sidecar, check, validate, version, and help.

//go:build !http3

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/mcp"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// Build-time variables set by goreleaser or -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// osExit and signalNotify are injectable for testing.
var (
	osExit       = os.Exit
	signalNotify = signal.Notify
	signalStop   = signal.Stop
)

func init() {
	// Register UA parser so Event structs get browser/OS/device info
	engine.SetUAParser(func(ua string) (browser, brVersion, os, deviceType string, isBot bool) {
		p := botdetect.ParseUserAgent(ua)
		return p.Browser, p.BrVersion, p.OS, p.DeviceType, p.IsBot
	})
}

func main() {
	osExit(runMain(os.Args))
}

func runMain(args []string) int {
	if len(args) < 2 {
		printUsage()
		return 1
	}

	switch args[1] {
	case "serve":
		cmdServe(args[2:])
	case "sidecar":
		cmdSidecar(args[2:])
	case "check":
		cmdCheck(args[2:])
	case "validate":
		cmdValidate(args[2:])
	case "test-alert":
		cmdTestAlert(args[2:])
	case "healthcheck":
		cmdHealthcheck()
	case "setup":
		cmdSetup(args[2:])
	case "version":
		cmdVersion()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[1])
		printUsage()
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Println(`guardianwaf — Zero-dependency WAF. One binary. Total protection.

USAGE:
  guardianwaf <command> [options]

COMMANDS:
  serve       Start in standalone reverse proxy mode (full features)
  sidecar     Start in lightweight sidecar proxy mode
  check       Test a request against the WAF (dry-run)
  validate    Validate a configuration file
  test-alert  Send test alert to configured targets
  setup       Interactive first-time setup
  version     Print version information
  help        Show help

Run 'guardianwaf <command> --help' for command-specific options.`)
}

// cmdVersion prints version information.
func cmdVersion() {
	fmt.Printf("guardianwaf %s (commit: %s, built: %s)\n", version, commit, date)
}

// cmdHealthcheck performs a health check and exits with appropriate code.
func cmdHealthcheck() {
	// Simple health check - just verify the binary runs
	fmt.Println("OK")
	os.Exit(0)
}

// cmdSetup provides interactive first-time setup.
func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	configPath := fs.String("config", DefaultConfigPath(), "Path to config file")
	fs.StringVar(configPath, "c", DefaultConfigPath(), "Path to config file (short)")
	force := fs.Bool("force", false, "Overwrite existing config")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	// Check if config already exists
	if _, err := os.Stat(*configPath); err == nil && !*force {
		fmt.Printf("Config file '%s' already exists. Use --force to overwrite.\n", *configPath)
		fmt.Println("Or run: guardianwaf serve -c", *configPath)
		return
	}

	banner := `
╔═══════════════════════════════════════════════════════════╗
║           GuardianWAF Production Setup Wizard               ║
║     Zero-dependency Web Application Firewall               ║
╚═══════════════════════════════════════════════════════════╝
`
	fmt.Print(banner)

	// Generate secure password
	dashboardPassword := generateDashboardPassword()

	// ============ SERVER SETTINGS ============
	fmt.Println("\n━━━ Server Settings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Listen address (HTTP) [0.0.0.0:8088]: ")
	listen := readLine(":8088")

	fmt.Print("WAF mode (enforce/monitor/disabled) [enforce]: ")
	mode := readLine("enforce")
	if mode == "" {
		mode = "enforce"
	}

	fmt.Print("Enable TLS/SSL? (yes/no) [no]: ")
	tlsEnabled := readLine("no") == "yes"

	var tlsConfig string
	var tlsListen string
	if tlsEnabled {
		fmt.Print("TLS listen port [0.0.0.0:8443]: ")
		tlsListen = readLine(":8443")
		fmt.Print("TLS certificate file path: ")
		certFile := readLine("")
		fmt.Print("TLS private key file path: ")
		keyFile := readLine("")
		fmt.Print("Enable HTTP->HTTPS redirect? (yes/no) [yes]: ")
		httpRedirect := readLine("yes") == "yes"
		if certFile != "" && keyFile != "" {
			tlsConfig = fmt.Sprintf(`
tls:
  enabled: true
  listen: "%s"
  http_redirect: %t
  cert_file: "%s"
  key_file: "%s"`, tlsListen, httpRedirect, certFile, keyFile)
		} else {
			tlsConfig = fmt.Sprintf(`
tls:
  enabled: true
  listen: "%s"
  http_redirect: true`, tlsListen)
		}
	} else {
		tlsConfig = `
tls:
  enabled: false`
	}

	// ============ UPSTREAMS ============
	fmt.Println("\n━━━ Upstream Backend(s) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Number of backends [1]: ")
	numBackends := readLine("1")
	if numBackends == "" {
		numBackends = "1"
	}

	n := 1
	if _, err := fmt.Sscanf(numBackends, "%d", &n); err != nil {
		n = 1 // Invalid input, use default
	}
	if n < 1 {
		n = 1
	}
	if n > 10 {
		n = 10
	}

	var targets []string
	for i := 0; i < n; i++ {
		fmt.Printf("  Backend #%d URL: ", i+1)
		url := readLine("")
		if url == "" {
			url = "http://localhost:3000"
		}
		fmt.Printf("  Backend #%d weight (1-10) [1]: ", i+1)
		weight := readLine("1")
		if weight == "" {
			weight = "1"
		}
		targets = append(targets, fmt.Sprintf(`      - url: "%s"
        weight: %s`, url, weight))
	}

	// Build upstream targets string
	upstreamsTargets := strings.Join(targets, "\n")

	// Load balancing
	fmt.Print("Load balancing strategy (round_robin/weighted/least_conn/ip_hash) [weighted]: ")
	lb := readLine("weighted")

	// Health check
	fmt.Print("Enable health checks? (yes/no) [yes]: ")
	hcEnabled := readLine("yes") == "yes"

	var healthCheck string
	if hcEnabled {
		fmt.Print("  Health check path [/healthz]: ")
		hcPath := readLine("/healthz")
		fmt.Print("  Health check interval (e.g., 10s, 30s) [10s]: ")
		hcInterval := readLine("10s")
		fmt.Print("  Health check timeout (e.g., 5s) [5s]: ")
		hcTimeout := readLine("5s")
		healthCheck = fmt.Sprintf(`
    health_check:
      enabled: true
      path: "%s"
      interval: %s
      timeout: %s`, hcPath, hcInterval, hcTimeout)
	}

	// ============ ROUTING ============
	fmt.Println("\n━━━ Routing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Route domain/host pattern [*]: ")
	host := readLine("*")

	fmt.Print("Route path prefix [/]: ")
	path := readLine("/")

	// ============ WAF SETTINGS ============
	fmt.Println("\n━━━ WAF Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Block threshold (1-100) [50]: ")
	blockThresh := readLine("50")
	fmt.Print("Log threshold (1-100) [25]: ")
	logThresh := readLine("25")

	fmt.Println("  Attack detectors to enable (all enabled by default):")
	fmt.Print("  - SQL Injection (yes/no) [yes]: ")
	sqli := readLine("yes") == "yes"
	fmt.Print("  - Cross-Site Scripting (yes/no) [yes]: ")
	xss := readLine("yes") == "yes"
	fmt.Print("  - Local File Inclusion (yes/no) [yes]: ")
	lfi := readLine("yes") == "yes"
	fmt.Print("  - Command Injection (yes/no) [yes]: ")
	cmdi := readLine("yes") == "yes"
	fmt.Print("  - XXE (yes/no) [yes]: ")
	xxe := readLine("yes") == "yes"
	fmt.Print("  - SSRF (yes/no) [yes]: ")
	ssrf := readLine("yes") == "yes"

	var detectors []string
	if sqli {
		detectors = append(detectors, "sqli")
	}
	if xss {
		detectors = append(detectors, "xss")
	}
	if lfi {
		detectors = append(detectors, "lfi")
	}
	if cmdi {
		detectors = append(detectors, "cmdi")
	}
	if xxe {
		detectors = append(detectors, "xxe")
	}
	if ssrf {
		detectors = append(detectors, "ssrf")
	}

	detectorsConfig := fmt.Sprintf(`      sqli:
        enabled: %t
        multiplier: 1.0
      xss:
        enabled: %t
        multiplier: 1.0
      lfi:
        enabled: %t
        multiplier: 1.0
      cmdi:
        enabled: %t
        multiplier: 1.0
      xxe:
        enabled: %t
        multiplier: 1.0
      ssrf:
        enabled: %t
        multiplier: 1.0`, sqli, xss, lfi, cmdi, xxe, ssrf)

	// ============ BOT DETECTION ============
	fmt.Println("\n━━━ Bot Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable bot detection? (yes/no) [yes]: ")
	botEnabled := readLine("yes") == "yes"

	var botConfig string
	if botEnabled {
		fmt.Print("  Bot action (block/challenge/log) [block]: ")
		botMode := readLine("block")
		fmt.Print("  Enable JA3 fingerprinting? (yes/no) [yes]: ")
		ja3 := readLine("yes") == "yes"
		fmt.Print("  Enable JA4 fingerprinting? (yes/no) [yes]: ")
		ja4 := readLine("yes") == "yes"
		_ = ja4 // nolint:errcheck // ja4 result read into local var for future use; CLI scaffolding currently only uses fmt.Sprintf
		botConfig = fmt.Sprintf(`
  bot_detection:
    enabled: true
    mode: %s
    tls_fingerprint:
      enabled: %t
      known_bots_action: block
      unknown_action: log
      mismatch_action: log
    user_agent:
      enabled: true
      block_empty: true
      block_known_scanners: true`, botMode, ja3)
	} else {
		botConfig = `
  bot_detection:
    enabled: false`
	}

	// ============ RATE LIMITING ============
	fmt.Println("\n━━━ Rate Limiting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable rate limiting? (yes/no) [yes]: ")
	rlEnabled := readLine("yes") == "yes"

	var rateLimitConfig string
	rlAutoBan := false
	rlBanDur := "15m"
	if rlEnabled {
		fmt.Print("  Requests per minute [100]: ")
		rlRpm := readLine("100")
		fmt.Print("  Burst size [20]: ")
		rlBurst := readLine("20")
		fmt.Print("  Enable auto-ban? (yes/no) [yes]: ")
		rlAutoBan = readLine("yes") == "yes"
		fmt.Print("  Ban duration (e.g., 15m, 1h) [15m]: ")
		rlBanDur = readLine("15m")
		rateLimitConfig = fmt.Sprintf(`
  rate_limit:
    enabled: true
    rules:
      - id: global
        scope: ip
        limit: %s
        window: 1m
        burst: %s
        action: block`, rlRpm, rlBurst)
	} else {
		rateLimitConfig = `
  rate_limit:
    enabled: false`
	}

	// ============ CORS ============
	fmt.Println("\n━━━ CORS Settings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable CORS? (yes/no) [yes]: ")
	corsEnabled := readLine("yes") == "yes"

	var corsConfig string
	if corsEnabled {
		fmt.Print("  Allowed origins (comma-separated, * for any) [*]: ")
		origins := readLine("*")
		fmt.Print("  Allowed methods (comma-separated) [GET,POST,PUT,DELETE,OPTIONS]: ")
		methods := readLine("GET,POST,PUT,DELETE,OPTIONS")
		corsConfig = fmt.Sprintf(`
  cors:
  enabled: true
  allow_origins:
    - "%s"
  allow_methods:
    - %s
  allow_headers:
    - "*"
  max_age_seconds: 86400`, origins, strings.ReplaceAll(methods, ",", "\n    - "))
	} else {
		corsConfig = `
  cors:
  enabled: false`
	}

	// ============ ATO PROTECTION ============
	fmt.Println("\n━━━ Account Takeover Protection ━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable ATO protection? (yes/no) [yes]: ")
	atoEnabled := readLine("yes") == "yes"

	var atoConfig string
	if atoEnabled {
		fmt.Print("  Max login attempts [5]: ")
		atoMax := readLine("5")
		fmt.Print("  Detection window (e.g., 10m) [10m]: ")
		atoWindow := readLine("10m")
		fmt.Print("  Ban duration (e.g., 30m) [30m]: ")
		atoBan := readLine("30m")
		atoConfig = fmt.Sprintf(`
  ato_protection:
  enabled: true
  brute_force:
    enabled: true
    max_attempts_per_ip: %s
    window: %s
    block_duration: %s`, atoMax, atoWindow, atoBan)
	} else {
		atoConfig = `
  ato_protection:
  enabled: false`
	}

	// ============ ALERTING ============
	fmt.Println("\n━━━ Alerting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable alerting? (yes/no) [no]: ")
	alertEnabled := readLine("no") == "yes"

	var alertConfig string
	if alertEnabled {
		fmt.Print("  Webhook URL for alerts: ")
		webhookURL := readLine("")
		fmt.Print("  Alert on events (block,challenge,log) [block,challenge]: ")
		events := readLine("block,challenge")
		fmt.Print("  Minimum score threshold [50]: ")
		minScore := readLine("50")
		if webhookURL != "" {
			alertConfig = fmt.Sprintf(`
alerting:
  enabled: true
  webhooks:
    - name: default
      url: "%s"
      events:
        - %s
      min_score: %s`, webhookURL, strings.ReplaceAll(events, ",", "\n        - "), minScore)
		} else {
			alertConfig = `
alerting:
  enabled: false`
		}
	} else {
		alertConfig = `
alerting:
  enabled: false`
	}

	// ============ DOCKER ============
	fmt.Println("\n━━━ Docker Auto-Discovery ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Enable Docker auto-discovery? (yes/no) [yes]: ")
	dockerEnabled := readLine("yes") == "yes"

	var dockerConfig string
	if dockerEnabled {
		fmt.Print("  Docker socket path [/var/run/docker.sock]: ")
		dockerSocket := readLine("/var/run/docker.sock")
		dockerConfig = fmt.Sprintf(`
docker:
  enabled: true
  socket_path: "%s"
  label_prefix: gwaf
  poll_interval: 5s`, dockerSocket)
	} else {
		dockerConfig = `
docker:
  enabled: false`
	}

	// ============ DASHBOARD ============
	fmt.Println("\n━━━ Dashboard ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Dashboard port [0.0.0.0:9443]: ")
	dashboardListen := readLine(":9443")

	// ============ SUMMARY ============
	fmt.Println("\n━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Mode: %s\n", mode)
	fmt.Printf("  Listen: %s\n", listen)
	fmt.Printf("  TLS: %s\n", boolStr(tlsEnabled))
	if tlsEnabled {
		fmt.Printf("  TLS Listen: %s\n", tlsListen)
	}
	fmt.Printf("  Upstreams: %d\n", n)
	fmt.Printf("  Load Balancer: %s\n", lb)
	fmt.Printf("  Health Check: %s\n", boolStr(hcEnabled))
	fmt.Printf("  Detectors: %d enabled\n", len(detectors))
	fmt.Printf("  Bot Detection: %s\n", boolStr(botEnabled))
	fmt.Printf("  Rate Limiting: %s\n", boolStr(rlEnabled))
	fmt.Printf("  CORS: %s\n", boolStr(corsEnabled))
	fmt.Printf("  ATO Protection: %s\n", boolStr(atoEnabled))
	fmt.Printf("  Alerting: %s\n", boolStr(alertEnabled))
	fmt.Printf("  Docker Discovery: %s\n", boolStr(dockerEnabled))
	fmt.Printf("  Dashboard: %s\n", dashboardListen)

	fmt.Print("\nGenerate config? (yes/no) [yes]: ")
	if readLine("yes") != "yes" {
		fmt.Println("Setup cancelled.")
		return
	}

	fmt.Println("\nGenerating configuration...")

	// Ensure parent directory exists
	if dirIdx := strings.LastIndex(*configPath, "/"); dirIdx > 0 {
		if err := os.MkdirAll((*configPath)[:dirIdx], 0755); err != nil {
			fmt.Printf("warning: failed to create directory: %v\n", err)
		}
	}

	// Build config string piecewise
	var buf strings.Builder

	buf.WriteString("# GuardianWAF Configuration\n")
	buf.WriteString("# Generated by guardianwaf setup on " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	buf.WriteString("# ============================================================\n")
	buf.WriteString("# Mode: " + mode + " | Listen: " + listen + " | TLS: " + boolStr(tlsEnabled) + "\n")
	buf.WriteString("# Dashboard: " + dashboardListen + " | Upstreams: " + fmt.Sprintf("%d", n) + "\n")
	buf.WriteString("# ============================================================\n\n")

	buf.WriteString("mode: " + mode + "\n")
	buf.WriteString("listen: \"" + listen + "\"\n")
	buf.WriteString("allow_private_upstreams: true\n")
	buf.WriteString(tlsConfig + "\n")

	buf.WriteString("upstreams:\n")
	buf.WriteString("  - name: default\n")
	buf.WriteString("    load_balancer: " + lb + "\n")
	buf.WriteString("    targets:\n")
	buf.WriteString(upstreamsTargets + "\n")
	buf.WriteString(healthCheck + "\n")

	buf.WriteString("routes:\n")
	buf.WriteString("  - path: \"" + path + "\"\n")
	buf.WriteString("    upstream: default\n\n")
	_ = host // nolint:errcheck // host result read from readLine; unused in generated config but preserved for future CLI use

	buf.WriteString("logging:\n")
	buf.WriteString("  level: info\n")
	buf.WriteString("  format: json\n")
	buf.WriteString("  log_blocked: true\n")
	buf.WriteString("  log_allowed: false\n\n")

	buf.WriteString("waf:\n")
	buf.WriteString("  ip_acl:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    auto_ban:\n")
	buf.WriteString("      enabled: " + fmt.Sprintf("%t", rlAutoBan) + "\n")
	buf.WriteString("      default_ttl: " + rlBanDur + "\n")
	buf.WriteString("      max_ttl: 24h\n")
	buf.WriteString("  sanitizer:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    max_url_length: 8192\n")
	buf.WriteString("    max_header_size: 8192\n")
	buf.WriteString("    max_header_count: 100\n")
	buf.WriteString("    max_body_size: 10485760\n")
	buf.WriteString("    max_cookie_size: 4096\n")
	buf.WriteString("    block_null_bytes: true\n")
	buf.WriteString("    normalize_encoding: true\n")
	buf.WriteString("    strip_hop_by_hop: true\n")
	buf.WriteString("  detection:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    threshold:\n")
	buf.WriteString("      block: " + blockThresh + "\n")
	buf.WriteString("      log: " + logThresh + "\n")
	buf.WriteString("    detectors:\n")
	buf.WriteString(detectorsConfig + "\n")
	buf.WriteString("  challenge:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    difficulty: 20\n")
	buf.WriteString(botConfig + "\n")
	buf.WriteString(rateLimitConfig + "\n")
	buf.WriteString(corsConfig + "\n")
	buf.WriteString(atoConfig + "\n\n")

	buf.WriteString(alertConfig + "\n\n")

	buf.WriteString(dockerConfig + "\n\n")

	buf.WriteString("dashboard:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  listen: \"" + dashboardListen + "\"\n")
	buf.WriteString("  api_key: \"" + dashboardPassword + "\"\n\n")

	buf.WriteString("mcp:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  transport: stdio\n")

	configContent := buf.String()

	if err := os.WriteFile(*configPath, []byte(configContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Setup Complete!                            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Config saved to: %s\n", *configPath)
	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────────────┐")
	fmt.Println("  │  IMPORTANT - Save these credentials:                │")
	fmt.Println("  │                                                     │")
	fmt.Printf("  │  Dashboard password: %s                   │\n", dashboardPassword)
	fmt.Println("  │                                                     │")
	fmt.Println("  └─────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Printf("    sudo systemctl enable guardianwaf\n")
	fmt.Printf("    sudo systemctl start guardianwaf\n")
	fmt.Printf("    sudo systemctl status guardianwaf\n")
	fmt.Println()
	fmt.Printf("  Or run directly:\n")
	fmt.Printf("    guardianwaf serve -c %s\n", *configPath)
	fmt.Println()
}

// readLine reads a line from stdin with a default value
func readLine(defaultVal string) string {
	var input string
	if _, err := fmt.Scanln(&input); err != nil {
		// EOF or error - use default
		return defaultVal
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// boolStr converts bool to yes/no string
func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// --------------------------------------------------------------------------
// serve
// --------------------------------------------------------------------------

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: platform-specific)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	listenAddr := fs.String("listen", "", "Override listen address")
	fs.StringVar(listenAddr, "l", "", "Override listen address (short)")
	mode := fs.String("mode", "", "Override WAF mode (enforce/monitor/disabled)")
	fs.StringVar(mode, "m", "", "Override WAF mode (short)")
	dashboardAddr := fs.String("dashboard", "", "Override dashboard listen address")
	logLevel := fs.String("log-level", "", "Override log level")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	// 1. Load config
	explicitPath := *configPath != ""
	cfg := loadConfig(*configPath, explicitPath)

	// 2. Apply environment variable overrides, then CLI overrides
	config.LoadEnv(cfg)
	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *dashboardAddr != "" {
		cfg.Dashboard.Listen = *dashboardAddr
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	// 3. Validate
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		osExit(1)
	}

	// 4. Create runtime engine
	eventStore, eventBus, eng, err := setupRuntimeEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize runtime engine: %v\n", err)
		osExit(1)
		return
	}
	logRuntimeEngineReady(eng, cfg)

	// 7. Set up JS challenge service if enabled
	challengeSvc, err := setupChallengeService(cfg, eng)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating challenge service: %v\n", err)
		return
	}

	// 8. Build handler
	serveMux := http.NewServeMux()

	// Prometheus-compatible metrics endpoint
	registerMetricsHandler(serveMux, eng)

	// Mount challenge verification endpoint
	registerChallengeHandler(serveMux, challengeSvc)

	registerClientSideReportHandlers(serveMux)

	// Mount upstream proxy or default handler
	var proxyRuntimeMu sync.RWMutex
	upstream, proxyRouter, proxyHealthCheckers := buildProxyRuntime(cfg, standaloneNoUpstreamHandler())
	registerProbeHandlers(serveMux, cfg, eng, func() *proxy.Router {
		proxyRuntimeMu.RLock()
		defer proxyRuntimeMu.RUnlock()
		return proxyRouter
	})
	// Use atomic handler so rebuild can swap it without re-registering on mux
	var upstreamHandler atomic.Value
	upstreamHandler.Store(eng.Middleware(upstream))
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		upstreamHandler.Load().(http.Handler).ServeHTTP(w, r)
	})
	handler := http.Handler(serveMux)

	// 8. Start TLS server if enabled
	tlsSrv, certStore, diskStore := buildTLSServer(cfg, serveMux, handler)

	// 9. Start HTTP server
	// If TLS is enabled with http_redirect, HTTP server redirects to HTTPS
	srv := newRuntimeHTTPServer(cfg.Listen, buildHTTPHandler(cfg, serveMux, handler))

	// 10. Start MCP server if enabled
	var mcpSSE *mcp.SSEHandler
	if cfg.MCP.Enabled {
		// SSE transport — served via dashboard port, auth-protected
		mcpSrv := mcp.NewServer(nil, nil)
		mcpSrv.SetServerInfo("guardianwaf", version)
		mcpSrv.SetEngine(&mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: eventStore, alertMgr: nil})
		mcpSrv.RegisterAllTools()
		mcpSSE = mcp.NewSSEHandler(mcpSrv, cfg.Dashboard.APIKey)
		eng.Logs.Info("MCP SSE transport enabled")
	}

	// 10b. Start dashboard if enabled
	var dashSrv *http.Server
	var sseBroadcaster *dashboard.SSEBroadcaster
	var dash *dashboard.Dashboard
	if cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" {
		// Use API key as persistent session secret so sessions survive restarts
		if cfg.Dashboard.APIKey != "" {
			dashboard.SetSessionSecret(cfg.Dashboard.APIKey)
		}
		dashSrv, sseBroadcaster, dash = startDashboard(cfg, eng)
		wireDashboardProxyControls(dash, cfg, eng, *configPath, &proxyRouter, &proxyHealthCheckers, &proxyRuntimeMu, &upstreamHandler, diskStore)
		wireDashboardRules(dash, cfg, eng)
	}

	// Register MCP SSE routes on dashboard mux
	if mcpSSE != nil && dash != nil {
		mcpSSE.RegisterRoutes(dash.Mux())
		eng.Logs.Info("MCP SSE endpoints registered: GET /mcp/sse, POST /mcp/message")
	}

	tenantManager, tenantMiddleware := setupTenantRuntime(cfg, eng, dash, &upstreamHandler)
	aiAnalyzer := setupAIRuntime(cfg, eng, eventBus, dash)

	var eventConsumerWG sync.WaitGroup

	// 10c. Start alerting/webhooks if enabled
	alertMgr := setupAlertingRuntime(cfg, eng, eventBus, eventStore, dash, &eventConsumerWG, os.Stdin, os.Stdout)

	// 10d. Start Docker auto-discovery if enabled
	dockerWatcher := setupDockerRuntime(cfg, eng, dash, &proxyRouter, &proxyHealthCheckers, &proxyRuntimeMu, &upstreamHandler, tenantMiddleware)

	// 10d. Wire SSE broadcaster to event bus for real-time dashboard updates
	if sseBroadcaster != nil {
		startEventConsumer(eventBus, &eventConsumerWG, 256, func(event engine.Event) {
			sseBroadcaster.BroadcastEvent(event)
		})
	}

	// 11. Start periodic cleanup goroutine for layer state (rate limit buckets, bot trackers, etc.)
	cleanupStop, cleanupWG := startPeriodicCleanup(eng, tenantManager, periodicCleanupInterval)

	// 12. Graceful shutdown handling
	shutdown := make(chan os.Signal, 1)
	signalNotify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	defer signalStop(shutdown)

	startServeHTTPServer(cfg, eng, srv)
	startServeTLSServer(cfg, eng, tlsSrv)
	logServeRuntimeStatus(cfg, eng)

	<-shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	shutdownServeRuntime(ctx, serveShutdownResources{
		server:              srv,
		tlsServer:           tlsSrv,
		dashboardServer:     dashSrv,
		certStore:           certStore,
		engine:              eng,
		proxyRuntimeMu:      &proxyRuntimeMu,
		proxyHealthCheckers: &proxyHealthCheckers,
		cleanupStop:         cleanupStop,
		cleanupWG:           cleanupWG,
		dockerWatcher:       dockerWatcher,
		aiAnalyzer:          aiAnalyzer,
		alertManager:        alertMgr,
		dashboard:           dash,
		eventConsumerWG:     &eventConsumerWG,
	})
}

// --------------------------------------------------------------------------
// sidecar
// --------------------------------------------------------------------------

func cmdSidecar(args []string) {
	fs := flag.NewFlagSet("sidecar", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (optional)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	upstream := fs.String("upstream", "", "Upstream URL (required if no config)")
	fs.StringVar(upstream, "u", "", "Upstream URL (short)")
	listenAddr := fs.String("listen", "", "Listen address")
	fs.StringVar(listenAddr, "l", "", "Listen address (short)")
	mode := fs.String("mode", "", "Override WAF mode")
	fs.StringVar(mode, "m", "", "Override WAF mode (short)")
	logLevel := fs.String("log-level", "", "Override log level")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	// Load config or build from flags
	var cfg *config.Config
	if *configPath != "" {
		cfg = loadConfig(*configPath, true)
		config.LoadEnv(cfg)
	} else {
		cfg = config.DefaultConfig()
		config.LoadEnv(cfg)
	}

	// Sidecar overrides: no dashboard, no MCP
	cfg.Dashboard.Enabled = false
	cfg.MCP.Enabled = false

	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}
	if *mode != "" {
		cfg.Mode = *mode
	}

	// Handle upstream flag
	if *upstream != "" {
		cfg.Upstreams = []config.UpstreamConfig{
			{
				Name: "default",
				Targets: []config.TargetConfig{
					{URL: *upstream, Weight: 1},
				},
			},
		}
		cfg.Routes = []config.RouteConfig{
			{Path: "/", Upstream: "default"},
		}
	}

	// Validate we have an upstream
	if len(cfg.Upstreams) == 0 {
		fmt.Fprintf(os.Stderr, "Error: --upstream is required when no config file is provided\n")
		osExit(1)
	}

	// Validate
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		osExit(1)
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	_, _, eng, err := setupRuntimeEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize runtime engine: %v\n", err)
		osExit(1)
		return
	}

	if _, err := setupChallengeService(cfg, eng); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating challenge service: %v\n", err)
		return
	}

	// Build handler with probe and metrics endpoints
	mux := http.NewServeMux()
	registerMetricsHandler(mux, eng)

	registerClientSideReportHandlers(mux)

	proxyHandler, sidecarRouter, sidecarHealthCheckers := buildProxyRuntime(cfg, sidecarNoUpstreamHandler())
	registerProbeHandlers(mux, cfg, eng, func() *proxy.Router {
		return sidecarRouter
	})
	mux.Handle("/", eng.Middleware(proxyHandler))

	srv := newRuntimeHTTPServer(cfg.Listen, mux)

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signalNotify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	defer signalStop(shutdown)

	go func() {
		fmt.Printf("GuardianWAF sidecar %s starting on %s -> %s\n", version, cfg.Listen, upstreamSummary(cfg))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			osExit(1)
		}
	}()

	<-shutdown
	fmt.Println("\nShutting down sidecar...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx) // nolint:errcheck // graceful shutdown; error logged upstream if it matters
	stopHealthCheckers(sidecarHealthCheckers)
	eng.Close()
	fmt.Println("GuardianWAF sidecar stopped.")
}

// --------------------------------------------------------------------------
// check (dry-run)
// --------------------------------------------------------------------------

// headerSlice is a custom flag type for repeatable -H flags.
type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, ", ") }
func (h *headerSlice) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// CheckOptions holds options for the check command.
type CheckOptions struct {
	ConfigPath string
	URL        string
	Method     string
	Headers    []string
	Body       string
	Verbose    bool
}

// CheckResult holds the result of a check request.
type CheckResult struct {
	Action   string
	Score    int
	Duration time.Duration
	Findings []engine.Finding
}

// runCheck executes a request check against the WAF engine.
// This is the testable version of cmdCheck.
func runCheck(opts *CheckOptions) (*CheckResult, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("--url is required")
	}

	// Load config
	explicitPath := opts.ConfigPath != ""
	cfg := loadConfig(opts.ConfigPath, explicitPath)
	config.LoadEnv(cfg)

	// Create engine
	eventStore := events.NewMemoryStore(1000)
	eventBus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}
	defer eng.Close()

	// Wire layers
	if addErr := addLayers(eng, cfg); addErr != nil {
		return nil, fmt.Errorf("failed to wire WAF layers: %w", addErr)
	}

	// Build HTTP request
	fullURL := opts.URL
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "http://localhost" + fullURL
	}

	var bodyReader *strings.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequestWithContext(context.Background(), opts.Method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply custom headers
	for _, h := range opts.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Set default remote addr for IP extraction
	req.RemoteAddr = "127.0.0.1:0"

	// Run check
	event := eng.Check(req)

	return &CheckResult{
		Action:   event.Action.String(),
		Score:    event.Score,
		Duration: event.Duration,
		Findings: event.Findings,
	}, nil
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: platform-specific)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	urlStr := fs.String("url", "", "URL path to test (e.g., /search?q=test)")
	method := fs.String("method", "GET", "HTTP method")
	verbose := fs.Bool("verbose", false, "Show detailed detection results")
	fs.BoolVar(verbose, "v", false, "Verbose (short)")
	var headers headerSlice
	fs.Var(&headers, "H", "HTTP header in 'Name: Value' format (repeatable)")
	body := fs.String("body", "", "Request body content")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	result, err := runCheck(&CheckOptions{
		ConfigPath: *configPath,
		URL:        *urlStr,
		Method:     *method,
		Headers:    headers,
		Body:       *body,
		Verbose:    *verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		osExit(1)
	}

	// Print results
	fmt.Printf("Action:   %s\n", result.Action)
	fmt.Printf("Score:    %d\n", result.Score)
	fmt.Printf("Duration: %s\n", result.Duration)

	switch result.Action {
	case "block":
		fmt.Println("Result:   BLOCKED")
	case "log":
		fmt.Println("Result:   LOGGED (suspicious)")
	default:
		fmt.Println("Result:   PASSED")
	}

	if len(result.Findings) > 0 {
		fmt.Printf("Findings: %d\n", len(result.Findings))
		if *verbose {
			fmt.Println()
			for i, f := range result.Findings {
				fmt.Printf("  [%d] %s (%s)\n", i+1, f.Description, f.DetectorName)
				fmt.Printf("      Severity: %s | Score: %d | Confidence: %.2f\n", f.Severity, f.Score, f.Confidence)
				if f.MatchedValue != "" {
					fmt.Printf("      Match:    %s\n", f.MatchedValue)
				}
				fmt.Printf("      Location: %s\n", f.Location)
			}
		}
	} else {
		fmt.Println("Findings: 0")
	}

	// Exit code based on action
	if result.Action == "block" {
		osExit(2)
	}
}

// --------------------------------------------------------------------------
// validate
// --------------------------------------------------------------------------

// ValidateResult holds the result of config validation for testing.
type ValidateResult struct {
	Config  *config.Config
	Summary *ConfigSummary
}

// runValidate validates a config file and returns the result or error.
// This is the testable version of cmdValidate.
func runValidate(configPath string) (*ValidateResult, error) {
	cfg, summary, err := validateConfigFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("validation failed:\n%w", err)
	}
	return &ValidateResult{Config: cfg, Summary: summary}, nil
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: platform-specific)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	result, err := runValidate(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		osExit(1)
	}

	cfg := result.Config
	summary := result.Summary

	fmt.Printf("Configuration %s is valid.\n", *configPath)
	fmt.Printf("  Mode:       %s\n", cfg.Mode)
	fmt.Printf("  Listen:     %s\n", cfg.Listen)
	fmt.Printf("  Upstreams:  %d\n", summary.Upstreams)
	fmt.Printf("  Routes:     %d\n", summary.Routes)
	fmt.Printf("  Detection:  %v (%d detectors)\n", cfg.WAF.Detection.Enabled, summary.Detectors)
	fmt.Printf("  Rate Limit: %v (%d rules)\n", cfg.WAF.RateLimit.Enabled, summary.RateLimitRules)
	fmt.Printf("  IP ACL:     %v\n", cfg.WAF.IPACL.Enabled)
	fmt.Printf("  Bot Detect: %v\n", cfg.WAF.BotDetection.Enabled)
	fmt.Printf("  Dashboard:  %v (%s)\n", cfg.Dashboard.Enabled, cfg.Dashboard.Listen)
	fmt.Printf("  MCP:        %v (%s)\n", cfg.MCP.Enabled, cfg.MCP.Transport)
	fmt.Printf("  Alerting:   %v (%d webhooks, %d emails)\n", cfg.Alerting.Enabled, len(cfg.Alerting.Webhooks), len(cfg.Alerting.Emails))
}

func cmdTestAlert(args []string) {
	fs := flag.NewFlagSet("test-alert", flag.ExitOnError)
	configPath := fs.String("config", DefaultConfigPath(), "Path to config file")
	target := fs.String("target", "", "Target name (webhook or email)")
	all := fs.Bool("all", false, "Test all configured targets")
	_ = fs.Parse(args) // nolint:errcheck // flag.Parse after Validate* call; never fails in practice

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
		return
	}

	if !cfg.Alerting.Enabled {
		fmt.Fprintf(os.Stderr, "Alerting is not enabled in configuration\n")
		osExit(1)
	}

	// Create alerting manager
	var targets []alerting.WebhookTarget
	for _, w := range cfg.Alerting.Webhooks {
		targets = append(targets, alerting.WebhookTarget{
			Name:     w.Name,
			URL:      w.URL,
			Type:     w.Type,
			Events:   w.Events,
			MinScore: w.MinScore,
			Cooldown: w.Cooldown,
			Headers:  w.Headers,
		})
	}

	mgr := alerting.NewManagerWithEmail(targets, cfg.Alerting.Emails)

	// Test specific target or all
	if *all {
		fmt.Println("Testing all configured alert targets...")
		for _, w := range cfg.Alerting.Webhooks {
			fmt.Printf("  Testing webhook: %s... ", w.Name)
			if err := mgr.TestAlert(w.Name); err != nil {
				fmt.Printf("FAILED: %v\n", err)
			} else {
				fmt.Println("OK")
			}
		}
		for _, e := range cfg.Alerting.Emails {
			fmt.Printf("  Testing email: %s... ", e.Name)
			if err := mgr.TestAlert(e.Name); err != nil {
				fmt.Printf("FAILED: %v\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	} else if *target != "" {
		fmt.Printf("Testing alert target: %s... ", *target)
		if err := mgr.TestAlert(*target); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			osExit(1)
		}
		fmt.Println("OK")
	} else {
		fmt.Fprintf(os.Stderr, "Usage: guardianwaf test-alert -target=<name> or -all\n")
		fmt.Fprintf(os.Stderr, "\nConfigured targets:\n")
		for _, w := range cfg.Alerting.Webhooks {
			fmt.Fprintf(os.Stderr, "  Webhook: %s (%s)\n", w.Name, w.Type)
		}
		for _, e := range cfg.Alerting.Emails {
			fmt.Fprintf(os.Stderr, "  Email: %s (%s)\n", e.Name, e.SMTPHost)
		}
		osExit(1)
	}
}

// ConfigSummary holds summary information about a loaded config.
type ConfigSummary struct {
	Upstreams      int
	Routes         int
	Detectors      int
	RateLimitRules int
}

// validateConfigFile loads and validates a config file, returning the config and summary.
func validateConfigFile(path string) (*config.Config, *ConfigSummary, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}

	config.LoadEnv(cfg)

	if err := config.Validate(cfg); err != nil {
		return nil, nil, fmt.Errorf("validation: %w", err)
	}

	summary := &ConfigSummary{
		Upstreams:      len(cfg.Upstreams),
		Routes:         len(cfg.Routes),
		Detectors:      len(cfg.WAF.Detection.Detectors),
		RateLimitRules: len(cfg.WAF.RateLimit.Rules),
	}

	return cfg, summary, nil
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// DefaultConfigPath returns the platform-specific default config file path.
func DefaultConfigPath() string {
	// Linux: /etc/guardianwaf/guardianwaf.yaml
	// Windows: %PROGRAMDATA%\GuardianWAF\guardianwaf.yaml (C:\ProgramData\GuardianWAF\guardianwaf.yaml)
	if os.PathSeparator == '/' {
		return "/etc/guardianwaf/guardianwaf.yaml"
	}
	// Windows
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		return pd + string(os.PathSeparator) + "GuardianWAF" + string(os.PathSeparator) + "guardianwaf.yaml"
	}
	return `C:\ProgramData\GuardianWAF\guardianwaf.yaml`
}

// loadConfig loads config from path, falling back to defaults if the file is not found.
// Supports both single file and directory-based config.
// If explicitPath is true, the path was explicitly provided by user and non-existence is an error.
func loadConfig(path string, explicitPath bool) *config.Config {
	// Use platform-specific default if no path specified
	if path == "" {
		path = DefaultConfigPath()
	}

	// Check if path exists
	info, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		if explicitPath && !isDefaultPath(path) {
			// User explicitly provided a path that doesn't exist - this is an error
			fmt.Fprintf(os.Stderr, "Error: config file not found: %s\n", path)
			osExit(1)
			return nil
		}
		// Default path doesn't exist or relative path doesn't exist - use defaults
		return config.DefaultConfig()
	}

	var cfg *config.Config
	var err error

	if info.IsDir() {
		// Directory-based config
		cfg, err = config.LoadDir(path)
	} else {
		// Single file config (backward compatible)
		cfg, err = config.LoadFile(path)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		osExit(1)
	}
	return cfg
}

// isDefaultPath returns true if path is the platform-specific default config path.
func isDefaultPath(path string) bool {
	if os.PathSeparator == '/' {
		return path == "/etc/guardianwaf/guardianwaf.yaml"
	}
	// Windows
	return path == `C:\ProgramData\GuardianWAF\guardianwaf.yaml` ||
		path == os.Getenv("PROGRAMDATA")+`\GuardianWAF\guardianwaf.yaml`
}
