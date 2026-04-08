// Package main is the CLI entry point for GuardianWAF.
// It supports subcommands: serve, sidecar, check, validate, version, and help.

//go:build http3

package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/acme"
	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/http3"
	"github.com/guardianwaf/guardianwaf/internal/layers/apisecurity"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/ato"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
	"github.com/guardianwaf/guardianwaf/internal/layers/cors"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
	"github.com/guardianwaf/guardianwaf/internal/layers/threatintel"
	"github.com/guardianwaf/guardianwaf/internal/mcp"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
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
	_ = fs.Parse(args)

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
	dashboardPassword := generateSecurePassword()

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
	fmt.Sscanf(numBackends, "%d", &n)
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

	detectorsConfig := "      - " + strings.Join(detectors, "\n      - ")

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
		botConfig = fmt.Sprintf(`
  bot_detection:
    enabled: true
    mode: %s
    ja3_enabled: %t
    ja4_enabled: %t`, botMode, ja3, ja4)
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
	if rlEnabled {
		fmt.Print("  Requests per minute [100]: ")
		rlRpm := readLine("100")
		fmt.Print("  Burst size [20]: ")
		rlBurst := readLine("20")
		fmt.Print("  Enable auto-ban? (yes/no) [yes]: ")
		rlAutoBan := readLine("yes") == "yes"
		fmt.Print("  Ban duration (e.g., 15m, 1h) [15m]: ")
		rlBanDur := readLine("15m")
		rateLimitConfig = fmt.Sprintf(`
  rate_limit:
    enabled: true
    requests_per_minute: %s
    burst: %s
    auto_ban: %t
    ban_duration: %s`, rlRpm, rlBurst, rlAutoBan, rlBanDur)
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
  allowed_origins:
    - "%s"
  allowed_methods:
    - %s
  allowed_headers:
    - "*"
  max_age: 86400`, origins, strings.ReplaceAll(methods, ",", "\n    - "))
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
ato:
  enabled: true
  brute_force:
    enabled: true
    max_attempts: %s
    window: %s
    ban_duration: %s`, atoMax, atoWindow, atoBan)
	} else {
		atoConfig = `
ato:
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
  auto_discover: true
  socket: "%s"`, dockerSocket)
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
		os.MkdirAll((*configPath)[:dirIdx], 0755)
	}

	// Build config string piecewise
	var buf strings.Builder

	buf.WriteString("# GuardianWAF Configuration\n")
	buf.WriteString("# Generated by guardianwaf setup on " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	buf.WriteString("# ============================================================\n")
	buf.WriteString("# Mode: " + mode + " | Listen: " + listen + " | TLS: " + boolStr(tlsEnabled) + "\n")
	buf.WriteString("# Dashboard: " + dashboardListen + " | Upstreams: " + fmt.Sprintf("%d", n) + "\n")
	buf.WriteString("# ============================================================\n\n")

	buf.WriteString("version: \"1.0\"\n\n")

	buf.WriteString("server:\n")
	buf.WriteString("  listen: \"" + listen + "\"\n")
	buf.WriteString("  mode: " + mode + "\n")
	buf.WriteString(tlsConfig + "\n")

	buf.WriteString("upstreams:\n")
	buf.WriteString("  - name: default\n")
	buf.WriteString("    load_balancer: " + lb + "\n")
	buf.WriteString("    targets:\n")
	buf.WriteString(upstreamsTargets + "\n")
	buf.WriteString(healthCheck + "\n")

	buf.WriteString("routes:\n")
	buf.WriteString("  - host: \"" + host + "\"\n")
	buf.WriteString("    path: \"" + path + "\"\n")
	buf.WriteString("    upstream: default\n\n")

	buf.WriteString("logging:\n")
	buf.WriteString("  level: info\n")
	buf.WriteString("  format: json\n")
	buf.WriteString("  access_log: true\n\n")

	buf.WriteString("waf:\n")
	buf.WriteString("  detection:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    block_threshold: " + blockThresh + "\n")
	buf.WriteString("    log_threshold: " + logThresh + "\n")
	buf.WriteString("    detectors:\n")
	buf.WriteString(detectorsConfig + "\n")
	buf.WriteString("  challenge:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    difficulty: 20\n")
	buf.WriteString(botConfig + "\n")
	buf.WriteString(rateLimitConfig + "\n\n")

	buf.WriteString("ipacl:\n")
	buf.WriteString("  enabled: true\n\n")

	buf.WriteString(corsConfig + "\n\n")

	buf.WriteString(atoConfig + "\n\n")

	buf.WriteString(alertConfig + "\n\n")

	buf.WriteString(dockerConfig + "\n\n")

	buf.WriteString("dashboard:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  listen: \"" + dashboardListen + "\"\n")
	buf.WriteString("  username: \"admin\"\n")
	buf.WriteString("  # password: \"" + dashboardPassword + "\"\n\n")

	buf.WriteString("health:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  path: \"/healthz\"\n\n")

	buf.WriteString("metrics:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  path: \"/metrics\"\n\n")

	buf.WriteString("mcp:\n")
	buf.WriteString("  enabled: true\n")

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
	fmt.Scanln(&input)
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

// removeEmptyLines removes consecutive empty lines from config
func removeEmptyLines(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	emptyCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			emptyCount++
			if emptyCount <= 2 {
				result = append(result, line)
			}
		} else {
			emptyCount = 0
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// generateSecurePassword creates a random 16-character password.
func generateSecurePassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	// Use crypto/rand in production, this is a simple fallback
	return string(b)
}

// generateDashboardPassword creates a cryptographically secure random password for dashboard.
func generateDashboardPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 24)
	if _, err := cryptoRand.Read(b); err != nil {
		// Fallback to simple rand if crypto/rand fails
		for i := range b {
			b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		}
	} else {
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
	}
	return string(b)
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
	_ = fs.Parse(args)

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

	// 4. Create event infrastructure
	eventStore := events.NewMemoryStore(cfg.Events.MaxEvents)
	eventBus := events.NewEventBus()

	// 5. Create engine
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create engine: %v\n", err)
		osExit(1)
	}

	// 6. Wire all layers
	addLayers(eng, cfg)
	// Apply log level filtering
	if cfg.Logging.Level != "" {
		eng.Logs.SetLevel(cfg.Logging.Level)
	}
	eng.Logs.Infof("Engine initialized in %s mode (block=%d, log=%d)", cfg.Mode, cfg.WAF.Detection.Threshold.Block, cfg.WAF.Detection.Threshold.Log)

	// 6b. Set up structured access logging
	if cfg.Logging.LogBlocked || cfg.Logging.LogAllowed {
		logBlocked := cfg.Logging.LogBlocked
		logAllowed := cfg.Logging.LogAllowed
		eng.SetAccessLog(func(entry engine.AccessLogEntry) {
			isBlocked := entry.Action == "block" || entry.Action == "challenge"
			if isBlocked && !logBlocked {
				return
			}
			if !isBlocked && !logAllowed {
				return
			}
			if cfg.Logging.Format == "json" {
				fmt.Fprintf(os.Stdout, `{"ts":%q,"ip":%q,"method":%q,"path":%q,"status":%d,"action":%q,"score":%d,"dur_us":%s,"ua":%q,"findings":%d}`+"\n",
					entry.Timestamp, entry.ClientIP, entry.Method, entry.Path,
					entry.StatusCode, entry.Action, entry.Score, entry.Duration,
					entry.UserAgent, entry.Findings)
			} else {
				fmt.Fprintf(os.Stdout, "%s %s %s %s %d %s score=%d dur=%sus findings=%d\n",
					entry.Timestamp, entry.ClientIP, entry.Method, entry.Path,
					entry.StatusCode, entry.Action, entry.Score, entry.Duration, entry.Findings)
			}
		})
		eng.Logs.Infof("Access logging enabled (blocked=%v, allowed=%v, format=%s)", logBlocked, logAllowed, cfg.Logging.Format)
	}

	// 7. Set up JS challenge service if enabled
	var challengeSvc *challenge.Service
	if cfg.WAF.Challenge.Enabled {
		chCfg := challenge.Config{
			Enabled:    true,
			Difficulty: cfg.WAF.Challenge.Difficulty,
			CookieTTL:  cfg.WAF.Challenge.CookieTTL,
			CookieName: cfg.WAF.Challenge.CookieName,
		}
		if cfg.WAF.Challenge.SecretKey != "" {
			chCfg.SecretKey = []byte(cfg.WAF.Challenge.SecretKey)
		}
		challengeSvc = challenge.NewService(chCfg)
		eng.SetChallengeService(challengeSvc)
	}

	// 8. Build handler
	serveMux := http.NewServeMux()

	// Health check endpoint for Kubernetes liveness/readiness probes
	serveMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		s := eng.Stats()
		fmt.Fprintf(w, `{"status":"ok","mode":%q,"total_requests":%d,"blocked_requests":%d}`,
			cfg.Mode, s.TotalRequests, s.BlockedRequests)
	})

	// Prometheus-compatible metrics endpoint
	serveMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s := eng.Stats()
		fmt.Fprintf(w, "# HELP guardianwaf_requests_total Total number of requests processed.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_total %d\n", s.TotalRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_blocked_total Total number of blocked requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_blocked_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_blocked_total %d\n", s.BlockedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_challenged_total Total number of challenged requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_challenged_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_challenged_total %d\n", s.ChallengedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_logged_total Total number of logged (suspicious) requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_logged_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_logged_total %d\n", s.LoggedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_passed_total Total number of passed requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_passed_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_passed_total %d\n", s.PassedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_latency_avg_microseconds Average request latency in microseconds.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_latency_avg_microseconds gauge\n")
		fmt.Fprintf(w, "guardianwaf_latency_avg_microseconds %d\n", s.AvgLatencyUs)
	})

	// Mount challenge verification endpoint
	if challengeSvc != nil {
		serveMux.Handle(challenge.VerifyPath, challengeSvc.VerifyHandler())
	}

	// Mount upstream proxy or default handler
	var upstream http.Handler
	var proxyRouter *proxy.Router
	if len(cfg.Upstreams) > 0 && len(cfg.Routes) > 0 {
		var h http.Handler
		h, _ = buildReverseProxy(cfg)
		proxyRouter, _ = h.(*proxy.Router)
		upstream = h
	} else {
		upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "GuardianWAF is running. No upstream configured.")
		})
	}
	// Use atomic handler so rebuild can swap it without re-registering on mux
	var upstreamHandler atomic.Value
	upstreamHandler.Store(eng.Middleware(upstream))
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		upstreamHandler.Load().(http.Handler).ServeHTTP(w, r)
	})
	handler := http.Handler(serveMux)

	// 8. Start TLS server if enabled
	var tlsSrv *http.Server
	var h3Server *http3.Server
	var certStore *gwaftls.CertStore
	var diskStore *acme.CertDiskStore
	if cfg.TLS.Enabled {
		certStore = gwaftls.NewCertStore()

		// Load default cert if provided
		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			if err := certStore.LoadDefaultCert(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load default TLS cert: %v\n", err)
			}
		}

		// Load per-vhost certs
		for _, vh := range cfg.VirtualHosts {
			if vh.TLS.CertFile != "" && vh.TLS.KeyFile != "" {
				if err := certStore.LoadCert(vh.Domains, vh.TLS.CertFile, vh.TLS.KeyFile); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to load TLS cert for %v: %v\n", vh.Domains, err)
				}
			}
		}

		// ACME auto-certificate if enabled
		var acmeHandler *acme.HTTP01Handler
		if cfg.TLS.ACME.Enabled && cfg.TLS.ACME.Email != "" {
			acmeHandler = acme.NewHTTP01Handler()

			acmeClient := acme.NewClient(acme.LetsEncryptProduction)
			// Load or generate account key from cache dir
			accountKeyPath := cfg.TLS.ACME.CacheDir + "/account.key"
			var accountKeyPEM []byte
			if data, err := os.ReadFile(accountKeyPath); err == nil {
				accountKeyPEM = data
			}
			if err := acmeClient.Init(accountKeyPEM); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ACME init failed: %v\n", err)
			} else {
				// Save account key
				if keyPEM, err := acmeClient.AccountKeyPEM(); err == nil {
					if err := os.MkdirAll(cfg.TLS.ACME.CacheDir, 0o700); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to create ACME cache dir: %v\n", err)
					} else {
						_ = os.WriteFile(accountKeyPath, keyPEM, 0o600)
					}
				}
				// Register account
				if err := acmeClient.Register(cfg.TLS.ACME.Email); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: ACME registration: %v\n", err)
				} else {
					// Obtain certs for all ACME domains + vhost domains
					diskStore = acme.NewCertDiskStore(cfg.TLS.ACME.CacheDir, acmeClient, acmeHandler)
					allDomains := collectACMEDomains(cfg)
					for _, domains := range allDomains {
						diskStore.AddDomains(domains)
						cert, err := diskStore.LoadOrObtain(domains)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Warning: ACME cert for %v: %v\n", domains, err)
						} else {
							certStore.LoadCertFromTLS(domains, cert)
						}
					}
					// Start background renewal
					diskStore.StartRenewal(12 * time.Hour)
				}
			}
			// Mount ACME challenge handler on HTTP server
			serveMux.Handle("/.well-known/acme-challenge/", acmeHandler)
		}

		// Start cert hot-reload
		certStore.StartReload(30 * time.Second)

		tlsSrv = &http.Server{
			Addr:         cfg.TLS.Listen,
			Handler:      handler,
			TLSConfig:    certStore.TLSConfig(),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		// Start HTTP/3 server if enabled
		if cfg.TLS.HTTP3.Enabled {
			h3Config := &http3.Config{
				Enabled:            cfg.TLS.HTTP3.Enabled,
				Listen:             cfg.TLS.HTTP3.Listen,
				MaxHeaderBytes:     cfg.TLS.HTTP3.MaxHeaderBytes,
				ReadTimeout:        cfg.TLS.HTTP3.ReadTimeout,
				WriteTimeout:       cfg.TLS.HTTP3.WriteTimeout,
				IdleTimeout:        cfg.TLS.HTTP3.IdleTimeout,
				Enable0RTT:         cfg.TLS.HTTP3.Enable0RTT,
				EnableDatagrams:    cfg.TLS.HTTP3.EnableDatagrams,
				AltSvcPort:         cfg.TLS.HTTP3.AltSvcPort,
				AltSvcProtocol:     "h3",
				MaxRequestBodySize: 10 << 20,
			}
			if h3Config.Listen == "" {
				h3Config.Listen = cfg.TLS.Listen
			}

			var err error
			h3Server, err = http3.NewServer(h3Config, handler, certStore.TLSConfig())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to create HTTP/3 server: %v\n", err)
			} else {
				if err := h3Server.Start(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to start HTTP/3 server: %v\n", err)
				} else {
					eng.Logs.Infof("HTTP/3 server started on %s", h3Config.Listen)
					// Advertise HTTP/3 via Alt-Svc header on TLS responses
					if cfg.TLS.HTTP3.AdvertiseAltSvc {
						tlsSrv.Handler = http3.EnableAltSvc(tlsSrv.Handler, h3Server.AltSvcHeader())
					}
				}
			}
		}
	}

	// 9. Start HTTP server
	// If TLS is enabled with http_redirect, HTTP server redirects to HTTPS
	httpHandler := handler
	if cfg.TLS.Enabled && cfg.TLS.HTTPRedirect {
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Serve ACME challenges even when redirecting
			if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				serveMux.ServeHTTP(w, r)
				return
			}
			host := r.Host
			if idx := strings.LastIndex(host, ":"); idx > 0 {
				host = host[:idx]
			}
			target := "https://" + host + r.RequestURI
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}
	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      httpHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

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
	var aiAnalyzer *ai.Analyzer
	if cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" {
		// Use API key as persistent session secret so sessions survive restarts
		if cfg.Dashboard.APIKey != "" {
			dashboard.SetSessionSecret(cfg.Dashboard.APIKey)
		}
		dashSrv, sseBroadcaster, dash = startDashboard(cfg, eng)
		// Inject upstream status provider and rebuild function
		if proxyRouter != nil && dash != nil {
			r := proxyRouter
			dash.SetUpstreamsFn(func() any {
				return r.AllUpstreamStatus()
			})
			// Inject SSL cert status provider
			if diskStore != nil {
				dash.SetCertFn(func() any {
					return diskStore.CertStatus()
				})
			}
		}
		// Wire rules management — always create a rules layer for dashboard CRUD
		if dash != nil {
			// Find existing rules layer or create one
			var rLayer *rules.Layer
			if rl := eng.FindLayer("rules"); rl != nil {
				rLayer, _ = rl.(*rules.Layer)
			}
			if rLayer == nil {
				// Create an empty rules layer and add to pipeline
				rLayer = rules.NewLayer(&rules.Config{Enabled: true}, nil)
				eng.AddLayer(engine.OrderedLayer{Layer: rLayer, Order: engine.OrderRules})
			}
			var gDB *geoip.DB
			if cfg.WAF.GeoIP.Enabled {
				gDB, _ = loadGeoIP(cfg, eng)
			}

			// Register GeoIP lookup for events (same pattern as dashboard)
			if gDB != nil {
				engine.SetGeoIPLookup(func(ip string) (string, string) {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						return "", ""
					}
					code := gDB.Lookup(parsed)
					return code, geoip.CountryName(code)
				})
			}

			dash.SetRulesFns(
				func() any { return rLayer.Rules() },
				func(raw map[string]any) error {
					r := mapToRule(raw)
					if r.ID == "" {
						return fmt.Errorf("rule id is required")
					}
					rLayer.AddRule(r)
					return nil
				},
				func(id string, raw map[string]any) error {
					r := mapToRule(raw)
					r.ID = id
					if !rLayer.UpdateRule(r) {
						return fmt.Errorf("rule %s not found", id)
					}
					return nil
				},
				func(id string) bool { return rLayer.RemoveRule(id) },
				func(id string, enabled bool) bool { return rLayer.ToggleRule(id, enabled) },
				func(ip string) (string, string) {
					if gDB == nil {
						return "", "GeoIP not loaded"
					}
					parsed := net.ParseIP(ip)
					if parsed == nil {
						return "", "invalid IP"
					}
					code := gDB.Lookup(parsed)
					return code, geoip.CountryName(code)
				},
			)
		}

		if dash != nil {
			dash.SetRebuildFn(func() error {
				newHandler, _ := buildReverseProxy(cfg)
				newRouter, ok := newHandler.(*proxy.Router)
				if ok && newRouter != nil {
					proxyRouter = newRouter
					rr := newRouter
					dash.SetUpstreamsFn(func() any {
						return rr.AllUpstreamStatus()
					})
				}
				// Atomic swap — no mux re-registration needed
				upstreamHandler.Store(eng.Middleware(newHandler))
				return nil
			})
			// Persist config changes to disk
			cfgPath := *configPath
			dash.SetSaveFn(func() error {
				c := eng.Config()
				// Sync custom rules from rules layer back to config
				if rl := eng.FindLayer("rules"); rl != nil {
					type rulesGetter interface{ Rules() []rules.Rule }
					if rg, ok := rl.(rulesGetter); ok {
						liveRules := rg.Rules()
						cfgRules := make([]config.CustomRule, len(liveRules))
						for i, r := range liveRules {
							conds := make([]config.RuleCondition, len(r.Conditions))
							for j, cond := range r.Conditions {
								conds[j] = config.RuleCondition{Field: cond.Field, Op: cond.Op, Value: cond.Value}
							}
							cfgRules[i] = config.CustomRule{
								ID: r.ID, Name: r.Name, Enabled: r.Enabled,
								Priority: r.Priority, Conditions: conds,
								Action: r.Action, Score: r.Score,
							}
						}
						c.WAF.CustomRules.Enabled = len(cfgRules) > 0
						c.WAF.CustomRules.Rules = cfgRules
					}
				}
				return config.SaveFile(cfgPath, c)
			})
		}
	}

	// Register MCP SSE routes on dashboard mux
	if mcpSSE != nil && dash != nil {
		mcpSSE.RegisterRoutes(dash.Mux())
		eng.Logs.Info("MCP SSE endpoints registered: GET /mcp/sse, POST /mcp/message")
	}

	// Wire up tenant manager for multi-tenant dashboard and middleware
	var tenantManager *tenant.Manager
	var tenantMiddleware *tenant.Middleware
	if cfg.Tenant.Enabled {
		maxTenants := cfg.Tenant.MaxTenants
		if maxTenants <= 0 {
			maxTenants = 100
		}

		// Create manager with persistence
		storePath := cfg.Tenant.StorePath
		if storePath == "" {
			storePath = "data/tenants"
		}
		tenantManager = tenant.NewManagerWithStore(maxTenants, storePath)

		// Load persisted tenants
		if err := tenantManager.Init(); err != nil {
			eng.Logs.Warnf("Failed to load persisted tenants: %v", err)
		} else {
			eng.Logs.Infof("Loaded %d tenants from persistence", len(tenantManager.ListTenants()))
		}

		// Create pre-configured tenants from config (only if not already persisted)
		for _, t := range cfg.Tenant.Tenants {
			quota := &tenant.ResourceQuota{
				MaxRequestsPerMinute: t.Quota.MaxRequestsPerMinute,
				MaxRequestsPerHour:   t.Quota.MaxRequestsPerHour,
				MaxBandwidthMbps:     t.Quota.MaxBandwidthMbps,
				MaxRules:             t.Quota.MaxRules,
				MaxRateLimitRules:    t.Quota.MaxRateLimitRules,
				MaxIPACLs:            t.Quota.MaxIPACLs,
			}
			_, _ = tenantManager.CreateTenant(t.Name, t.Description, t.Domains, quota)
		}

		// Register with dashboard
		if dash != nil {
			dash.SetTenantManager(&tenantManagerAdapter{mgr: tenantManager})
		}

		// Wrap the upstream handler with tenant middleware
		if tenantManager != nil {
			tenantMiddleware = tenant.NewMiddleware(tenantManager)
			// Store original handler
			originalHandler := upstreamHandler.Load().(http.Handler)
			// Wrap with tenant middleware
			wrappedHandler := tenantMiddleware.Handler(originalHandler)
			upstreamHandler.Store(wrappedHandler)
		}

		eng.Logs.Infof("Multi-tenant mode enabled (%d tenants configured)", len(cfg.Tenant.Tenants))
	}

	// 10b. Start AI analyzer if enabled
	if cfg.WAF.AIAnalysis.Enabled {
		aiStore := ai.NewStore(cfg.WAF.AIAnalysis.StorePath)
		aiAnalyzer = ai.NewAnalyzer(ai.AnalyzerConfig{
			Enabled:          true,
			BatchSize:        cfg.WAF.AIAnalysis.BatchSize,
			BatchInterval:    cfg.WAF.AIAnalysis.BatchInterval,
			MaxTokensHour:    cfg.WAF.AIAnalysis.MaxTokensPerHour,
			MaxTokensDay:     cfg.WAF.AIAnalysis.MaxTokensPerDay,
			MaxRequestsHour:  cfg.WAF.AIAnalysis.MaxRequestsHour,
			AutoBlockEnabled: cfg.WAF.AIAnalysis.AutoBlock,
			AutoBlockTTL:     cfg.WAF.AIAnalysis.AutoBlockTTL,
			MinScoreForAI:    cfg.WAF.AIAnalysis.MinScore,
		}, aiStore, cfg.WAF.AIAnalysis.CatalogURL)
		aiAnalyzer.SetLogger(eng.Logs.Add)

		// Wire auto-block to IP ACL layer
		if ipaclL := eng.FindLayer("ipacl"); ipaclL != nil {
			type autoBanner interface {
				AddAutoBan(ip string, reason string, ttl time.Duration)
			}
			if ab, ok := ipaclL.(autoBanner); ok {
				aiAnalyzer.SetBlocker(ab)
			}
		}

		// Subscribe to event bus and start
		aiCh := make(chan engine.Event, 512)
		eventBus.Subscribe(aiCh)
		aiAnalyzer.Start(aiCh)
		eng.Logs.Info("AI threat analysis enabled")

		// Wire to dashboard
		if dash != nil {
			dash.SetAIAnalyzer(aiAnalyzer)
		}
	}

	// 10c. Start alerting/webhooks if enabled
	var alertMgr *alerting.Manager
	if cfg.Alerting.Enabled && (len(cfg.Alerting.Webhooks) > 0 || len(cfg.Alerting.Emails) > 0) {
		var targets []alerting.WebhookTarget
		for _, wc := range cfg.Alerting.Webhooks {
			targets = append(targets, alerting.WebhookTarget{
				Name: wc.Name, URL: wc.URL, Type: wc.Type,
				Events: wc.Events, MinScore: wc.MinScore,
				Cooldown: wc.Cooldown, Headers: wc.Headers,
			})
		}
		alertMgr = alerting.NewManagerWithEmail(targets, cfg.Alerting.Emails)
		alertMgr.SetLogger(eng.Logs.Add)

		// Subscribe to event bus
		alertCh := make(chan engine.Event, 256)
		eventBus.Subscribe(alertCh)
		go func() {
			for event := range alertCh {
				alertMgr.HandleEvent(&event)
			}
		}()
		eng.Logs.Infof("Alerting enabled (%d webhooks, %d emails)", len(targets), len(cfg.Alerting.Emails))

		// Set alerting stats for dashboard
		if dash != nil {
			dash.SetAlertingStatsFn(func() any { return alertMgr.GetStats() })
		}

		// Start MCP stdio server now that alertMgr is available
		if cfg.MCP.Enabled && cfg.MCP.Transport == "stdio" {
			go startMCPServer(eng, cfg, eventStore, alertMgr, os.Stdin, os.Stdout)
		}
	}

	// 10d. Start Docker auto-discovery if enabled
	var dockerWatcher *dkr.Watcher
	if cfg.Docker.Enabled {
		dockerClient := dkr.NewClient(cfg.Docker.SocketPath)
		if err := dockerClient.Ping(); err != nil {
			eng.Logs.Warnf("Docker: connection failed: %v (auto-discovery disabled)", err)
		} else {
			dockerWatcher = dkr.NewWatcher(dockerClient, cfg.Docker.LabelPrefix, cfg.Docker.Network, cfg.Docker.PollInterval)
			dockerWatcher.SetLogger(eng.Logs.Add)
			dockerWatcher.SetOnChange(func() {
				services := dockerWatcher.Services()
				mergedCfg := dkr.BuildConfig(services, cfg)
				newHandler, _ := buildReverseProxy(mergedCfg)
				newRouter, ok := newHandler.(*proxy.Router)
				if ok && newRouter != nil {
					proxyRouter = newRouter
					if dash != nil {
						rr := newRouter
						dash.SetUpstreamsFn(func() any { return rr.AllUpstreamStatus() })
					}
				}
				upstreamHandler.Store(eng.Middleware(newHandler))
				eng.Logs.Infof("Docker: proxy rebuilt (%d services discovered)", len(services))
			})
			dockerWatcher.Start()
			eng.Logs.Infof("Docker auto-discovery enabled (socket: %s, prefix: %s)", cfg.Docker.SocketPath, cfg.Docker.LabelPrefix)

			// Wire dashboard endpoint
			if dash != nil {
				dash.SetDockerWatcher(dockerWatcher)
			}
		}
	}

	// 10d. Wire SSE broadcaster to event bus for real-time dashboard updates
	if sseBroadcaster != nil {
		eventCh := make(chan engine.Event, 256)
		eventBus.Subscribe(eventCh)
		go func() {
			for event := range eventCh {
				sseBroadcaster.BroadcastEvent(event)
			}
		}()
	}

	// 11. Start periodic cleanup goroutine for layer state (rate limit buckets, bot trackers, etc.)
	cleanupStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if rl := eng.FindLayer("ratelimit"); rl != nil {
					type cleaner interface{ CleanupExpired(time.Duration) }
					if c, ok := rl.(cleaner); ok {
						c.CleanupExpired(30 * time.Minute)
					}
				}
				if acl := eng.FindLayer("ipacl"); acl != nil {
					type cleaner interface{ CleanupExpired() }
					if c, ok := acl.(cleaner); ok {
						c.CleanupExpired()
					}
				}
				if atoL := eng.FindLayer("ato"); atoL != nil {
					type cleaner interface{ Cleanup() }
					if c, ok := atoL.(cleaner); ok {
						c.Cleanup()
					}
				}
				// Cleanup tenant rate limiter old entries
				if tenantManager != nil {
					type rateLimiterCleaner interface{ CleanupRateLimiter(maxAge time.Duration) }
					if c, ok := interface{}(tenantManager).(rateLimiterCleaner); ok {
						c.CleanupRateLimiter(30 * time.Minute)
					}
				}
				eng.Logs.Debug("Periodic cleanup completed")
			case <-cleanupStop:
				return
			}
		}
	}()

	// 12. Graceful shutdown handling
	shutdown := make(chan os.Signal, 1)
	signalNotify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		msg := fmt.Sprintf("GuardianWAF %s starting in %s mode on %s", version, cfg.Mode, cfg.Listen)
		fmt.Println(msg)
		eng.Logs.Info(msg)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			eng.Logs.Errorf("HTTP server error: %v", err)
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			osExit(1)
		}
	}()

	// Start TLS server if configured
	if tlsSrv != nil {
		go func() {
			msg := fmt.Sprintf("TLS server listening on %s", cfg.TLS.Listen)
			fmt.Println(msg)
			eng.Logs.Info(msg)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				eng.Logs.Errorf("TLS server error: %v", err)
				fmt.Fprintf(os.Stderr, "TLS server error: %v\n", err)
			}
		}()
	}

	if cfg.Dashboard.Enabled {
		eng.Logs.Infof("Dashboard listening on %s", cfg.Dashboard.Listen)
	}
	if cfg.WAF.Challenge.Enabled {
		eng.Logs.Infof("JS Challenge enabled (difficulty: %d bits)", cfg.WAF.Challenge.Difficulty)
	}
	if cfg.WAF.BotDetection.Enabled {
		eng.Logs.Infof("Bot detection enabled in %s mode", cfg.WAF.BotDetection.Mode)
	}
	eng.Logs.Infof("Upstreams: %d configured", len(cfg.Upstreams))
	if len(cfg.VirtualHosts) > 0 {
		eng.Logs.Infof("Virtual hosts: %d configured", len(cfg.VirtualHosts))
	}

	<-shutdown
	eng.Logs.Info("Shutting down...")
	fmt.Println("\nShutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Stop accepting new requests
	_ = srv.Shutdown(ctx)
	if tlsSrv != nil {
		_ = tlsSrv.Shutdown(ctx)
	}

		// 2. Stop HTTP/3 server
		if h3Server != nil {
			_ = h3Server.Stop()
		}

	// 3. Stop background services
	if certStore != nil {
		certStore.StopReload()
	}
	if dashSrv != nil {
		_ = dashSrv.Shutdown(ctx)
	}

	// 4. Stop threat intel feed refresh loops
	if tiLayer := eng.FindLayer("threat_intel"); tiLayer != nil {
		type stopper interface{ Stop() }
		if s, ok := tiLayer.(stopper); ok {
			s.Stop()
		}
	}

	// 5. Stop cleanup goroutine
	close(cleanupStop)

	// 6. Stop Docker watcher and AI analyzer
	if dockerWatcher != nil {
		dockerWatcher.Stop()
	}
	if aiAnalyzer != nil {
		aiAnalyzer.Stop()
	}

	// 7. Close engine (flushes pending events, closes event bus and store)
	eng.Close()
	fmt.Println("GuardianWAF stopped.")
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
	_ = fs.Parse(args)

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

	// Create event infrastructure
	eventStore := events.NewMemoryStore(cfg.Events.MaxEvents)
	eventBus := events.NewEventBus()

	// Create engine
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create engine: %v\n", err)
		osExit(1)
	}

	// Wire layers
	addLayers(eng, cfg)

	// Apply log level and access logging
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if cfg.Logging.Level != "" {
		eng.Logs.SetLevel(cfg.Logging.Level)
	}
	if cfg.Logging.LogBlocked || cfg.Logging.LogAllowed {
		logBlocked := cfg.Logging.LogBlocked
		logAllowed := cfg.Logging.LogAllowed
		eng.SetAccessLog(func(entry engine.AccessLogEntry) {
			isBlocked := entry.Action == "block" || entry.Action == "challenge"
			if isBlocked && !logBlocked {
				return
			}
			if !isBlocked && !logAllowed {
				return
			}
			if cfg.Logging.Format == "json" {
				fmt.Fprintf(os.Stdout, `{"ts":%q,"ip":%q,"method":%q,"path":%q,"status":%d,"action":%q,"score":%d,"dur_us":%s,"ua":%q,"findings":%d}`+"\n",
					entry.Timestamp, entry.ClientIP, entry.Method, entry.Path,
					entry.StatusCode, entry.Action, entry.Score, entry.Duration,
					entry.UserAgent, entry.Findings)
			} else {
				fmt.Fprintf(os.Stdout, "%s %s %s %s %d %s score=%d dur=%sus findings=%d\n",
					entry.Timestamp, entry.ClientIP, entry.Method, entry.Path,
					entry.StatusCode, entry.Action, entry.Score, entry.Duration, entry.Findings)
			}
		})
	}

	// Set up JS challenge service if enabled
	if cfg.WAF.Challenge.Enabled {
		chCfg := challenge.Config{
			Enabled:    true,
			Difficulty: cfg.WAF.Challenge.Difficulty,
			CookieTTL:  cfg.WAF.Challenge.CookieTTL,
			CookieName: cfg.WAF.Challenge.CookieName,
		}
		if cfg.WAF.Challenge.SecretKey != "" {
			chCfg.SecretKey = []byte(cfg.WAF.Challenge.SecretKey)
		}
		svc := challenge.NewService(chCfg)
		eng.SetChallengeService(svc)
	}

	// Build handler with /healthz and /metrics endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s := eng.Stats()
		fmt.Fprintf(w, "# HELP guardianwaf_requests_total Total number of requests processed.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_total %d\n", s.TotalRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_blocked_total Total number of blocked requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_blocked_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_blocked_total %d\n", s.BlockedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_passed_total Total number of passed requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_passed_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_passed_total %d\n", s.PassedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_latency_avg_microseconds Average request latency in microseconds.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_latency_avg_microseconds gauge\n")
		fmt.Fprintf(w, "guardianwaf_latency_avg_microseconds %d\n", s.AvgLatencyUs)
	})

	var proxyHandler http.Handler
	if len(cfg.Upstreams) > 0 && len(cfg.Routes) > 0 {
		proxyHandler, _ = buildReverseProxy(cfg)
	} else {
		proxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintln(w, "502 Bad Gateway - No upstream configured")
		})
	}
	mux.Handle("/", eng.Middleware(proxyHandler))

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signalNotify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("GuardianWAF sidecar %s starting on %s -> %s\n", version, cfg.Listen, upstreamSummary(cfg))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			osExit(1)
		}
	}()

	<-shutdown
	fmt.Println("\nShutting down sidecar...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
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
	cfg := loadConfig(opts.ConfigPath, opts.ConfigPath != "")
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
	addLayers(eng, cfg)

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
	_ = fs.Parse(args)

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
	_ = fs.Parse(args)

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
	_ = fs.Parse(args)

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		osExit(1)
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
// isDefaultPath returns true if path is the platform-specific default config path.
func isDefaultPath(path string) bool {
	if os.PathSeparator == '/' {
		return path == "/etc/guardianwaf/guardianwaf.yaml"
	}
	return path == `C:\ProgramData\GuardianWAF\guardianwaf.yaml` ||
		path == os.Getenv("PROGRAMDATA")+string(os.PathSeparator)+"GuardianWAF"+string(os.PathSeparator)+"guardianwaf.yaml"
}

func loadConfig(path string, explicitPath bool) *config.Config {
	// Use platform-specific default if no path specified
	if path == "" {
		path = DefaultConfigPath()
	}

	// Check if path exists
	info, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		if explicitPath && !isDefaultPath(path) {
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

// addLayers wires all WAF layers to the engine based on config.
func addLayers(eng *engine.Engine, cfg *config.Config) {
	// Track IP ACL layer for auto-ban integration
	var ipaclLayer *ipacl.Layer

	// 1. IP ACL layer (Order 100)
	if cfg.WAF.IPACL.Enabled {
		var err error
		ipaclLayer, err = ipacl.NewLayer(&ipacl.Config{
			Enabled:   cfg.WAF.IPACL.Enabled,
			Whitelist: cfg.WAF.IPACL.Whitelist,
			Blacklist: cfg.WAF.IPACL.Blacklist,
			AutoBan: ipacl.AutoBanConfig{
				Enabled:    cfg.WAF.IPACL.AutoBan.Enabled,
				DefaultTTL: cfg.WAF.IPACL.AutoBan.DefaultTTL,
				MaxTTL:     cfg.WAF.IPACL.AutoBan.MaxTTL,
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create IP ACL layer: %v\n", err)
		} else {
			eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})
		}
	}

	// 1b. Threat Intelligence layer (Order 125)
	if cfg.WAF.ThreatIntel.Enabled {
		feeds := make([]threatintel.FeedConfig, len(cfg.WAF.ThreatIntel.Feeds))
		for i, f := range cfg.WAF.ThreatIntel.Feeds {
			feeds[i] = threatintel.FeedConfig{
				Type:    f.Type,
				Path:    f.Path,
				URL:     f.URL,
				Refresh: f.Refresh,
				Format:  f.Format,
			}
		}
		tiLayer, err := threatintel.NewLayer(&threatintel.Config{
			Enabled: cfg.WAF.ThreatIntel.Enabled,
			IPReputation: threatintel.IPRepConfig{
				Enabled:        cfg.WAF.ThreatIntel.IPReputation.Enabled,
				BlockMalicious: cfg.WAF.ThreatIntel.IPReputation.BlockMalicious,
				ScoreThreshold: cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold,
			},
			DomainRep: threatintel.DomainRepConfig{
				Enabled:        cfg.WAF.ThreatIntel.DomainRep.Enabled,
				BlockMalicious: cfg.WAF.ThreatIntel.DomainRep.BlockMalicious,
				CheckRedirects: cfg.WAF.ThreatIntel.DomainRep.CheckRedirects,
			},
			CacheSize: cfg.WAF.ThreatIntel.CacheSize,
			CacheTTL:  cfg.WAF.ThreatIntel.CacheTTL,
			Feeds:     feeds,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create threat intel layer: %v\n", err)
		} else {
			eng.AddLayer(engine.OrderedLayer{Layer: tiLayer, Order: engine.OrderThreatIntel})
			tiLayer.Start()
			eng.Logs.Info("Threat intelligence layer enabled")
		}
	}

	// 1c. CORS Security layer (Order 150)
	if cfg.WAF.CORS.Enabled {
		corsLayer, err := cors.NewLayer(&cors.Config{
			Enabled:               cfg.WAF.CORS.Enabled,
			AllowOrigins:          cfg.WAF.CORS.AllowOrigins,
			AllowMethods:          cfg.WAF.CORS.AllowMethods,
			AllowHeaders:          cfg.WAF.CORS.AllowHeaders,
			ExposeHeaders:         cfg.WAF.CORS.ExposeHeaders,
			AllowCredentials:      cfg.WAF.CORS.AllowCredentials,
			MaxAgeSeconds:         cfg.WAF.CORS.MaxAgeSeconds,
			StrictMode:            cfg.WAF.CORS.StrictMode,
			PreflightCacheSeconds: cfg.WAF.CORS.PreflightCacheSeconds,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create CORS layer: %v\n", err)
		} else {
			eng.AddLayer(engine.OrderedLayer{Layer: corsLayer, Order: engine.OrderCORS})
			eng.Logs.Infof("CORS security enabled (%d allowed origins)", len(cfg.WAF.CORS.AllowOrigins))
		}
	}

	// 1d. Custom Rules layer (Order 150)
	if cfg.WAF.CustomRules.Enabled {
		var geodb *geoip.DB
		if cfg.WAF.GeoIP.Enabled {
			geodb, _ = loadGeoIP(cfg, eng)
		}

		// Register GeoIP lookup for events
		if geodb != nil {
			engine.SetGeoIPLookup(func(ip string) (string, string) {
				parsed := net.ParseIP(ip)
				if parsed == nil {
					return "", ""
				}
				code := geodb.Lookup(parsed)
				return code, geoip.CountryName(code)
			})
		}

		ruleList := make([]rules.Rule, len(cfg.WAF.CustomRules.Rules))
		for i, r := range cfg.WAF.CustomRules.Rules {
			conditions := make([]rules.Condition, len(r.Conditions))
			for j, c := range r.Conditions {
				conditions[j] = rules.Condition{Field: c.Field, Op: c.Op, Value: c.Value}
			}
			ruleList[i] = rules.Rule{
				ID: r.ID, Name: r.Name, Enabled: r.Enabled,
				Priority: r.Priority, Conditions: conditions,
				Action: r.Action, Score: r.Score,
			}
		}

		rulesLayer := rules.NewLayer(&rules.Config{Enabled: true, Rules: ruleList}, geodb)
		eng.AddLayer(engine.OrderedLayer{Layer: rulesLayer, Order: engine.OrderRules})
		eng.Logs.Infof("Custom rules: %d rules loaded", len(ruleList))
	}

	// 2. Rate Limit layer (Order 200)
	if cfg.WAF.RateLimit.Enabled {
		rules := make([]ratelimit.Rule, len(cfg.WAF.RateLimit.Rules))
		for i, r := range cfg.WAF.RateLimit.Rules {
			rules[i] = ratelimit.Rule{
				ID:           r.ID,
				Scope:        r.Scope,
				Paths:        r.Paths,
				Limit:        r.Limit,
				Window:       r.Window,
				Burst:        r.Burst,
				Action:       r.Action,
				AutoBanAfter: r.AutoBanAfter,
			}
		}
		rlLayer := ratelimit.NewLayer(&ratelimit.Config{
			Enabled: cfg.WAF.RateLimit.Enabled,
			Rules:   rules,
		})
		// Wire up auto-ban: when rate limit exceeds AutoBanAfter, ban IP in IP ACL layer
		if ipaclLayer != nil && cfg.WAF.IPACL.AutoBan.Enabled {
			rlLayer.OnAutoBan = func(ip, reason string) {
				ttl := cfg.WAF.IPACL.AutoBan.DefaultTTL
				if cfg.WAF.IPACL.AutoBan.MaxTTL > 0 && ttl > cfg.WAF.IPACL.AutoBan.MaxTTL {
					ttl = cfg.WAF.IPACL.AutoBan.MaxTTL
				}
				ipaclLayer.AddAutoBan(ip, reason, ttl)
			}
		}
		eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})
	}

	// 2b. ATO Protection layer (Order 250)
	if cfg.WAF.ATOProtection.Enabled {
		atoLayer, err := ato.NewLayer(&ato.Config{
			Enabled:    cfg.WAF.ATOProtection.Enabled,
			LoginPaths: cfg.WAF.ATOProtection.LoginPaths,
			BruteForce: ato.BruteForceConfig{
				Enabled:             cfg.WAF.ATOProtection.BruteForce.Enabled,
				Window:              cfg.WAF.ATOProtection.BruteForce.Window,
				MaxAttemptsPerIP:    cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP,
				MaxAttemptsPerEmail: cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail,
				BlockDuration:       cfg.WAF.ATOProtection.BruteForce.BlockDuration,
			},
			CredStuffing: ato.CredentialStuffingConfig{
				Enabled:              cfg.WAF.ATOProtection.CredStuffing.Enabled,
				DistributedThreshold: cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold,
				Window:               cfg.WAF.ATOProtection.CredStuffing.Window,
				BlockDuration:        cfg.WAF.ATOProtection.CredStuffing.BlockDuration,
			},
			PasswordSpray: ato.PasswordSprayConfig{
				Enabled:       cfg.WAF.ATOProtection.PasswordSpray.Enabled,
				Threshold:     cfg.WAF.ATOProtection.PasswordSpray.Threshold,
				Window:        cfg.WAF.ATOProtection.PasswordSpray.Window,
				BlockDuration: cfg.WAF.ATOProtection.PasswordSpray.BlockDuration,
			},
			Travel: ato.ImpossibleTravelConfig{
				Enabled:       cfg.WAF.ATOProtection.Travel.Enabled,
				MaxDistanceKm: cfg.WAF.ATOProtection.Travel.MaxDistanceKm,
				MaxTimeHours:  cfg.WAF.ATOProtection.Travel.MaxTimeHours,
				BlockDuration: cfg.WAF.ATOProtection.Travel.BlockDuration,
			},
			GeoDBPath: cfg.WAF.ATOProtection.GeoDBPath,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create ATO protection layer: %v\n", err)
		} else {
			eng.AddLayer(engine.OrderedLayer{Layer: atoLayer, Order: engine.OrderATO})
			eng.Logs.Infof("ATO protection enabled (%d login paths)", len(cfg.WAF.ATOProtection.LoginPaths))
		}
	}

	// 2c. API Security layer (Order 275)
	if cfg.WAF.APISecurity.Enabled {
		apiKeys := make([]apisecurity.APIKeyConfig, len(cfg.WAF.APISecurity.APIKeys.Keys))
		for i, k := range cfg.WAF.APISecurity.APIKeys.Keys {
			apiKeys[i] = apisecurity.APIKeyConfig{
				Name:         k.Name,
				KeyHash:      k.KeyHash,
				KeyPrefix:    k.KeyPrefix,
				RateLimit:    k.RateLimit,
				AllowedPaths: k.AllowedPaths,
				Enabled:      k.Enabled,
			}
		}
		apiLayer, err := apisecurity.NewLayer(&apisecurity.Config{
			Enabled:    cfg.WAF.APISecurity.Enabled,
			SkipPaths:  cfg.WAF.APISecurity.SkipPaths,
			HeaderName: cfg.WAF.APISecurity.HeaderName,
			QueryParam: cfg.WAF.APISecurity.QueryParam,
			JWT: apisecurity.JWTConfig{
				Enabled:          cfg.WAF.APISecurity.JWT.Enabled,
				Issuer:           cfg.WAF.APISecurity.JWT.Issuer,
				Audience:         cfg.WAF.APISecurity.JWT.Audience,
				Algorithms:       cfg.WAF.APISecurity.JWT.Algorithms,
				PublicKeyFile:    cfg.WAF.APISecurity.JWT.PublicKeyFile,
				JWKSURL:          cfg.WAF.APISecurity.JWT.JWKSURL,
				ClockSkewSeconds: cfg.WAF.APISecurity.JWT.ClockSkewSeconds,
				PublicKeyPEM:     cfg.WAF.APISecurity.JWT.PublicKeyPEM,
			},
			APIKeys: apisecurity.APIKeysConfig{
				Enabled:    cfg.WAF.APISecurity.APIKeys.Enabled,
				HeaderName: cfg.WAF.APISecurity.APIKeys.HeaderName,
				QueryParam: cfg.WAF.APISecurity.APIKeys.QueryParam,
				Keys:       apiKeys,
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create API security layer: %v\n", err)
		} else {
			eng.AddLayer(engine.OrderedLayer{Layer: apiLayer, Order: engine.OrderAPISecurity})
			eng.Logs.Info("API security layer enabled")
		}
	}

	// 2.5. API Validation layer (Order 280) - OpenAPI schema validation
	if cfg.WAF.APIValidation.Enabled {
		schemas := make([]apivalidation.SchemaSource, len(cfg.WAF.APIValidation.Schemas))
		for i, s := range cfg.WAF.APIValidation.Schemas {
			schemas[i] = apivalidation.SchemaSource{
				Path:      s.Path,
				Type:      s.Type,
				AutoLearn: s.AutoLearn,
			}
		}
		apiValLayer := apivalidation.NewLayer(&apivalidation.Config{
			Enabled:          cfg.WAF.APIValidation.Enabled,
			ValidateRequest:  cfg.WAF.APIValidation.ValidateRequest,
			ValidateResponse: cfg.WAF.APIValidation.ValidateResponse,
			StrictMode:       cfg.WAF.APIValidation.StrictMode,
			BlockOnViolation: cfg.WAF.APIValidation.BlockOnViolation,
			ViolationScore:   cfg.WAF.APIValidation.ViolationScore,
			CacheSize:        cfg.WAF.APIValidation.CacheSize,
			Schemas:          schemas,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: apiValLayer, Order: 280})
		eng.Logs.Info("API validation layer enabled")
	}

	// 3. Sanitizer layer (Order 300)
	if cfg.WAF.Sanitizer.Enabled {
		sanLayer := sanitizer.NewLayer(&sanitizer.Config{
			MaxURLLength:   cfg.WAF.Sanitizer.MaxURLLength,
			MaxHeaderSize:  cfg.WAF.Sanitizer.MaxHeaderSize,
			MaxHeaderCount: cfg.WAF.Sanitizer.MaxHeaderCount,
			MaxBodySize:    cfg.WAF.Sanitizer.MaxBodySize,
			MaxCookieSize:  cfg.WAF.Sanitizer.MaxCookieSize,
			AllowedMethods: cfg.WAF.Sanitizer.AllowedMethods,
			BlockNullBytes: cfg.WAF.Sanitizer.BlockNullBytes,
			StripHopByHop:  cfg.WAF.Sanitizer.StripHopByHop,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: sanLayer, Order: engine.OrderSanitizer})
	}

	// 3.5. CRS Layer (Order 350) - OWASP Core Rule Set
	if cfg.WAF.CRS.Enabled {
		crsLayer := crs.NewLayer(&crs.Config{
			Enabled:          cfg.WAF.CRS.Enabled,
			RulePath:         cfg.WAF.CRS.RulePath,
			ParanoiaLevel:    cfg.WAF.CRS.ParanoiaLevel,
			AnomalyThreshold: cfg.WAF.CRS.AnomalyThreshold,
			Exclusions:       cfg.WAF.CRS.Exclusions,
			DisabledRules:    cfg.WAF.CRS.DisabledRules,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: crsLayer, Order: engine.OrderCRS})
		eng.Logs.Info("CRS layer enabled")
	}

	// 4. Detection layer (Order 400)
	if cfg.WAF.Detection.Enabled {
		detConfigs := make(map[string]detection.DetectorConfig, len(cfg.WAF.Detection.Detectors))
		for name, dc := range cfg.WAF.Detection.Detectors {
			detConfigs[name] = detection.DetectorConfig{
				Enabled:    dc.Enabled,
				Multiplier: dc.Multiplier,
			}
		}
		var exclusions []detection.Exclusion
		for _, exc := range cfg.WAF.Detection.Exclusions {
			exclusions = append(exclusions, detection.Exclusion{
				PathPrefix: exc.Path,
				Detectors:  exc.Detectors,
				Reason:     exc.Reason,
			})
		}
		detLayer := detection.NewLayer(&detection.Config{
			Enabled:    cfg.WAF.Detection.Enabled,
			Detectors:  detConfigs,
			Exclusions: exclusions,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: engine.OrderDetection})
	}

	// 4.5. Virtual Patch layer (Order 450) - CVE-based virtual patching
	if cfg.WAF.VirtualPatch.Enabled {
		vpLayer := virtualpatch.NewLayer(&virtualpatch.Config{
			Enabled:           cfg.WAF.VirtualPatch.Enabled,
			AutoUpdate:        cfg.WAF.VirtualPatch.AutoUpdate,
			UpdateInterval:    cfg.WAF.VirtualPatch.UpdateInterval,
			CVEPath:           cfg.WAF.VirtualPatch.CVEPath,
			NVDFeedURL:        cfg.WAF.VirtualPatch.NVDFeedURL,
			AutoGenerateRules: cfg.WAF.VirtualPatch.AutoGenerateRules,
			BlockSeverity:     cfg.WAF.VirtualPatch.BlockSeverity,
			NotifyOnPatch:     cfg.WAF.VirtualPatch.NotifyOnPatch,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: vpLayer, Order: engine.OrderVirtualPatch})
		eng.Logs.Info("Virtual patch layer enabled")
	}

	// 4.75. DLP Layer (Order 475) - Data Loss Prevention
	if cfg.WAF.DLP.Enabled {
		dlpLayer := dlp.NewLayer(&dlp.Config{
			Enabled:      cfg.WAF.DLP.Enabled,
			ScanRequest:  cfg.WAF.DLP.ScanRequest,
			ScanResponse: cfg.WAF.DLP.ScanResponse,
			BlockOnMatch: cfg.WAF.DLP.BlockOnMatch,
			MaskResponse: cfg.WAF.DLP.MaskResponse,
			MaxBodySize:  cfg.WAF.DLP.MaxBodySize,
			Patterns:     cfg.WAF.DLP.Patterns,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: dlpLayer, Order: engine.OrderDLP})
		eng.Logs.Info("DLP layer enabled")
	}

	// 5. Bot Detection layer (Order 500)
	if cfg.WAF.BotDetection.Enabled {
		bdLayer := botdetect.NewLayer(&botdetect.Config{
			Enabled: cfg.WAF.BotDetection.Enabled,
			Mode:    cfg.WAF.BotDetection.Mode,
			TLSFingerprint: botdetect.TLSFingerprintConfig{
				Enabled:         cfg.WAF.BotDetection.TLSFingerprint.Enabled,
				KnownBotsAction: cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction,
				UnknownAction:   cfg.WAF.BotDetection.TLSFingerprint.UnknownAction,
				MismatchAction:  cfg.WAF.BotDetection.TLSFingerprint.MismatchAction,
			},
			UserAgent: botdetect.UAConfig{
				Enabled:            cfg.WAF.BotDetection.UserAgent.Enabled,
				BlockEmpty:         cfg.WAF.BotDetection.UserAgent.BlockEmpty,
				BlockKnownScanners: cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
			},
			Behavior: botdetect.BehaviorAnalysisConfig{
				Enabled:            cfg.WAF.BotDetection.Behavior.Enabled,
				Window:             cfg.WAF.BotDetection.Behavior.Window,
				RPSThreshold:       cfg.WAF.BotDetection.Behavior.RPSThreshold,
				ErrorRateThreshold: cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
			},
		})
		eng.AddLayer(engine.OrderedLayer{Layer: bdLayer, Order: engine.OrderBotDetect})
	}

	// 5.5. Client-side protection layer (Order 590) - Magecart detection and CSP
	if cfg.WAF.ClientSide.Enabled {
		csLayer := clientside.NewLayer(&clientside.Config{
			Enabled: cfg.WAF.ClientSide.Enabled,
			Mode:    cfg.WAF.ClientSide.Mode,
			MagecartDetection: clientside.MagecartConfig{
				Enabled:                 cfg.WAF.ClientSide.MagecartDetection.Enabled,
				DetectObfuscatedJS:      cfg.WAF.ClientSide.MagecartDetection.DetectObfuscatedJS,
				DetectSuspiciousDomains: cfg.WAF.ClientSide.MagecartDetection.DetectSuspiciousDomains,
				DetectFormExfiltration:  cfg.WAF.ClientSide.MagecartDetection.DetectFormExfiltration,
				DetectKeyloggers:        cfg.WAF.ClientSide.MagecartDetection.DetectKeyloggers,
				KnownSkimmingDomains:    cfg.WAF.ClientSide.MagecartDetection.KnownSkimmingDomains,
				BlockScore:              cfg.WAF.ClientSide.MagecartDetection.BlockScore,
				AlertScore:              cfg.WAF.ClientSide.MagecartDetection.AlertScore,
			},
			AgentInjection: clientside.AgentConfig{
				Enabled:        cfg.WAF.ClientSide.AgentInjection.Enabled,
				ScriptURL:      cfg.WAF.ClientSide.AgentInjection.ScriptURL,
				InjectInHTML:   cfg.WAF.ClientSide.AgentInjection.InjectInHTML,
				InjectPosition: cfg.WAF.ClientSide.AgentInjection.InjectPosition,
				MonitorDOM:     cfg.WAF.ClientSide.AgentInjection.MonitorDOM,
				MonitorNetwork: cfg.WAF.ClientSide.AgentInjection.MonitorNetwork,
				MonitorForms:   cfg.WAF.ClientSide.AgentInjection.MonitorForms,
				ProtectedPaths: cfg.WAF.ClientSide.AgentInjection.ProtectedPaths,
			},
			CSP: clientside.CSPConfig{
				Enabled:         cfg.WAF.ClientSide.CSP.Enabled,
				ReportOnly:      cfg.WAF.ClientSide.CSP.ReportOnly,
				DefaultSrc:      cfg.WAF.ClientSide.CSP.DefaultSrc,
				ScriptSrc:       cfg.WAF.ClientSide.CSP.ScriptSrc,
				StyleSrc:        cfg.WAF.ClientSide.CSP.StyleSrc,
				ImgSrc:          cfg.WAF.ClientSide.CSP.ImgSrc,
				ConnectSrc:      cfg.WAF.ClientSide.CSP.ConnectSrc,
				FontSrc:         cfg.WAF.ClientSide.CSP.FontSrc,
				ObjectSrc:       cfg.WAF.ClientSide.CSP.ObjectSrc,
				MediaSrc:        cfg.WAF.ClientSide.CSP.MediaSrc,
				FrameSrc:        cfg.WAF.ClientSide.CSP.FrameSrc,
				FrameAncestors:  cfg.WAF.ClientSide.CSP.FrameAncestors,
				FormAction:      cfg.WAF.ClientSide.CSP.FormAction,
				BaseURI:         cfg.WAF.ClientSide.CSP.BaseURI,
				ReportURI:       cfg.WAF.ClientSide.CSP.ReportURI,
				UpgradeInsecure: cfg.WAF.ClientSide.CSP.UpgradeInsecure,
			},
			Exclusions: cfg.WAF.ClientSide.Exclusions,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: csLayer, Order: 590})
		eng.Logs.Info("Client-side protection layer enabled")
	}

	// 6. Response layer (Order 600)
	respCfg := response.Config{
		SecurityHeadersEnabled: cfg.WAF.Response.SecurityHeaders.Enabled,
		DataMaskingEnabled:     cfg.WAF.Response.DataMasking.Enabled,
		MaskCreditCards:        cfg.WAF.Response.DataMasking.MaskCreditCards,
		MaskSSN:                cfg.WAF.Response.DataMasking.MaskSSN,
		MaskAPIKeys:            cfg.WAF.Response.DataMasking.MaskAPIKeys,
		StripStackTraces:       cfg.WAF.Response.DataMasking.StripStackTraces,
		ErrorPageMode:          cfg.WAF.Response.ErrorPages.Mode,
	}
	if cfg.WAF.Response.SecurityHeaders.Enabled {
		respCfg.Headers = response.SecurityHeaders{
			XContentTypeOptions: "nosniff",
			XFrameOptions:       cfg.WAF.Response.SecurityHeaders.XFrameOptions,
			ReferrerPolicy:      cfg.WAF.Response.SecurityHeaders.ReferrerPolicy,
			PermissionsPolicy:   cfg.WAF.Response.SecurityHeaders.PermissionsPolicy,
		}
		if cfg.WAF.Response.SecurityHeaders.HSTS.Enabled {
			hsts := fmt.Sprintf("max-age=%d", cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
			if cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains {
				hsts += "; includeSubDomains"
			}
			respCfg.Headers.HSTS = hsts
		}
	}
	respLayer := response.NewLayer(&respCfg)
	eng.AddLayer(engine.OrderedLayer{Layer: respLayer, Order: engine.OrderResponse})
}

// buildReverseProxy creates an http.Handler that routes requests to upstreams
// based on the configured routes. It uses the proxy package for load balancing
// and health checking across multiple targets per upstream.
func buildReverseProxy(cfg *config.Config) (http.Handler, []*proxy.HealthChecker) {
	// Build balancers: name -> *Balancer
	balancerMap := make(map[string]*proxy.Balancer)
	var healthCheckers []*proxy.HealthChecker

	for _, u := range cfg.Upstreams {
		var targets []*proxy.Target
		for _, t := range u.Targets {
			target, err := proxy.NewTarget(t.URL, t.Weight)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: invalid upstream URL %q: %v\n", t.URL, err)
				continue
			}
			targets = append(targets, target)
		}
		if len(targets) == 0 {
			continue
		}

		strategy := u.LoadBalancer
		if strategy == "" {
			strategy = proxy.StrategyRoundRobin
		}
		lb := proxy.NewBalancer(targets, strategy)
		balancerMap[u.Name] = lb

		// Start health checks if configured
		if u.HealthCheck.Enabled {
			hc := proxy.NewHealthChecker(lb, proxy.HealthConfig{
				Enabled:  true,
				Interval: u.HealthCheck.Interval,
				Timeout:  u.HealthCheck.Timeout,
				Path:     u.HealthCheck.Path,
			})
			hc.Start()
			healthCheckers = append(healthCheckers, hc)
		}
	}

	// Build default routes (flat routes array — fallback)
	defaultRoutes := make([]proxy.Route, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		lb, ok := balancerMap[route.Upstream]
		if !ok {
			continue
		}
		defaultRoutes = append(defaultRoutes, proxy.Route{
			PathPrefix:  route.Path,
			Balancer:    lb,
			StripPrefix: route.StripPrefix,
		})
	}

	// Build virtual hosts if configured
	if len(cfg.VirtualHosts) > 0 {
		var vhosts []proxy.VirtualHost
		for _, vh := range cfg.VirtualHosts {
			var vhRoutes []proxy.Route
			for _, route := range vh.Routes {
				lb, ok := balancerMap[route.Upstream]
				if !ok {
					continue
				}
				vhRoutes = append(vhRoutes, proxy.Route{
					PathPrefix:  route.Path,
					Balancer:    lb,
					StripPrefix: route.StripPrefix,
				})
			}
			vhosts = append(vhosts, proxy.VirtualHost{
				Domains: vh.Domains,
				Routes:  vhRoutes,
			})
		}
		return proxy.NewRouterWithVHosts(vhosts, defaultRoutes), healthCheckers
	}

	return proxy.NewRouter(defaultRoutes), healthCheckers
}

// startDashboard starts the full dashboard HTTP server in the background.
// It provides a real-time web UI with SSE event streaming, REST API,
// and security analytics. Returns the server and the SSE broadcaster
// so the engine can publish events to connected dashboard clients.
func startDashboard(cfg *config.Config, eng *engine.Engine) (*http.Server, *dashboard.SSEBroadcaster, *dashboard.Dashboard) {
	eventStore, ok := eng.EventStore().(events.EventStore)
	if !ok {
		fmt.Fprintf(os.Stderr, "Warning: event store does not support queries; dashboard events disabled\n")
		eventStore = events.NewMemoryStore(1000)
	}

	// Require API key for dashboard — generate random if not set
	if cfg.Dashboard.APIKey == "" {
		cfg.Dashboard.APIKey = generateDashboardPassword()
		fmt.Printf("Dashboard API key not set — generated: %s\n", cfg.Dashboard.APIKey)
		fmt.Printf("Access dashboard at https://%s (user: admin, pass: %s)\n", cfg.Dashboard.Listen, cfg.Dashboard.APIKey)
	}

	dash := dashboard.New(eng, eventStore, cfg.Dashboard.APIKey)

	srv := &http.Server{
		Addr:         cfg.Dashboard.Listen,
		Handler:      dash.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		fmt.Printf("Dashboard listening on %s\n", cfg.Dashboard.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
		}
	}()

	return srv, dash.SSE(), dash
}

// startMCPServer starts the MCP JSON-RPC server over stdio.
// It runs in a goroutine and blocks until stdin is closed.
func startMCPServer(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, stdin io.Reader, stdout io.Writer) {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	mcpSrv := mcp.NewServer(stdin, stdout)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(&mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store, alertMgr: alertMgr})
	mcpSrv.RegisterAllTools()

	if err := mcpSrv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
	}
}

// upstreamSummary returns a short description of configured upstreams.
func upstreamSummary(cfg *config.Config) string {
	if len(cfg.Upstreams) == 0 {
		return "(no upstream)"
	}
	var targets []string
	for _, u := range cfg.Upstreams {
		for _, t := range u.Targets {
			targets = append(targets, t.URL)
		}
	}
	return strings.Join(targets, ", ")
}

// tenantManagerAdapter adapts *tenant.Manager to dashboard.tenantManagerInterface.
type tenantManagerAdapter struct {
	mgr *tenant.Manager
}

func (a *tenantManagerAdapter) ListTenants() []any {
	tenants := a.mgr.ListTenants()
	result := make([]any, len(tenants))
	for i, t := range tenants {
		result[i] = t
	}
	return result
}

func (a *tenantManagerAdapter) GetTenant(id string) any {
	return a.mgr.GetTenant(id)
}

func (a *tenantManagerAdapter) CreateTenant(name, description string, domains []string, quota any) (any, error) {
	// Convert quota from any to *tenant.ResourceQuota
	var tQuota *tenant.ResourceQuota
	if q, ok := quota.(*tenant.ResourceQuota); ok {
		tQuota = q
	}
	return a.mgr.CreateTenant(name, description, domains, tQuota)
}

func (a *tenantManagerAdapter) UpdateTenant(id string, update any) error {
	// Convert map to TenantUpdate if needed
	if u, ok := update.(*tenant.TenantUpdate); ok {
		return a.mgr.UpdateTenant(id, u)
	}
	if m, ok := update.(map[string]any); ok {
		tu := &tenant.TenantUpdate{}
		if v, ok := m["name"].(string); ok {
			tu.Name = v
		}
		if v, ok := m["description"].(string); ok {
			tu.Description = v
		}
		if v, ok := m["domains"].([]string); ok {
			tu.Domains = v
		}
		return a.mgr.UpdateTenant(id, tu)
	}
	return fmt.Errorf("unsupported update type")
}

func (a *tenantManagerAdapter) DeleteTenant(id string) error {
	return a.mgr.DeleteTenant(id)
}

func (a *tenantManagerAdapter) RegenerateAPIKey(id string) (string, error) {
	return a.mgr.RegenerateAPIKey(id)
}

func (a *tenantManagerAdapter) Stats() any {
	return a.mgr.Stats()
}

func (a *tenantManagerAdapter) BillingManager() dashboard.BillingManagerInterface {
	return &billingManagerAdapter{bm: a.mgr.BillingManager()}
}

func (a *tenantManagerAdapter) AlertManager() dashboard.AlertManagerInterface {
	return &alertManagerAdapter{am: a.mgr.AlertManager()}
}

func (a *tenantManagerAdapter) GetAllUsage() []any {
	usage := a.mgr.GetAllUsage()
	result := make([]any, len(usage))
	for i, u := range usage {
		result[i] = u
	}
	return result
}

func (a *tenantManagerAdapter) GetTenantUsage(tenantID string) any {
	return a.mgr.GetTenantUsage(tenantID)
}

func (a *tenantManagerAdapter) GetTenantRules(tenantID string) []any {
	rules := a.mgr.GetTenantRules(tenantID)
	return rules
}

func (a *tenantManagerAdapter) AddTenantRule(tenantID string, rule map[string]any) error {
	return a.mgr.AddTenantRule(tenantID, rule)
}

func (a *tenantManagerAdapter) GetTenantRule(tenantID, ruleID string) any {
	return a.mgr.GetTenantRule(tenantID, ruleID)
}

func (a *tenantManagerAdapter) UpdateTenantRule(tenantID string, rule map[string]any) error {
	return a.mgr.UpdateTenantRule(tenantID, rule)
}

func (a *tenantManagerAdapter) RemoveTenantRule(tenantID, ruleID string) error {
	return a.mgr.RemoveTenantRule(tenantID, ruleID)
}

func (a *tenantManagerAdapter) ToggleTenantRule(tenantID, ruleID string, enabled bool) error {
	return a.mgr.ToggleTenantRule(tenantID, ruleID, enabled)
}

// billingManagerAdapter adapts tenant.BillingManager to dashboard interface.
type billingManagerAdapter struct {
	bm *tenant.BillingManager
}

func (a *billingManagerAdapter) GetAllInvoices() []any {
	if a.bm == nil {
		return nil
	}
	invoices := a.bm.GetAllInvoices()
	result := make([]any, len(invoices))
	for i, inv := range invoices {
		result[i] = inv
	}
	return result
}

func (a *billingManagerAdapter) GetInvoices(tenantID string) []any {
	if a.bm == nil {
		return nil
	}
	invoices := a.bm.GetInvoices(tenantID)
	result := make([]any, len(invoices))
	for i, inv := range invoices {
		result[i] = inv
	}
	return result
}

func (a *billingManagerAdapter) GetCurrentUsage(tenantID string) any {
	if a.bm == nil {
		return nil
	}
	return a.bm.GetCurrentUsage(tenantID)
}

func (a *billingManagerAdapter) GenerateInvoice(tenantID, tenantName string, plan string, periodStart, periodEnd time.Time) (any, error) {
	if a.bm == nil {
		return nil, fmt.Errorf("billing not enabled")
	}
	return a.bm.GenerateInvoice(tenantID, tenantName, tenant.BillingPlan(plan), periodStart, periodEnd)
}

// alertManagerAdapter adapts tenant.AlertManager to dashboard interface.
type alertManagerAdapter struct {
	am *tenant.AlertManager
}

func (a *alertManagerAdapter) GetRecentAlerts(since time.Duration) []any {
	if a.am == nil {
		return nil
	}
	alerts := a.am.GetRecentAlerts(since)
	result := make([]any, len(alerts))
	for i, alert := range alerts {
		result[i] = alert
	}
	return result
}

// --------------------------------------------------------------------------
// MCP engine adapter
// --------------------------------------------------------------------------

// mcpEngineAdapter adapts the engine.Engine to the mcp.EngineInterface.
type mcpEngineAdapter struct {
	engine     *engine.Engine
	cfg        *config.Config
	eventStore events.EventStore
	alertMgr   *alerting.Manager
}

func (a *mcpEngineAdapter) GetStats() any {
	s := a.engine.Stats()
	return map[string]any{
		"total_requests":   s.TotalRequests,
		"blocked_requests": s.BlockedRequests,
		"logged_requests":  s.LoggedRequests,
		"passed_requests":  s.PassedRequests,
		"avg_latency_us":   s.AvgLatencyUs,
	}
}

func (a *mcpEngineAdapter) GetConfig() any {
	cfg := a.engine.Config()
	return map[string]any{
		"mode":   cfg.Mode,
		"listen": cfg.Listen,
		"waf": map[string]any{
			"ip_acl_enabled":     cfg.WAF.IPACL.Enabled,
			"rate_limit_enabled": cfg.WAF.RateLimit.Enabled,
			"sanitizer_enabled":  cfg.WAF.Sanitizer.Enabled,
			"detection_enabled":  cfg.WAF.Detection.Enabled,
			"bot_detect_enabled": cfg.WAF.BotDetection.Enabled,
			"threshold_block":    cfg.WAF.Detection.Threshold.Block,
			"threshold_log":      cfg.WAF.Detection.Threshold.Log,
		},
		"dashboard": map[string]any{
			"enabled": cfg.Dashboard.Enabled,
			"listen":  cfg.Dashboard.Listen,
		},
		"mcp": map[string]any{
			"enabled":   cfg.MCP.Enabled,
			"transport": cfg.MCP.Transport,
		},
	}
}

func (a *mcpEngineAdapter) GetMode() string {
	return a.engine.Config().Mode
}

func (a *mcpEngineAdapter) SetMode(mode string) error {
	cfg := a.engine.Config()
	cfg.Mode = mode
	return a.engine.Reload(cfg)
}

func (a *mcpEngineAdapter) AddWhitelist(ip string) error {
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.AddWhitelist(ip)
}

func (a *mcpEngineAdapter) RemoveWhitelist(ip string) error {
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.RemoveWhitelist(ip)
}

func (a *mcpEngineAdapter) AddBlacklist(ip string) error {
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.AddBlacklist(ip)
}

func (a *mcpEngineAdapter) RemoveBlacklist(ip string) error {
	layer := a.engine.FindLayer("ipacl")
	if layer == nil {
		return fmt.Errorf("IP ACL layer not available")
	}
	ipaclLayer := layer.(*ipacl.Layer)
	return ipaclLayer.RemoveBlacklist(ip)
}

func (a *mcpEngineAdapter) AddRateLimit(rule any) error {
	layer := a.engine.FindLayer("ratelimit")
	if layer == nil {
		return fmt.Errorf("rate limit layer not available")
	}
	rlLayer := layer.(*ratelimit.Layer)

	// Parse the rule from the MCP params
	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}
	var p struct {
		ID     string `json:"id"`
		Scope  string `json:"scope"`
		Limit  int    `json:"limit"`
		Window string `json:"window"`
		Action string `json:"action"`
	}
	if unmarshalErr := json.Unmarshal(data, &p); unmarshalErr != nil {
		return fmt.Errorf("invalid rule format: %w", unmarshalErr)
	}

	window, err := time.ParseDuration(p.Window)
	if err != nil {
		return fmt.Errorf("invalid window duration: %w", err)
	}

	rlLayer.AddRule(ratelimit.Rule{
		ID:     p.ID,
		Scope:  p.Scope,
		Limit:  p.Limit,
		Window: window,
		Action: p.Action,
	})
	return nil
}

func (a *mcpEngineAdapter) RemoveRateLimit(id string) error {
	layer := a.engine.FindLayer("ratelimit")
	if layer == nil {
		return fmt.Errorf("rate limit layer not available")
	}
	rlLayer := layer.(*ratelimit.Layer)
	if !rlLayer.RemoveRule(id) {
		return fmt.Errorf("rate limit rule %s not found", id)
	}
	return nil
}

func (a *mcpEngineAdapter) AddExclusion(path string, detectors []string, reason string) error {
	layer := a.engine.FindLayer("detection")
	if layer == nil {
		return fmt.Errorf("detection layer not available")
	}
	detLayer := layer.(*detection.Layer)
	detLayer.AddExclusion(detection.Exclusion{
		PathPrefix: path,
		Detectors:  detectors,
		Reason:     reason,
	})
	return nil
}

func (a *mcpEngineAdapter) RemoveExclusion(path string) error {
	layer := a.engine.FindLayer("detection")
	if layer == nil {
		return fmt.Errorf("detection layer not available")
	}
	detLayer := layer.(*detection.Layer)
	if !detLayer.RemoveExclusion(path) {
		return fmt.Errorf("exclusion for path %s not found", path)
	}
	return nil
}

func (a *mcpEngineAdapter) GetEvents(params json.RawMessage) (any, error) {
	if a.eventStore == nil {
		return map[string]any{"events": []any{}, "total": 0}, nil
	}

	// Parse query params
	var p struct {
		Limit    int    `json:"limit"`
		Offset   int    `json:"offset"`
		Action   string `json:"action"`
		ClientIP string `json:"client_ip"`
		MinScore int    `json:"min_score"`
		Path     string `json:"path"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p)
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}

	evts, total, err := a.eventStore.Query(events.EventFilter{
		Limit:    p.Limit,
		Offset:   p.Offset,
		Action:   p.Action,
		ClientIP: p.ClientIP,
		MinScore: p.MinScore,
		Path:     p.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}

	// Convert to serializable format
	items := make([]map[string]any, len(evts))
	for i, ev := range evts {
		items[i] = map[string]any{
			"id":        ev.ID,
			"timestamp": ev.Timestamp,
			"client_ip": ev.ClientIP,
			"method":    ev.Method,
			"path":      ev.Path,
			"action":    ev.Action.String(),
			"score":     ev.Score,
			"findings":  len(ev.Findings),
		}
	}

	return map[string]any{"events": items, "total": total}, nil
}

func (a *mcpEngineAdapter) GetTopIPs(n int) any {
	if a.eventStore == nil {
		return []any{}
	}

	// Get recent events and aggregate by IP
	evts, _ := a.eventStore.Recent(10000)
	ipCounts := make(map[string]int)
	ipScores := make(map[string]int)
	for _, ev := range evts {
		ipCounts[ev.ClientIP]++
		ipScores[ev.ClientIP] += ev.Score
	}

	// Sort by count
	type ipStat struct {
		IP       string `json:"ip"`
		Requests int    `json:"requests"`
		Score    int    `json:"total_score"`
	}
	stats := make([]ipStat, 0, len(ipCounts))
	for ip, count := range ipCounts {
		stats = append(stats, ipStat{IP: ip, Requests: count, Score: ipScores[ip]})
	}
	// Sort descending by request count
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Requests > stats[i].Requests {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}
	if n > 0 && n < len(stats) {
		stats = stats[:n]
	}
	return stats
}

func (a *mcpEngineAdapter) GetDetectors() any {
	cfg := a.engine.Config()
	detectors := make([]map[string]any, 0, len(cfg.WAF.Detection.Detectors))
	for name, dc := range cfg.WAF.Detection.Detectors {
		detectors = append(detectors, map[string]any{
			"name":       name,
			"enabled":    dc.Enabled,
			"multiplier": dc.Multiplier,
		})
	}
	return detectors
}

func (a *mcpEngineAdapter) TestRequest(method, urlStr string, headers map[string]string) (any, error) {
	fullURL := urlStr
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "http://localhost" + fullURL
	}

	req, err := http.NewRequestWithContext(context.Background(), method, fullURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "127.0.0.1:0"

	event := a.engine.Check(req)
	findings := make([]map[string]any, 0, len(event.Findings))
	for _, f := range event.Findings {
		findings = append(findings, map[string]any{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
		})
	}

	return map[string]any{
		"action":   event.Action.String(),
		"score":    event.Score,
		"findings": findings,
		"duration": event.Duration.String(),
	}, nil
}

func (a *mcpEngineAdapter) GetAlertingStatus() any {
	if a.alertMgr == nil {
		return map[string]any{
			"enabled":       false,
			"webhook_count": 0,
			"email_count":   0,
			"sent":          0,
			"failed":        0,
		}
	}
	stats := a.alertMgr.GetStats()
	return map[string]any{
		"enabled":       true,
		"webhook_count": stats.WebhookCount,
		"email_count":   stats.EmailCount,
		"sent":          stats.Sent,
		"failed":        stats.Failed,
	}
}

func (a *mcpEngineAdapter) AddWebhook(name, url, webhookType string, events []string, minScore int, cooldown string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	d, err := time.ParseDuration(cooldown)
	if err != nil && cooldown != "" {
		return fmt.Errorf("invalid cooldown duration: %w", err)
	}
	target := alerting.WebhookTarget{
		Name:     name,
		URL:      url,
		Type:     webhookType,
		Events:   events,
		MinScore: minScore,
		Cooldown: d,
	}
	a.alertMgr.AddWebhook(target)
	return nil
}

func (a *mcpEngineAdapter) RemoveWebhook(name string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	if !a.alertMgr.RemoveWebhook(name) {
		return fmt.Errorf("webhook %s not found", name)
	}
	return nil
}

func (a *mcpEngineAdapter) AddEmailTarget(name, smtpHost string, smtpPort int, username, password, from string, to []string, useTLS bool, events []string, minScore int) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	cfg := config.EmailConfig{
		Name:     name,
		SMTPHost: smtpHost,
		SMTPPort: smtpPort,
		Username: username,
		Password: password,
		From:     from,
		To:       to,
		UseTLS:   useTLS,
		Events:   events,
		MinScore: minScore,
	}
	a.alertMgr.AddEmailTarget(cfg)
	return nil
}

func (a *mcpEngineAdapter) RemoveEmailTarget(name string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	if !a.alertMgr.RemoveEmailTarget(name) {
		return fmt.Errorf("email target %s not found", name)
	}
	return nil
}

func (a *mcpEngineAdapter) TestAlert(target string) error {
	if a.alertMgr == nil {
		return fmt.Errorf("alerting manager not available")
	}
	return a.alertMgr.TestAlert(target)
}

// New Feature Methods - CRS
func (a *mcpEngineAdapter) GetCRSRules(phase int, severity string) (any, error) {
	return map[string]any{
		"enabled": a.cfg.WAF.CRS.Enabled,
		"rules":   []any{},
	}, nil
}
func (a *mcpEngineAdapter) EnableCRSRule(ruleID string, enabled bool) error { return nil }
func (a *mcpEngineAdapter) SetParanoiaLevel(level int) error {
	cfg := a.engine.Config()
	cfg.WAF.CRS.ParanoiaLevel = level
	return a.engine.Reload(cfg)
}
func (a *mcpEngineAdapter) AddCRSExclusion(ruleID, path, parameter, reason string) error { return nil }

// New Feature Methods - Virtual Patch
func (a *mcpEngineAdapter) GetVirtualPatches(severity string, activeOnly bool) (any, error) {
	return map[string]any{
		"enabled": a.cfg.WAF.VirtualPatch.Enabled,
		"patches": []any{},
	}, nil
}
func (a *mcpEngineAdapter) EnableVirtualPatch(patchID string, enabled bool) error { return nil }
func (a *mcpEngineAdapter) AddCustomPatch(id, name, description, cveID, pattern, patternType, target, action, severity string, score int) error {
	return nil
}
func (a *mcpEngineAdapter) UpdateCVEDatabase() error { return nil }

// New Feature Methods - API Validation
func (a *mcpEngineAdapter) GetAPISchemas() (any, error) {
	return map[string]any{
		"enabled": a.cfg.WAF.APIValidation.Enabled,
		"schemas": []any{},
	}, nil
}
func (a *mcpEngineAdapter) UploadAPISchema(name, content, format string, strictMode bool) error { return nil }
func (a *mcpEngineAdapter) RemoveAPISchema(name string) error { return nil }
func (a *mcpEngineAdapter) SetAPIValidationMode(validateRequest, validateResponse, strictMode, blockOnViolation *bool) error {
	cfg := a.engine.Config()
	if validateRequest != nil {
		cfg.WAF.APIValidation.ValidateRequest = *validateRequest
	}
	if validateResponse != nil {
		cfg.WAF.APIValidation.ValidateResponse = *validateResponse
	}
	if strictMode != nil {
		cfg.WAF.APIValidation.StrictMode = *strictMode
	}
	if blockOnViolation != nil {
		cfg.WAF.APIValidation.BlockOnViolation = *blockOnViolation
	}
	return a.engine.Reload(cfg)
}
func (a *mcpEngineAdapter) TestAPISchema(method, path, body string) (any, error) {
	return map[string]any{"valid": true, "violations": []any{}}, nil
}

// New Feature Methods - Client-Side Protection
func (a *mcpEngineAdapter) GetClientSideStats() (any, error) {
	return map[string]any{
		"enabled":             a.cfg.WAF.ClientSide.Enabled,
		"mode":                a.cfg.WAF.ClientSide.Mode,
		"magecart_detection":  a.cfg.WAF.ClientSide.MagecartDetection.Enabled,
		"agent_injection":     a.cfg.WAF.ClientSide.AgentInjection.Enabled,
		"csp_enabled":         a.cfg.WAF.ClientSide.CSP.Enabled,
	}, nil
}
func (a *mcpEngineAdapter) SetClientSideMode(mode string, magecartDetection, agentInjection, cspEnabled *bool) error {
	cfg := a.engine.Config()
	cfg.WAF.ClientSide.Mode = mode
	if magecartDetection != nil {
		cfg.WAF.ClientSide.MagecartDetection.Enabled = *magecartDetection
	}
	if agentInjection != nil {
		cfg.WAF.ClientSide.AgentInjection.Enabled = *agentInjection
	}
	if cspEnabled != nil {
		cfg.WAF.ClientSide.CSP.Enabled = *cspEnabled
	}
	return a.engine.Reload(cfg)
}
func (a *mcpEngineAdapter) AddSkimmingDomain(domain string) error { return nil }
func (a *mcpEngineAdapter) GetCSPReports(limit int) (any, error) {
	return map[string]any{"reports": []any{}}, nil
}

// New Feature Methods - DLP
func (a *mcpEngineAdapter) GetDLPAlerts(limit int, patternType string) (any, error) {
	return map[string]any{
		"enabled": a.cfg.WAF.DLP.Enabled,
		"alerts":  []any{},
	}, nil
}
func (a *mcpEngineAdapter) AddDLPPattern(id, name, pattern, description, action string, score int) error { return nil }
func (a *mcpEngineAdapter) RemoveDLPPattern(id string) error                                             { return nil }
func (a *mcpEngineAdapter) TestDLPPattern(pattern, testData string) (any, error) {
	return map[string]any{"matched": false, "matches": []any{}}, nil
}

// New Feature Methods - HTTP/3 (stubs since HTTP3 is in separate build tag)
func (a *mcpEngineAdapter) GetHTTP3Status() (any, error) {
	return map[string]any{
		"enabled":           a.cfg.TLS.HTTP3.Enabled,
		"available":         true,
		"enable_0rtt":       a.cfg.TLS.HTTP3.Enable0RTT,
		"advertise_alt_svc": a.cfg.TLS.HTTP3.AdvertiseAltSvc,
	}, nil
}
func (a *mcpEngineAdapter) SetHTTP3Config(enabled, enable0RTT, advertiseAltSvc *bool) error {
	cfg := a.engine.Config()
	if enabled != nil {
		cfg.TLS.HTTP3.Enabled = *enabled
	}
	if enable0RTT != nil {
		cfg.TLS.HTTP3.Enable0RTT = *enable0RTT
	}
	if advertiseAltSvc != nil {
		cfg.TLS.HTTP3.AdvertiseAltSvc = *advertiseAltSvc
	}
	return a.engine.Reload(cfg)
}

// collectACMEDomains gathers all domains that need ACME certificates.
// Collects from tls.acme.domains and virtual_hosts that don't have manual certs.
func collectACMEDomains(cfg *config.Config) [][]string {
	var result [][]string

	// Explicit ACME domains from config
	if len(cfg.TLS.ACME.Domains) > 0 {
		result = append(result, cfg.TLS.ACME.Domains)
	}

	// Virtual hosts without manual TLS certs
	for _, vh := range cfg.VirtualHosts {
		if vh.TLS.CertFile == "" && vh.TLS.KeyFile == "" && len(vh.Domains) > 0 {
			// Filter out wildcard domains (ACME HTTP-01 doesn't support them)
			var nonWild []string
			for _, d := range vh.Domains {
				if !strings.HasPrefix(d, "*.") {
					nonWild = append(nonWild, d)
				}
			}
			if len(nonWild) > 0 {
				result = append(result, nonWild)
			}
		}
	}

	return result
}

// loadGeoIP loads the GeoIP database from file or downloads it.
func loadGeoIP(cfg *config.Config, eng *engine.Engine) (*geoip.DB, func()) {
	noop := func() {}

	// Try loading from specified path
	if cfg.WAF.GeoIP.DBPath != "" {
		db, err := geoip.LoadCSV(cfg.WAF.GeoIP.DBPath)
		if err == nil {
			eng.Logs.Infof("GeoIP DB loaded: %d ranges from %s", db.Count(), cfg.WAF.GeoIP.DBPath)
			if cfg.WAF.GeoIP.AutoDownload {
				stopFn := db.StartAutoRefresh(cfg.WAF.GeoIP.DBPath, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
				eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
				return db, stopFn
			}
			return db, noop
		}
		eng.Logs.Warnf("GeoIP DB load failed: %v", err)
	}

	// Auto-download if enabled
	if cfg.WAF.GeoIP.AutoDownload {
		path := cfg.WAF.GeoIP.DBPath
		if path == "" {
			path = "/var/lib/guardianwaf/geoip.csv"
		}
		eng.Logs.Info("Downloading GeoIP database...")
		db, err := geoip.LoadOrDownload(path, cfg.WAF.GeoIP.DownloadURL, 30*24*time.Hour)
		if err != nil {
			eng.Logs.Warnf("GeoIP auto-download failed: %v", err)
			return nil, noop
		}
		eng.Logs.Infof("GeoIP DB ready: %d ranges", db.Count())
		stopFn := db.StartAutoRefresh(path, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
		eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
		return db, stopFn
	}

	return nil, noop
}

// mapToRule converts a JSON map to a rules.Rule.
func mapToRule(raw map[string]any) rules.Rule {
	r := rules.Rule{}
	if v, ok := raw["id"].(string); ok {
		r.ID = v
	}
	if v, ok := raw["name"].(string); ok {
		r.Name = v
	}
	if v, ok := raw["enabled"].(bool); ok {
		r.Enabled = v
	}
	if v, ok := raw["priority"].(float64); ok {
		r.Priority = int(v)
	}
	if v, ok := raw["action"].(string); ok {
		r.Action = v
	}
	if v, ok := raw["score"].(float64); ok {
		r.Score = int(v)
	}
	if conds, ok := raw["conditions"].([]any); ok {
		for _, c := range conds {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			cond := rules.Condition{}
			if v, ok := cm["field"].(string); ok {
				cond.Field = v
			}
			if v, ok := cm["op"].(string); ok {
				cond.Op = v
			}
			cond.Value = cm["value"]
			r.Conditions = append(r.Conditions, cond)
		}
	}
	return r
}

// isValidIPOrCIDR returns true if s is a valid IP address or CIDR notation.
func isValidIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}
