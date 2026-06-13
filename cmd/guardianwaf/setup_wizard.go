package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// setupWizard holds the state collected during the interactive setup flow.
// Each promptXxx method asks the user for one section of configuration and
// stores results on the struct. buildConfig assembles everything into YAML.
type setupWizard struct {
	// Server
	listen    string
	mode      string
	tlsConfig string
	tlsListen string

	// Upstreams
	numBackends int
	lb          string
	hcConfig    string
	targets     []string

	// Routing
	routeHost  string
	routePath  string
	upstreams  string
	healthChk  string

	// WAF
	blockThresh string
	logThresh   string
	detectors   []string
	detectorCfg string

	// Feature sections
	botConfig      string
	botEnabled     bool
	rateLimitCfg   string
	rateLimitOn    bool
	corsConfig     string
	atoConfig      string
	alertConfig    string
	alertEnabled   bool
	dockerConfig   string
	dockerEnabled  bool
	dashboardListen string

	// Credentials
	dashboardPassword string

	// Rate limit auto-ban fields (used in WAF section)
	rlAutoBan bool
	rlBanDur  string
}

// newSetupWizard creates a wizard with sensible defaults pre-filled.
func newSetupWizard(password string) *setupWizard {
	return &setupWizard{
		dashboardPassword: password,
		rlBanDur:          "15m",
	}
}

func (w *setupWizard) promptServerSettings() {
	fmt.Println("\n━━━ Server Settings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Listen address (HTTP) [0.0.0.0:8088]: ")
	w.listen = readLine(":8088")

	fmt.Print("WAF mode (enforce/monitor/disabled) [enforce]: ")
	w.mode = readLine("enforce")
	if w.mode == "" {
		w.mode = "enforce"
	}

	fmt.Print("Enable TLS/SSL? (yes/no) [no]: ")
	tlsEnabled := readLine("no") == "yes"

	if tlsEnabled {
		fmt.Print("TLS listen port [0.0.0.0:8443]: ")
		w.tlsListen = readLine(":8443")
		fmt.Print("TLS certificate file path: ")
		certFile := readLine("")
		fmt.Print("TLS private key file path: ")
		keyFile := readLine("")
		fmt.Print("Enable HTTP->HTTPS redirect? (yes/no) [yes]: ")
		httpRedirect := readLine("yes") == "yes"
		if certFile != "" && keyFile != "" {
			w.tlsConfig = fmt.Sprintf(`
tls:
  enabled: true
  listen: "%s"
  http_redirect: %t
  cert_file: "%s"
  key_file: "%s"`, w.tlsListen, httpRedirect, certFile, keyFile)
		} else {
			w.tlsConfig = fmt.Sprintf(`
tls:
  enabled: true
  listen: "%s"
  http_redirect: true`, w.tlsListen)
		}
	} else {
		w.tlsConfig = `
tls:
  enabled: false`
	}
}

func (w *setupWizard) promptUpstreams() {
	fmt.Println("\n━━━ Upstream Backend(s) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Number of backends [1]: ")
	numBackends := readLine("1")
	if numBackends == "" {
		numBackends = "1"
	}

	n := 1
	if _, err := fmt.Sscanf(numBackends, "%d", &n); err != nil {
		n = 1
	}
	if n < 1 {
		n = 1
	}
	if n > 10 {
		n = 10
	}
	w.numBackends = n

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
		w.targets = append(w.targets, fmt.Sprintf(`      - url: "%s"
        weight: %s`, url, weight))
	}

	fmt.Print("Load balancing strategy (round_robin/weighted/least_conn/ip_hash) [weighted]: ")
	w.lb = readLine("weighted")

	fmt.Print("Enable health checks? (yes/no) [yes]: ")
	hcEnabled := readLine("yes") == "yes"

	if hcEnabled {
		fmt.Print("  Health check path [/healthz]: ")
		hcPath := readLine("/healthz")
		fmt.Print("  Health check interval (e.g., 10s, 30s) [10s]: ")
		hcInterval := readLine("10s")
		fmt.Print("  Health check timeout (e.g., 5s) [5s]: ")
		hcTimeout := readLine("5s")
		w.hcConfig = fmt.Sprintf(`
    health_check:
      enabled: true
      path: "%s"
      interval: %s
      timeout: %s`, hcPath, hcInterval, hcTimeout)
	}
}

func (w *setupWizard) promptRouting() {
	fmt.Println("\n━━━ Routing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Route domain/host pattern [*]: ")
	w.routeHost = readLine("*")
	fmt.Print("Route path prefix [/]: ")
	w.routePath = readLine("/")
}

func (w *setupWizard) promptWAF() {
	fmt.Println("\n━━━ WAF Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Print("Block threshold (1-100) [50]: ")
	w.blockThresh = readLine("50")
	fmt.Print("Log threshold (1-100) [25]: ")
	w.logThresh = readLine("25")

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

	if sqli {
		w.detectors = append(w.detectors, "sqli")
	}
	if xss {
		w.detectors = append(w.detectors, "xss")
	}
	if lfi {
		w.detectors = append(w.detectors, "lfi")
	}
	if cmdi {
		w.detectors = append(w.detectors, "cmdi")
	}
	if xxe {
		w.detectors = append(w.detectors, "xxe")
	}
	if ssrf {
		w.detectors = append(w.detectors, "ssrf")
	}

	w.detectorCfg = fmt.Sprintf(`      sqli:
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
}

func (w *setupWizard) promptBot() {
	fmt.Println("\n━━━ Bot Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable bot detection? (yes/no) [yes]: ")
	w.botEnabled = readLine("yes") == "yes"

	if w.botEnabled {
		fmt.Print("  Bot action (block/challenge/log) [block]: ")
		botMode := readLine("block")
		fmt.Print("  Enable JA3 fingerprinting? (yes/no) [yes]: ")
		ja3 := readLine("yes") == "yes"
		fmt.Print("  Enable JA4 fingerprinting? (yes/no) [yes]: ")
		ja4 := readLine("yes") == "yes"
		_ = ja4
		w.botConfig = fmt.Sprintf(`
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
		w.botConfig = `
  bot_detection:
    enabled: false`
	}
}

func (w *setupWizard) promptRateLimit() {
	fmt.Println("\n━━━ Rate Limiting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable rate limiting? (yes/no) [yes]: ")
	w.rateLimitOn = readLine("yes") == "yes"

	if w.rateLimitOn {
		fmt.Print("  Requests per minute [100]: ")
		rlRpm := readLine("100")
		fmt.Print("  Burst size [20]: ")
		rlBurst := readLine("20")
		fmt.Print("  Enable auto-ban? (yes/no) [yes]: ")
		w.rlAutoBan = readLine("yes") == "yes"
		fmt.Print("  Ban duration (e.g., 15m, 1h) [15m]: ")
		w.rlBanDur = readLine("15m")
		w.rateLimitCfg = fmt.Sprintf(`
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
		w.rateLimitCfg = `
  rate_limit:
    enabled: false`
	}
}

func (w *setupWizard) promptCORS() {
	fmt.Println("\n━━━ CORS Settings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable CORS? (yes/no) [yes]: ")
	corsEnabled := readLine("yes") == "yes"

	if corsEnabled {
		fmt.Print("  Allowed origins (comma-separated, * for any) [*]: ")
		origins := readLine("*")
		fmt.Print("  Allowed methods (comma-separated) [GET,POST,PUT,DELETE,OPTIONS]: ")
		methods := readLine("GET,POST,PUT,DELETE,OPTIONS")
		w.corsConfig = fmt.Sprintf(`
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
		w.corsConfig = `
  cors:
  enabled: false`
	}
}

func (w *setupWizard) promptATO() {
	fmt.Println("\n━━━ Account Takeover Protection ━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable ATO protection? (yes/no) [yes]: ")
	atoEnabled := readLine("yes") == "yes"

	if atoEnabled {
		fmt.Print("  Max login attempts [5]: ")
		atoMax := readLine("5")
		fmt.Print("  Detection window (e.g., 10m) [10m]: ")
		atoWindow := readLine("10m")
		fmt.Print("  Ban duration (e.g., 30m) [30m]: ")
		atoBan := readLine("30m")
		w.atoConfig = fmt.Sprintf(`
  ato_protection:
  enabled: true
  brute_force:
    enabled: true
    max_attempts_per_ip: %s
    window: %s
    block_duration: %s`, atoMax, atoWindow, atoBan)
	} else {
		w.atoConfig = `
  ato_protection:
  enabled: false`
	}
}

func (w *setupWizard) promptAlerting() {
	fmt.Println("\n━━━ Alerting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable alerting? (yes/no) [no]: ")
	w.alertEnabled = readLine("no") == "yes"

	if w.alertEnabled {
		fmt.Print("  Webhook URL for alerts: ")
		webhookURL := readLine("")
		fmt.Print("  Alert on events (block,challenge,log) [block,challenge]: ")
		events := readLine("block,challenge")
		fmt.Print("  Minimum score threshold [50]: ")
		minScore := readLine("50")
		if webhookURL != "" {
			w.alertConfig = fmt.Sprintf(`
alerting:
  enabled: true
  webhooks:
    - name: default
      url: "%s"
      events:
        - %s
      min_score: %s`, webhookURL, strings.ReplaceAll(events, ",", "\n        - "), minScore)
		} else {
			w.alertConfig = `
alerting:
  enabled: false`
		}
	} else {
		w.alertConfig = `
alerting:
  enabled: false`
	}
}

func (w *setupWizard) promptDocker() {
	fmt.Println("\n━━━ Docker Auto-Discovery ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Enable Docker auto-discovery? (yes/no) [yes]: ")
	w.dockerEnabled = readLine("yes") == "yes"

	if w.dockerEnabled {
		fmt.Print("  Docker socket path [/var/run/docker.sock]: ")
		dockerSocket := readLine("/var/run/docker.sock")
		w.dockerConfig = fmt.Sprintf(`
docker:
  enabled: true
  socket_path: "%s"
  label_prefix: gwaf
  poll_interval: 5s`, dockerSocket)
	} else {
		w.dockerConfig = `
docker:
  enabled: false`
	}
}

func (w *setupWizard) promptDashboard() {
	fmt.Println("\n━━━ Dashboard ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Dashboard port [0.0.0.0:9443]: ")
	w.dashboardListen = readLine(":9443")
}

func (w *setupWizard) printSummary() {
	fmt.Println("\n━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Mode: %s\n", w.mode)
	fmt.Printf("  Listen: %s\n", w.listen)
	tlsEnabled := w.tlsConfig != "\ntls:\n  enabled: false"
	fmt.Printf("  TLS: %s\n", boolStr(tlsEnabled))
	if tlsEnabled {
		fmt.Printf("  TLS Listen: %s\n", w.tlsListen)
	}
	fmt.Printf("  Upstreams: %d\n", w.numBackends)
	fmt.Printf("  Load Balancer: %s\n", w.lb)
	fmt.Printf("  Health Check: %s\n", boolStr(w.hcConfig != ""))
	fmt.Printf("  Detectors: %d enabled\n", len(w.detectors))
	fmt.Printf("  Bot Detection: %s\n", boolStr(w.botEnabled))
	fmt.Printf("  Rate Limiting: %s\n", boolStr(w.rateLimitOn))
	fmt.Printf("  CORS: %s\n", boolStr(w.corsConfig != "" && !strings.Contains(w.corsConfig, "enabled: false")))
	fmt.Printf("  ATO Protection: %s\n", boolStr(w.atoConfig != "" && !strings.Contains(w.atoConfig, "enabled: false")))
	fmt.Printf("  Alerting: %s\n", boolStr(w.alertEnabled))
	fmt.Printf("  Docker Discovery: %s\n", boolStr(w.dockerEnabled))
	fmt.Printf("  Dashboard: %s\n", w.dashboardListen)
}

func (w *setupWizard) buildConfig() string {
	upstreamsTargets := strings.Join(w.targets, "\n")

	var buf strings.Builder

	buf.WriteString("# GuardianWAF Configuration\n")
	buf.WriteString("# Generated by guardianwaf setup on " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	buf.WriteString("# ============================================================\n")
	buf.WriteString("# Mode: " + w.mode + " | Listen: " + w.listen + "\n")
	buf.WriteString("# Dashboard: " + w.dashboardListen + " | Upstreams: " + fmt.Sprintf("%d", w.numBackends) + "\n")
	buf.WriteString("# ============================================================\n\n")

	buf.WriteString("mode: " + w.mode + "\n")
	buf.WriteString("listen: \"" + w.listen + "\"\n")
	buf.WriteString("allow_private_upstreams: true\n")
	buf.WriteString(w.tlsConfig + "\n")

	buf.WriteString("upstreams:\n")
	buf.WriteString("  - name: default\n")
	buf.WriteString("    load_balancer: " + w.lb + "\n")
	buf.WriteString("    targets:\n")
	buf.WriteString(upstreamsTargets + "\n")
	buf.WriteString(w.hcConfig + "\n")

	buf.WriteString("routes:\n")
	buf.WriteString("  - path: \"" + w.routePath + "\"\n")
	buf.WriteString("    upstream: default\n\n")
	_ = w.routeHost

	buf.WriteString("logging:\n")
	buf.WriteString("  level: info\n")
	buf.WriteString("  format: json\n")
	buf.WriteString("  log_blocked: true\n")
	buf.WriteString("  log_allowed: false\n\n")

	buf.WriteString("waf:\n")
	buf.WriteString("  ip_acl:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    auto_ban:\n")
	buf.WriteString("      enabled: " + fmt.Sprintf("%t", w.rlAutoBan) + "\n")
	buf.WriteString("      default_ttl: " + w.rlBanDur + "\n")
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
	buf.WriteString("      block: " + w.blockThresh + "\n")
	buf.WriteString("      log: " + w.logThresh + "\n")
	buf.WriteString("    detectors:\n")
	buf.WriteString(w.detectorCfg + "\n")
	buf.WriteString("  challenge:\n")
	buf.WriteString("    enabled: true\n")
	buf.WriteString("    difficulty: 20\n")
	buf.WriteString(w.botConfig + "\n")
	buf.WriteString(w.rateLimitCfg + "\n")
	buf.WriteString(w.corsConfig + "\n")
	buf.WriteString(w.atoConfig + "\n\n")

	buf.WriteString(w.alertConfig + "\n\n")
	buf.WriteString(w.dockerConfig + "\n\n")

	buf.WriteString("dashboard:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  listen: \"" + w.dashboardListen + "\"\n")
	buf.WriteString("  api_key: \"" + w.dashboardPassword + "\"\n\n")

	buf.WriteString("mcp:\n")
	buf.WriteString("  enabled: true\n")
	buf.WriteString("  transport: stdio\n")

	return buf.String()
}

// run executes the full interactive wizard flow and writes the config file.
func (w *setupWizard) run(configPath string) {
	w.promptServerSettings()
	w.promptUpstreams()
	w.promptRouting()
	w.promptWAF()
	w.promptBot()
	w.promptRateLimit()
	w.promptCORS()
	w.promptATO()
	w.promptAlerting()
	w.promptDocker()
	w.promptDashboard()

	w.printSummary()

	fmt.Print("\nGenerate config? (yes/no) [yes]: ")
	if readLine("yes") != "yes" {
		fmt.Println("Setup cancelled.")
		return
	}

	fmt.Println("\nGenerating configuration...")

	// Ensure parent directory exists
	if dirIdx := strings.LastIndex(configPath, "/"); dirIdx > 0 {
		if err := os.MkdirAll(configPath[:dirIdx], 0o750); err != nil {
			fmt.Printf("warning: failed to create directory: %v\n", err)
		}
	}

	configContent := w.buildConfig()

	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║              Setup Complete!                            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Config saved to: %s\n", configPath)
	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────────────┐")
	fmt.Println("  │  IMPORTANT - Save these credentials:                │")
	fmt.Println("  │                                                     │")
	fmt.Printf("  │  Dashboard password: %s                   │\n", w.dashboardPassword)
	fmt.Println("  │                                                     │")
	fmt.Println("  └─────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Printf("    sudo systemctl enable guardianwaf\n")
	fmt.Printf("    sudo systemctl start guardianwaf\n")
	fmt.Printf("    sudo systemctl status guardianwaf\n")
	fmt.Println()
	fmt.Printf("  Or run directly:\n")
	fmt.Printf("    guardianwaf serve -c %s\n", configPath)
	fmt.Println()
}
