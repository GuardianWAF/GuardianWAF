// Package main is the CLI entry point for GuardianWAF.
// It supports subcommands: serve, sidecar, check, validate, version, and help.

//go:build http3

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

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/mcp"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
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
		return cmdHealthcheck(args[2:])
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
	dashboardPassword, err := generateDashboardPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate dashboard API key: %v\n", err)
		return
	}

	wizard := newSetupWizard(dashboardPassword)
	wizard.run(*configPath)
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
	loadedConfigPath := *configPath
	if loadedConfigPath == "" {
		loadedConfigPath = DefaultConfigPath()
	}
	cfg := loadConfig(loadedConfigPath, explicitPath)

	// 2. Apply environment variable overrides, then CLI overrides
	if err := config.LoadEnv(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration environment error: %v\n", err)
		osExit(1)
		return
	}
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
		return
	}

	// 4. Create runtime engine
	eventStore, eventBus, eng, layerResources, err := setupRuntimeEngine(cfg)
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

	// Mount challenge verification endpoint
	registerChallengeHandler(serveMux, challengeSvc)

	registerClientSideReportHandlers(serveMux)

	// Mount upstream proxy or default handler
	var proxyRuntimeMu sync.RWMutex
	var alertMgrPtr atomic.Pointer[alerting.Manager]
	var dockerWatcherPtr atomic.Pointer[dkr.Watcher]
	var tenantMWPtr atomic.Pointer[tenant.Middleware]
	var aiAnalyzerPtr atomic.Pointer[ai.Analyzer]
	upstream, proxyRouter, proxyHealthCheckers := buildProxyRuntime(cfg, standaloneNoUpstreamHandler())
	registerMetricsHandlerWithDeps(serveMux, eng, metricsDependencies{
		Router: func() *proxy.Router {
			proxyRuntimeMu.RLock()
			defer proxyRuntimeMu.RUnlock()
			return proxyRouter
		},
		AlertManager: alertMgrPtr.Load,
		DockerEnabled: func() bool {
			return cfg.Docker.Enabled
		},
		DockerWatcher: dockerWatcherPtr.Load,
		AIEnabled: func() bool {
			return cfg.WAF.AIAnalysis.Enabled
		},
		AIAnalyzer: aiAnalyzerPtr.Load,
	})
	var dashboardReady atomic.Bool
	registerProbeHandlersWithDeps(serveMux, cfg, eng, probeDependencies{
		Router: func() *proxy.Router {
			proxyRuntimeMu.RLock()
			defer proxyRuntimeMu.RUnlock()
			return proxyRouter
		},
		DashboardReady: dashboardReady.Load,
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

	// 10. Prepare MCP SSE registration after dashboard startup.
	var mcpSSE *mcp.SSEHandler

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
		if dashSrv == nil || dash == nil {
			fmt.Fprintf(os.Stderr, "Failed to start dashboard on %s\n", cfg.Dashboard.Listen)
			osExit(1)
			return
		}
		dashboardReady.Store(dashSrv != nil && dash != nil)
		wireDashboardProxyControls(dash, cfg, eng, loadedConfigPath, &proxyRouter, &proxyHealthCheckers, &proxyRuntimeMu, &upstreamHandler, &tenantMWPtr, diskStore)
		wireDashboardRules(dash, cfg, eng, layerResources)
	}

	// Register MCP SSE routes on dashboard mux
	if cfg.MCP.Enabled && dash != nil {
		// SSE transport is served via the dashboard port and protected by the
		// final dashboard API key, including keys generated during startup.
		mcpSSE = buildMCPSSEHandler(eng, cfg, eventStore, nil, dash.CurrentAPIKey)
		mcpSSE.RegisterRoutes(dash.Mux())
		eng.Logs.Info("MCP SSE endpoints registered: GET /mcp/sse, POST /mcp/message")
	}

	tenantManager, tenantMiddleware := setupTenantRuntime(cfg, eng, dash, &upstreamHandler, &tenantMWPtr)
	aiAnalyzer := setupAIRuntime(cfg, eng, eventBus, dash)
	if aiAnalyzer != nil {
		aiAnalyzerPtr.Store(aiAnalyzer)
	}

	var eventConsumerWG sync.WaitGroup

	// 10c. Start alerting/webhooks if enabled
	alertMgr := setupAlertingRuntime(cfg, eng, eventBus, eventStore, dash, &eventConsumerWG, os.Stdin, os.Stdout)
	if alertMgr != nil {
		alertMgrPtr.Store(alertMgr)
	}
	if startMCPStdioRuntime(eng, cfg, eventStore, alertMgr, os.Stdin, os.Stdout) {
		eng.Logs.Info("MCP stdio transport enabled")
	}

	// 10c.2 Start SIEM export if enabled
	siemExp := setupSIEMRuntime(cfg, eng, eventBus, &eventConsumerWG, dash)

	// 10d. Start Docker auto-discovery if enabled
	dockerWatcher := setupDockerRuntime(cfg, eng, dash, &proxyRouter, &proxyHealthCheckers, &proxyRuntimeMu, &upstreamHandler, tenantMiddleware)
	if dockerWatcher != nil {
		dockerWatcherPtr.Store(dockerWatcher)
	}

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
	if err := shutdownServeRuntime(ctx, serveShutdownResources{
		server:              srv,
		tlsServer:           tlsSrv,
		dashboardServer:     dashSrv,
		certStore:           certStore,
		acmeRenewal:         diskStore,
		engine:              eng,
		proxyRuntimeMu:      &proxyRuntimeMu,
		proxyRouter:         &proxyRouter,
		proxyHealthCheckers: &proxyHealthCheckers,
		cleanupStop:         cleanupStop,
		cleanupWG:           cleanupWG,
		dockerWatcher:       dockerWatcher,
		aiAnalyzer:          aiAnalyzer,
		alertManager:        alertMgr,
		dashboard:           dash,
		tenantManager:       tenantManager,
		siemExporter:        siemExp,
		eventConsumerWG:     &eventConsumerWG,
		layerResources:      layerResources,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "GuardianWAF shutdown failed: %v\n", err)
		osExit(1)
	}
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
	} else {
		cfg = config.DefaultConfig()
	}
	if err := config.LoadEnv(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration environment error: %v\n", err)
		osExit(1)
		return
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
		return
	}

	// Validate
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		osExit(1)
		return
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	_, _, eng, layerResources, err := setupRuntimeEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize runtime engine: %v\n", err)
		osExit(1)
		return
	}

	if _, err := setupChallengeService(cfg, eng); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating challenge service: %v\n", err)
		return
	}
	cleanupStop, cleanupWG := startPeriodicCleanup(eng, nil, periodicCleanupInterval)

	// Build handler with probe and metrics endpoints
	mux := http.NewServeMux()
	registerClientSideReportHandlers(mux)

	proxyHandler, sidecarRouter, sidecarHealthCheckers := buildProxyRuntime(cfg, sidecarNoUpstreamHandler())
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{
		Router: func() *proxy.Router {
			return sidecarRouter
		},
	})
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := shutdownSidecarRuntime(ctx, sidecarShutdownResources{
		server:              srv,
		engine:              eng,
		proxyRouter:         &sidecarRouter,
		proxyHealthCheckers: &sidecarHealthCheckers,
		cleanupStop:         cleanupStop,
		cleanupWG:           cleanupWG,
		layerResources:      layerResources,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "GuardianWAF sidecar shutdown failed: %v\n", err)
		osExit(1)
	}
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
	if err := config.LoadEnv(cfg); err != nil {
		return nil, fmt.Errorf("invalid environment configuration: %w", err)
	}
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create engine
	eventStore := events.NewMemoryStore(1000)
	eventBus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}
	defer eng.Close()
	layerResources := &layerRuntimeResources{}
	defer func() {
		_ = layerResources.stopGeoIPRefresh(context.Background())
	}()

	// Wire layers
	if addErr := addLayersWithRuntime(eng, cfg, layerResources); addErr != nil {
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
		return
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
		return
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
	if err := config.LoadEnv(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration environment error: %v\n", err)
		osExit(1)
		return
	}
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		osExit(1)
		return
	}

	if !cfg.Alerting.Enabled {
		fmt.Fprintf(os.Stderr, "Alerting is not enabled in configuration\n")
		osExit(1)
		return
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
		if len(cfg.Alerting.Webhooks)+len(cfg.Alerting.Emails) == 0 {
			fmt.Fprintln(os.Stderr, "No alert targets are configured")
			osExit(1)
			return
		}
		failed := false
		for _, w := range cfg.Alerting.Webhooks {
			fmt.Printf("  Testing webhook: %s... ", w.Name)
			if err := mgr.TestAlert(w.Name); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				failed = true
			} else {
				fmt.Println("OK")
			}
		}
		for _, e := range cfg.Alerting.Emails {
			fmt.Printf("  Testing email: %s... ", e.Name)
			if err := mgr.TestAlert(e.Name); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				failed = true
			} else {
				fmt.Println("OK")
			}
		}
		if failed {
			osExit(1)
			return
		}
	} else if *target != "" {
		fmt.Printf("Testing alert target: %s... ", *target)
		if err := mgr.TestAlert(*target); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			osExit(1)
			return
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
		return
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

	if err := config.LoadEnv(cfg); err != nil {
		return nil, nil, fmt.Errorf("environment configuration: %w", err)
	}

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
		return nil
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
