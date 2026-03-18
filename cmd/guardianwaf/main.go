// Package main is the CLI entry point for GuardianWAF.
// It supports subcommands: serve, sidecar, check, validate, version, and help.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
	"github.com/guardianwaf/guardianwaf/internal/mcp"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/acme"
	gwaftls "github.com/guardianwaf/guardianwaf/internal/tls"
)

// Build-time variables set by goreleaser or -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	// Register UA parser so Event structs get browser/OS/device info
	engine.SetUAParser(func(ua string) (browser, brVersion, os, deviceType string, isBot bool) {
		p := botdetect.ParseUserAgent(ua)
		return p.Browser, p.BrVersion, p.OS, p.DeviceType, p.IsBot
	})
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "sidecar":
		cmdSidecar(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "version":
		cmdVersion()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
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
  version     Print version information
  help        Show help

Run 'guardianwaf <command> --help' for command-specific options.`)
}

// cmdVersion prints version information.
func cmdVersion() {
	fmt.Printf("guardianwaf %s (commit: %s, built: %s)\n", version, commit, date)
}

// --------------------------------------------------------------------------
// serve
// --------------------------------------------------------------------------

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "guardianwaf.yaml", "Path to config file")
	fs.StringVar(configPath, "c", "guardianwaf.yaml", "Path to config file (short)")
	listenAddr := fs.String("listen", "", "Override listen address")
	fs.StringVar(listenAddr, "l", "", "Override listen address (short)")
	mode := fs.String("mode", "", "Override WAF mode (enforce/monitor/disabled)")
	fs.StringVar(mode, "m", "", "Override WAF mode (short)")
	dashboardAddr := fs.String("dashboard", "", "Override dashboard listen address")
	logLevel := fs.String("log-level", "", "Override log level")
	fs.Parse(args)

	// 1. Load config
	cfg := loadConfig(*configPath)

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
		os.Exit(1)
	}

	// 4. Create event infrastructure
	eventStore := events.NewMemoryStore(cfg.Events.MaxEvents)
	eventBus := events.NewEventBus()

	// 5. Create engine
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create engine: %v\n", err)
		os.Exit(1)
	}

	// 6. Wire all layers
	addLayers(eng, cfg)
	eng.Logs.Infof("Engine initialized in %s mode (block=%d, log=%d)", cfg.Mode, cfg.WAF.Detection.Threshold.Block, cfg.WAF.Detection.Threshold.Log)

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
	var certStore *gwaftls.CertStore
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
					os.MkdirAll(cfg.TLS.ACME.CacheDir, 0700)
					os.WriteFile(accountKeyPath, keyPEM, 0600)
				}
				// Register account
				if err := acmeClient.Register(cfg.TLS.ACME.Email); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: ACME registration: %v\n", err)
				} else {
					// Obtain certs for all ACME domains + vhost domains
					diskStore := acme.NewCertDiskStore(cfg.TLS.ACME.CacheDir, acmeClient, acmeHandler)
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
	if cfg.MCP.Enabled && cfg.MCP.Transport == "stdio" {
		go startMCPServer(eng, cfg)
	}

	// 10. Start dashboard if enabled
	var dashSrv *http.Server
	var sseBroadcaster *dashboard.SSEBroadcaster
	if cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" {
		var dash *dashboard.Dashboard
		dashSrv, sseBroadcaster, dash = startDashboard(cfg, eng)
		// Inject upstream status provider and rebuild function
		if proxyRouter != nil && dash != nil {
			r := proxyRouter
			dash.SetUpstreamsFn(func() any {
				return r.AllUpstreamStatus()
			})
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
				rLayer = rules.NewLayer(rules.Config{Enabled: true}, nil)
				eng.AddLayer(engine.OrderedLayer{Layer: rLayer, Order: engine.OrderRules})
			}
			var gDB *geoip.DB
			if cfg.WAF.GeoIP.Enabled {
				gDB = loadGeoIP(cfg, eng)
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
		}
	}

	// 10b. Wire SSE broadcaster to event bus for real-time dashboard updates
	if sseBroadcaster != nil {
		eventCh := make(chan engine.Event, 256)
		eventBus.Subscribe(eventCh)
		go func() {
			for event := range eventCh {
				sseBroadcaster.BroadcastEvent(event)
			}
		}()
	}

	// 11. Graceful shutdown handling
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		msg := fmt.Sprintf("GuardianWAF %s starting in %s mode on %s", version, cfg.Mode, cfg.Listen)
		fmt.Println(msg)
		eng.Logs.Info(msg)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			eng.Logs.Errorf("HTTP server error: %v", err)
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
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

	srv.Shutdown(ctx)
	if tlsSrv != nil {
		tlsSrv.Shutdown(ctx)
	}
	if certStore != nil {
		certStore.StopReload()
	}
	if dashSrv != nil {
		dashSrv.Shutdown(ctx)
	}
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
	listenAddr := fs.String("listen", ":8080", "Listen address")
	fs.StringVar(listenAddr, "l", ":8080", "Listen address (short)")
	mode := fs.String("mode", "", "Override WAF mode")
	fs.StringVar(mode, "m", "", "Override WAF mode (short)")
	fs.Parse(args)

	// Load config or build from flags
	var cfg *config.Config
	if *configPath != "" {
		cfg = loadConfig(*configPath)
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
		os.Exit(1)
	}

	// Validate
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Create event infrastructure
	eventStore := events.NewMemoryStore(cfg.Events.MaxEvents)
	eventBus := events.NewEventBus()

	// Create engine
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create engine: %v\n", err)
		os.Exit(1)
	}

	// Wire layers
	addLayers(eng, cfg)

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

	// Build handler with /healthz endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
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
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("GuardianWAF sidecar %s starting on %s -> %s\n", version, cfg.Listen, upstreamSummary(cfg))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
		}
	}()

	<-shutdown
	fmt.Println("\nShutting down sidecar...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
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

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "guardianwaf.yaml", "Path to config file")
	fs.StringVar(configPath, "c", "guardianwaf.yaml", "Path to config file (short)")
	urlStr := fs.String("url", "", "URL path to test (e.g., /search?q=test)")
	method := fs.String("method", "GET", "HTTP method")
	verbose := fs.Bool("verbose", false, "Show detailed detection results")
	fs.BoolVar(verbose, "v", false, "Verbose (short)")
	var headers headerSlice
	fs.Var(&headers, "H", "HTTP header in 'Name: Value' format (repeatable)")
	body := fs.String("body", "", "Request body content")
	fs.Parse(args)

	if *urlStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --url is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load config
	cfg := loadConfig(*configPath)
	config.LoadEnv(cfg)

	// Create engine
	eventStore := events.NewMemoryStore(1000)
	eventBus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	// Wire layers
	addLayers(eng, cfg)

	// Build HTTP request from flags
	fullURL := *urlStr
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "http://localhost" + fullURL
	}

	var bodyReader *strings.Reader
	if *body != "" {
		bodyReader = strings.NewReader(*body)
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequest(*method, fullURL, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		os.Exit(1)
	}

	// Apply custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Set default remote addr for IP extraction
	req.RemoteAddr = "127.0.0.1:0"

	// Run check
	event := eng.Check(req)

	// Print results
	fmt.Printf("Action:   %s\n", event.Action)
	fmt.Printf("Score:    %d\n", event.Score)
	fmt.Printf("Duration: %s\n", event.Duration)

	if event.Action == engine.ActionBlock {
		fmt.Println("Result:   BLOCKED")
	} else if event.Action == engine.ActionLog {
		fmt.Println("Result:   LOGGED (suspicious)")
	} else {
		fmt.Println("Result:   PASSED")
	}

	if len(event.Findings) > 0 {
		fmt.Printf("Findings: %d\n", len(event.Findings))
		if *verbose {
			fmt.Println()
			for i, f := range event.Findings {
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
	if event.Action == engine.ActionBlock {
		os.Exit(2)
	}
}

// --------------------------------------------------------------------------
// validate
// --------------------------------------------------------------------------

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "guardianwaf.yaml", "Path to config file")
	fs.StringVar(configPath, "c", "guardianwaf.yaml", "Path to config file (short)")
	fs.Parse(args)

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	config.LoadEnv(cfg)

	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Validation failed:\n%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration %s is valid.\n", *configPath)
	fmt.Printf("  Mode:       %s\n", cfg.Mode)
	fmt.Printf("  Listen:     %s\n", cfg.Listen)
	fmt.Printf("  Upstreams:  %d\n", len(cfg.Upstreams))
	fmt.Printf("  Routes:     %d\n", len(cfg.Routes))
	fmt.Printf("  Detection:  %v (%d detectors)\n", cfg.WAF.Detection.Enabled, len(cfg.WAF.Detection.Detectors))
	fmt.Printf("  Rate Limit: %v (%d rules)\n", cfg.WAF.RateLimit.Enabled, len(cfg.WAF.RateLimit.Rules))
	fmt.Printf("  IP ACL:     %v\n", cfg.WAF.IPACL.Enabled)
	fmt.Printf("  Bot Detect: %v\n", cfg.WAF.BotDetection.Enabled)
	fmt.Printf("  Dashboard:  %v (%s)\n", cfg.Dashboard.Enabled, cfg.Dashboard.Listen)
	fmt.Printf("  MCP:        %v (%s)\n", cfg.MCP.Enabled, cfg.MCP.Transport)
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// loadConfig loads config from path, falling back to defaults if the file is not found.
func loadConfig(path string) *config.Config {
	cfg, err := config.LoadFile(path)
	if err != nil {
		// If default path doesn't exist, use defaults silently
		if path == "guardianwaf.yaml" {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				return config.DefaultConfig()
			}
		}
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// addLayers wires all WAF layers to the engine based on config.
func addLayers(eng *engine.Engine, cfg *config.Config) {
	// 1. IP ACL layer (Order 100)
	if cfg.WAF.IPACL.Enabled {
		ipaclLayer, err := ipacl.NewLayer(ipacl.Config{
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

	// 1b. Custom Rules layer (Order 150)
	if cfg.WAF.CustomRules.Enabled {
		var geodb *geoip.DB
		if cfg.WAF.GeoIP.Enabled {
			geodb = loadGeoIP(cfg, eng)
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

		rulesLayer := rules.NewLayer(rules.Config{Enabled: true, Rules: ruleList}, geodb)
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
		rlLayer := ratelimit.NewLayer(ratelimit.Config{
			Enabled: cfg.WAF.RateLimit.Enabled,
			Rules:   rules,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})
	}

	// 3. Sanitizer layer (Order 300)
	if cfg.WAF.Sanitizer.Enabled {
		sanLayer := sanitizer.NewLayer(sanitizer.SanitizerConfig{
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
		detLayer := detection.NewLayer(detection.Config{
			Enabled:    cfg.WAF.Detection.Enabled,
			Detectors:  detConfigs,
			Exclusions: exclusions,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: engine.OrderDetection})
	}

	// 5. Bot Detection layer (Order 500)
	if cfg.WAF.BotDetection.Enabled {
		bdLayer := botdetect.NewLayer(botdetect.Config{
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
	respLayer := response.NewLayer(respCfg)
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
	var defaultRoutes []proxy.Route
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
func startMCPServer(eng *engine.Engine, cfg *config.Config) {
	mcpSrv := mcp.NewServer(os.Stdin, os.Stdout)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(&mcpEngineAdapter{engine: eng, cfg: cfg})
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

// --------------------------------------------------------------------------
// MCP engine adapter
// --------------------------------------------------------------------------

// mcpEngineAdapter adapts the engine.Engine to the mcp.EngineInterface.
type mcpEngineAdapter struct {
	engine *engine.Engine
	cfg    *config.Config
}

func (a *mcpEngineAdapter) GetStats() interface{} {
	s := a.engine.Stats()
	return map[string]interface{}{
		"total_requests":   s.TotalRequests,
		"blocked_requests": s.BlockedRequests,
		"logged_requests":  s.LoggedRequests,
		"passed_requests":  s.PassedRequests,
		"avg_latency_us":   s.AvgLatencyUs,
	}
}

func (a *mcpEngineAdapter) GetConfig() interface{} {
	cfg := a.engine.Config()
	return map[string]interface{}{
		"mode":   cfg.Mode,
		"listen": cfg.Listen,
		"waf": map[string]interface{}{
			"ip_acl_enabled":     cfg.WAF.IPACL.Enabled,
			"rate_limit_enabled": cfg.WAF.RateLimit.Enabled,
			"sanitizer_enabled":  cfg.WAF.Sanitizer.Enabled,
			"detection_enabled":  cfg.WAF.Detection.Enabled,
			"bot_detect_enabled": cfg.WAF.BotDetection.Enabled,
			"threshold_block":    cfg.WAF.Detection.Threshold.Block,
			"threshold_log":      cfg.WAF.Detection.Threshold.Log,
		},
		"dashboard": map[string]interface{}{
			"enabled": cfg.Dashboard.Enabled,
			"listen":  cfg.Dashboard.Listen,
		},
		"mcp": map[string]interface{}{
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
	// Validate IP/CIDR
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	return nil
}

func (a *mcpEngineAdapter) RemoveWhitelist(ip string) error {
	return nil
}

func (a *mcpEngineAdapter) AddBlacklist(ip string) error {
	if !isValidIPOrCIDR(ip) {
		return fmt.Errorf("invalid IP or CIDR: %s", ip)
	}
	return nil
}

func (a *mcpEngineAdapter) RemoveBlacklist(ip string) error {
	return nil
}

func (a *mcpEngineAdapter) AddRateLimit(rule interface{}) error {
	return nil
}

func (a *mcpEngineAdapter) RemoveRateLimit(id string) error {
	return nil
}

func (a *mcpEngineAdapter) AddExclusion(path string, detectors []string, reason string) error {
	return nil
}

func (a *mcpEngineAdapter) RemoveExclusion(path string) error {
	return nil
}

func (a *mcpEngineAdapter) GetEvents(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"events": []interface{}{},
		"total":  0,
	}, nil
}

func (a *mcpEngineAdapter) GetTopIPs(n int) interface{} {
	return []interface{}{}
}

func (a *mcpEngineAdapter) GetDetectors() interface{} {
	cfg := a.engine.Config()
	var detectors []map[string]interface{}
	for name, dc := range cfg.WAF.Detection.Detectors {
		detectors = append(detectors, map[string]interface{}{
			"name":       name,
			"enabled":    dc.Enabled,
			"multiplier": dc.Multiplier,
		})
	}
	return detectors
}

func (a *mcpEngineAdapter) TestRequest(method, urlStr string, headers map[string]string) (interface{}, error) {
	fullURL := urlStr
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "http://localhost" + fullURL
	}

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "127.0.0.1:0"

	event := a.engine.Check(req)
	var findings []map[string]interface{}
	for _, f := range event.Findings {
		findings = append(findings, map[string]interface{}{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
		})
	}

	return map[string]interface{}{
		"action":   event.Action.String(),
		"score":    event.Score,
		"findings": findings,
		"duration": event.Duration.String(),
	}, nil
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
func loadGeoIP(cfg *config.Config, eng *engine.Engine) *geoip.DB {
	// Try loading from specified path
	if cfg.WAF.GeoIP.DBPath != "" {
		db, err := geoip.LoadCSV(cfg.WAF.GeoIP.DBPath)
		if err == nil {
			eng.Logs.Infof("GeoIP DB loaded: %d ranges from %s", db.Count(), cfg.WAF.GeoIP.DBPath)
			return db
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
			return nil
		}
		eng.Logs.Infof("GeoIP DB ready: %d ranges", db.Count())
		return db
	}

	return nil
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
