package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// cmdHealthcheck probes the running server's /livez endpoint and returns the
// process exit code. It is the container HEALTHCHECK command, so it must
// report the actual server state: exit 0 only when the server answers.
func cmdHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: platform-specific)")
	fs.StringVar(configPath, "c", "", "Path to config file (short)")
	probeURL := fs.String("url", "", "Probe URL (default: http://127.0.0.1:<listen port>/livez)")
	timeout := fs.Duration("timeout", 3*time.Second, "Probe timeout")
	_ = fs.Parse(args) // nolint:errcheck // ExitOnError flag set never returns an error

	target := *probeURL
	if target == "" {
		target = os.Getenv("GWAF_HEALTHCHECK_URL")
	}
	if target == "" {
		cfg := loadConfig(*configPath, *configPath != "")
		if err := config.LoadEnv(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: invalid environment configuration: %v\n", err)
			return 1
		}
		target = "http://" + probeHostPort(cfg.Listen) + "/livez"
	}
	validationCtx, cancelValidation := context.WithTimeout(context.Background(), *timeout)
	parsedTarget, err := validateHealthcheckTarget(validationCtx, target)
	cancelValidation()
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: unsafe probe URL: %v\n", err)
		return 1
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			DialContext: localHealthcheckDialContext(*timeout),
			// Local probe: no connection reuse, tight handshake bounds.
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   *timeout,
			ResponseHeaderTimeout: *timeout,
			ExpectContinueTimeout: time.Second,
		},
		// A TLS http_redirect setup answers /livez on the HTTP port with a
		// 301; reaching the server at all proves liveness, so don't follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, parsedTarget.String(), nil) // #nosec G704 -- validateHealthcheckTarget restricts the URL to a local /livez endpoint.
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: invalid probe request: %v\n", err)
		return 1
	}
	resp, err := client.Do(req) // #nosec G704 -- dial-time DNS results are restricted to local interfaces and the validated IP is dialed directly.
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close() // nolint:errcheck // read-only probe response
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		fmt.Println("OK")
		return 0
	}
	fmt.Fprintf(os.Stderr, "healthcheck failed: %s returned HTTP %d\n", target, resp.StatusCode)
	return 1
}

// validateHealthcheckTarget limits the container healthcheck command to the
// local GuardianWAF liveness endpoint. The command accepts an override for
// unusual bind addresses, but it must never become a general-purpose URL
// fetcher that can reach metadata or other internal services.
func validateHealthcheckTarget(ctx context.Context, rawURL string) (*url.URL, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("host is required")
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials are not allowed")
	}
	if u.Path != "/livez" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("path must be exactly /livez without query or fragment")
	}
	if err := validateLocalHealthcheckHost(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	return u, nil
}

func validateLocalHealthcheckHost(ctx context.Context, host string) error {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("host %q has no addresses", host)
	}
	for _, address := range addresses {
		if !isLocalHealthcheckIP(address.IP) {
			return fmt.Errorf("host %q resolves to non-local address %s", host, address.IP)
		}
	}
	return nil
}

func isLocalHealthcheckIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range interfaces {
		localIP, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil && localIP.Equal(ip) {
			return true
		}
	}
	return false
}

// localHealthcheckDialContext resolves once, validates every result, and
// dials a validated local IP directly. This prevents DNS rebinding between a
// preflight validation and the actual connection.
func localHealthcheckDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("healthcheck dial address: %w", err)
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("healthcheck resolve %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("healthcheck host %q has no addresses", host)
		}
		for _, resolved := range addresses {
			if !isLocalHealthcheckIP(resolved.IP) {
				return nil, fmt.Errorf("healthcheck host %q resolves to non-local address %s", host, resolved.IP)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}
}

// probeHostPort converts a listen address into a loopback host:port to probe.
func probeHostPort(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "127.0.0.1:8088"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
