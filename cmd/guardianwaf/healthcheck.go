package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
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
		config.LoadEnv(cfg)
		target = "http://" + probeHostPort(cfg.Listen) + "/livez"
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: *timeout}).DialContext,
			// Loopback probe: no connection reuse, tight handshake bounds.
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
	resp, err := client.Get(target)
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
