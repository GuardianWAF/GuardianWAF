package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCLISmokeScriptUsesMinimalSelfContainedConfig(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "scripts", "smoke-test.sh"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	configYAML, ok := extractSmokeScriptConfig(string(data))
	if !ok {
		t.Fatal("scripts/smoke-test.sh missing CONFIG heredoc")
	}
	cfg, err := loadConfigBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("loadConfigBytes() error = %v\n%s", err, configYAML)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v\n%s", err, configYAML)
	}

	assertUnprivilegedListen(t, "listen", cfg.Listen)
	if !cfg.Dashboard.Enabled {
		t.Fatal("CLI smoke config must keep dashboard enabled so dashboard auth/health paths are tested")
	}
	assertUnprivilegedListen(t, "dashboard.listen", cfg.Dashboard.Listen)
	if cfg.Dashboard.TLS {
		t.Fatal("CLI smoke config must not require dashboard TLS certificates")
	}
	if cfg.TLS.Enabled || cfg.TLS.ACME.Enabled {
		t.Fatal("CLI smoke config must not require TLS or ACME")
	}
	if cfg.Docker.Enabled {
		t.Fatal("CLI smoke config must not require Docker")
	}
	if cfg.WAF.AIAnalysis.Enabled {
		t.Fatal("CLI smoke config must not require external AI providers")
	}
	if cfg.Alerting.Enabled || len(cfg.Alerting.Webhooks) > 0 || len(cfg.Alerting.Emails) > 0 {
		t.Fatal("CLI smoke config must not require outbound alerting integrations")
	}
	if cfg.MCP.Enabled {
		t.Fatal("CLI smoke config must not require MCP listener setup")
	}
}

func extractSmokeScriptConfig(script string) (string, bool) {
	const start = "cat > \"$CONFIG\" <<'YAML'\n"
	startIndex := strings.Index(script, start)
	if startIndex < 0 {
		return "", false
	}
	rest := script[startIndex+len(start):]
	endIndex := strings.Index(rest, "\nYAML")
	if endIndex < 0 {
		return "", false
	}
	return rest[:endIndex], true
}

func assertUnprivilegedListen(t *testing.T, field, listen string) {
	t.Helper()
	portText := listen
	if strings.Contains(listen, ":") {
		var err error
		_, portText, err = net.SplitHostPort(listen)
		if err != nil {
			if strings.HasPrefix(listen, ":") {
				portText = strings.TrimPrefix(listen, ":")
			} else {
				t.Fatalf("%s listen address %q is not parseable: %v", field, listen, err)
			}
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("%s listen address %q has non-numeric port %q", field, listen, portText)
	}
	if port < 1024 {
		t.Fatalf("%s listen address %q uses privileged port %d", field, listen, port)
	}
}
