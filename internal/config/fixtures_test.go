package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGuardianWAFConfigFixturesValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := []string{
		"guardianwaf.yaml",
		"examples/standalone/guardianwaf.yaml",
		"testdata/configs/minimal.yml",
		"testdata/configs/full.yml",
		"testdata/configs/sidecar.yml",
		"testdata/docker-test.yaml",
		"testdata/realtest.yaml",
	}
	profiles, err := filepath.Glob(filepath.Join(root, "examples", "profiles", "*.yaml"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("no production config profiles found")
	}
	for _, profile := range profiles {
		rel, err := filepath.Rel(root, profile)
		if err != nil {
			t.Fatalf("Rel() error = %v", err)
		}
		fixtures = append(fixtures, rel)
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			cfg, err := LoadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("LoadFile() error = %v", err)
			}
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestKubernetesEmbeddedConfigFixturesValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := []string{
		"examples/kubernetes/configmap.yaml",
		"contrib/k8s/configmap.yaml",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			embeddedConfigs, err := extractEmbeddedGuardianWAFConfigs(string(data))
			if err != nil {
				t.Fatalf("extractEmbeddedGuardianWAFConfigs() error = %v", err)
			}
			for name, embedded := range embeddedConfigs {
				t.Run(name, func(t *testing.T) {
					cfg, err := loadConfigBytes([]byte(embedded))
					if err != nil {
						t.Fatalf("loadConfigBytes() error = %v", err)
					}
					if err := Validate(cfg); err != nil {
						t.Fatalf("Validate() error = %v", err)
					}
				})
			}
		})
	}
}

func TestComposeMountedConfigFixturesValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := map[string][]string{
		"docker-compose.yml":      {"guardianwaf.yaml"},
		"docker-compose.prod.yml": {"guardianwaf.yaml"},
		"docker-compose.test.yml": {"testdata/docker-test.yaml"},
	}

	for fixture, expected := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			mounted := extractComposeGuardianWAFMounts(string(data))
			if len(mounted) != len(expected) {
				t.Fatalf("mounted configs = %v, want %v", mounted, expected)
			}
			for i, want := range expected {
				if mounted[i] != want {
					t.Fatalf("mounted config[%d] = %q, want %q", i, mounted[i], want)
				}
				cfg, err := LoadFile(filepath.Join(root, mounted[i]))
				if err != nil {
					t.Fatalf("LoadFile(%q) error = %v", mounted[i], err)
				}
				if err := Validate(cfg); err != nil {
					t.Fatalf("Validate(%q) error = %v", mounted[i], err)
				}
			}
		})
	}
}

func TestInstallerGeneratedConfigSnippetsValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := map[string]func(string) (string, error){
		"scripts/install.sh":  extractShellInstallerConfig,
		"scripts/install.ps1": extractPowerShellInstallerConfig,
	}

	for fixture, extract := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			embedded, err := extract(string(data))
			if err != nil {
				t.Fatalf("extract installer config: %v", err)
			}
			cfg, err := loadConfigBytes([]byte(embedded))
			if err != nil {
				t.Fatalf("loadConfigBytes() error = %v", err)
			}
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestMarkdownGuardianWAFConfigSnippetsValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := []string{
		"README.md",
		"docs/configuration.md",
		"docs/deployment-modes.md",
		"docs/docker-discovery.md",
		"docs/getting-started.md",
		"docs/production-deployment.md",
		"docs/runbook.md",
		"docs/security-best-practices.md",
		"docs/state-persistence.md",
		"docs/tuning-guide.md",
		"docs/design/GuardianWAF-Claude-Code-Prompt.md",
		"docs/design/SPECIFICATION.md",
	}

	total := 0
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			snippets, err := extractMarkedMarkdownConfigs(string(data))
			if err != nil {
				t.Fatalf("extract marked configs: %v", err)
			}
			total += len(snippets)
			for i, snippet := range snippets {
				t.Run(filepath.Base(fixture)+"#"+strconv.Itoa(i+1), func(t *testing.T) {
					cfg, err := loadConfigBytes([]byte(snippet))
					if err != nil {
						t.Fatalf("loadConfigBytes() error = %v\n%s", err, snippet)
					}
					if err := Validate(cfg); err != nil {
						t.Fatalf("Validate() error = %v\n%s", err, snippet)
					}
				})
			}
		})
	}
	if total == 0 {
		t.Fatal("no marked markdown GuardianWAF config snippets found")
	}
}

func TestWebsiteGuardianWAFConfigSnippetsValidate(t *testing.T) {
	root := filepath.Join("..", "..")
	fixture := filepath.Join("website", "src", "content", "docs.ts")
	data, err := os.ReadFile(filepath.Join(root, fixture))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	snippets, err := extractWebsiteGuardianWAFConfigs(string(data))
	if err != nil {
		t.Fatalf("extract website configs: %v", err)
	}
	for i, snippet := range snippets {
		t.Run("website#"+strconv.Itoa(i+1), func(t *testing.T) {
			cfg, err := loadConfigBytes([]byte(snippet))
			if err != nil {
				t.Fatalf("loadConfigBytes() error = %v\n%s", err, snippet)
			}
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v\n%s", err, snippet)
			}
		})
	}
}

func TestWebsiteRuntimeExamplesUseCurrentCLIAndEnvContract(t *testing.T) {
	path := filepath.Join("..", "..", "website", "src", "content", "docs.ts")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)

	for _, forbidden := range []string{
		"GUARDIANWAF_",
		"serve --listen :8088 --upstream",
		"serve --dry-run",
		"--block-score",
		"--log-score",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("%s contains stale runtime example %q", path, forbidden)
		}
	}
	for _, want := range []string{
		"GWAF_ prefix",
		"GWAF_WAF_DETECTION_THRESHOLD_BLOCK",
		"guardianwaf serve",
		"guardianwaf sidecar",
		"--mode monitor",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing current runtime example %q", path, want)
		}
	}
}

func TestWebsiteGoAPIExamplesUseCurrentPublicPackageContract(t *testing.T) {
	path := filepath.Join("..", "..", "website", "src", "content", "docs.ts")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)

	for _, forbidden := range []string{
		"(*WAF, error)",
		"*WAF)",
		"func (w *WAF)",
		"HandlerFunc",
		"Analyze(",
		"BlockScore",
		"LogScore",
		"DryRun",
		"ModeProxy",
		"ModeLibrary",
		"ModeSidecar",
		"DetectorID",
		"WeightConfig",
		"waf.Handler(",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("%s contains stale Go API example %q", path, forbidden)
		}
	}
	for _, want := range []string{
		"func New(config Config, opts ...Option) (*Engine, error)",
		"func NewFromFile(path string, opts ...Option) (*Engine, error)",
		"func (e *Engine) Middleware(next http.Handler) http.Handler",
		"func (e *Engine) Check(r *http.Request) Result",
		"func (e *Engine) OnEvent(fn func(Event))",
		"func (e *Engine) Stats() Stats",
		"ModeEnforce, ModeMonitor, ModeDisabled",
		"waf.Middleware(mux)",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing current Go API example %q", path, want)
		}
	}
}

func TestPublicMarkdownGuardianWAFConfigBlocksAreMarked(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := []string{
		"README.md",
		"docs/configuration.md",
		"docs/deployment-modes.md",
		"docs/docker-discovery.md",
		"docs/getting-started.md",
		"docs/production-deployment.md",
		"docs/runbook.md",
		"docs/security-best-practices.md",
		"docs/state-persistence.md",
		"docs/tuning-guide.md",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, fixture))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			blocks, err := extractMarkdownYAMLBlocks(string(data))
			if err != nil {
				t.Fatalf("extract yaml blocks: %v", err)
			}
			for _, block := range blocks {
				if !isGuardianWAFConfigBlock(block.content) {
					continue
				}
				if !block.marked {
					t.Fatalf("GuardianWAF config YAML block at line %d must be preceded by <!-- guardianwaf-config:validate -->", block.line)
				}
			}
		})
	}
}

func TestConfigurationDocsDocumentLegacyKeyMigration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	required := []string{
		"## Migrating Legacy Config Keys",
		"`server.listen`",
		"`listen`",
		"`server.mode`",
		"`mode`",
		"`proxy.upstreams`",
		"`upstreams`",
		"`proxy.routes`",
		"`routes`",
		"`security.waf`",
		"`waf`",
		"unknown top-level key",
		"guardianwaf validate -c guardianwaf.yaml",
	}
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Fatalf("configuration.md missing legacy migration guidance %q", want)
		}
	}
}

func TestInvalidConfigFixtureFailsValidation(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "testdata/configs/invalid.yml"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want validation failure")
	}
}

func extractWebsiteGuardianWAFConfigs(data string) ([]string, error) {
	const marker = "language: 'yaml', filename: 'guardianwaf.yaml', code: `"
	var configs []string
	for offset := 0; ; {
		idx := strings.Index(data[offset:], marker)
		if idx < 0 {
			break
		}
		start := offset + idx + len(marker)
		end := strings.Index(data[start:], "` }")
		if end < 0 {
			return nil, os.ErrInvalid
		}
		configs = append(configs, strings.TrimSpace(data[start:start+end])+"\n")
		offset = start + end + len("` }")
	}
	if len(configs) == 0 {
		return nil, os.ErrNotExist
	}
	return configs, nil
}

func extractMarkedMarkdownConfigs(data string) ([]string, error) {
	const marker = "<!-- guardianwaf-config:validate -->"
	lines := strings.Split(data, "\n")
	var configs []string
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != marker {
			continue
		}
		i++
		for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
		if i >= len(lines) || strings.TrimSpace(lines[i]) != "```yaml" {
			return nil, os.ErrInvalid
		}
		i++
		var block []string
		for ; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "```" {
				break
			}
			block = append(block, lines[i])
		}
		if i >= len(lines) {
			return nil, os.ErrInvalid
		}
		configs = append(configs, strings.TrimSpace(strings.Join(block, "\n"))+"\n")
	}
	if len(configs) == 0 {
		return nil, os.ErrNotExist
	}
	return configs, nil
}

type markdownYAMLBlock struct {
	line    int
	content string
	marked  bool
}

func extractMarkdownYAMLBlocks(data string) ([]markdownYAMLBlock, error) {
	const marker = "<!-- guardianwaf-config:validate -->"
	lines := strings.Split(data, "\n")
	var blocks []markdownYAMLBlock
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "```yaml" && trimmed != "```yml" {
			continue
		}

		marked := false
		for j := i - 1; j >= 0; j-- {
			prev := strings.TrimSpace(lines[j])
			if prev == "" {
				continue
			}
			marked = prev == marker
			break
		}

		var block []string
		startLine := i + 1
		i++
		for ; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "```" {
				break
			}
			block = append(block, lines[i])
		}
		if i >= len(lines) {
			return nil, os.ErrInvalid
		}
		blocks = append(blocks, markdownYAMLBlock{
			line:    startLine,
			content: strings.Join(block, "\n"),
			marked:  marked,
		})
	}
	return blocks, nil
}

func isGuardianWAFConfigBlock(data string) bool {
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		key, _, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		return isGuardianWAFTopLevelConfigKey(strings.TrimSpace(key))
	}
	return false
}

func isGuardianWAFTopLevelConfigKey(key string) bool {
	switch key {
	case "mode",
		"listen",
		"trusted_proxies",
		"allowed_upstream_cidrs",
		"allow_private_upstreams",
		"tls",
		"upstreams",
		"routes",
		"virtual_hosts",
		"waf",
		"dashboard",
		"mcp",
		"logging",
		"events",
		"alerting",
		"docker":
		return true
	default:
		return false
	}
}

func loadConfigBytes(data []byte) (*Config, error) {
	node, err := Parse(data)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		return nil, err
	}
	return cfg, nil
}

func extractEmbeddedGuardianWAFConfigs(data string) (map[string]string, error) {
	lines := strings.Split(data, "\n")
	configs := make(map[string]string)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "guardianwaf.yaml: |" && trimmed != "guardianwaf.yml: |" {
			continue
		}

		keyIndent := leadingSpaces(line)
		blockLines := make([]string, 0)
		minIndent := -1
		for _, blockLine := range lines[i+1:] {
			if strings.TrimSpace(blockLine) == "" {
				blockLines = append(blockLines, "")
				continue
			}
			indent := leadingSpaces(blockLine)
			if indent <= keyIndent {
				break
			}
			if minIndent == -1 || indent < minIndent {
				minIndent = indent
			}
			blockLines = append(blockLines, blockLine)
		}
		if len(blockLines) == 0 {
			return nil, os.ErrNotExist
		}
		if minIndent < 0 {
			minIndent = 0
		}
		for j, blockLine := range blockLines {
			if len(blockLine) >= minIndent {
				blockLines[j] = blockLine[minIndent:]
			}
		}
		configs[strings.TrimSuffix(trimmed, ": |")] = strings.TrimSpace(strings.Join(blockLines, "\n")) + "\n"
	}
	if len(configs) == 0 {
		return nil, os.ErrNotExist
	}
	return configs, nil
}

func extractComposeGuardianWAFMounts(data string) []string {
	var mounts []string
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "-") {
			continue
		}
		volume := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		volume = strings.Trim(volume, `"'`)
		idx := strings.Index(volume, ":/etc/guardianwaf/guardianwaf.yaml")
		if idx < 0 {
			continue
		}
		hostPath := strings.TrimPrefix(volume[:idx], "./")
		if hostPath == "" || strings.HasPrefix(hostPath, "/") {
			continue
		}
		mounts = append(mounts, filepath.Clean(hostPath))
	}
	return mounts
}

func extractShellInstallerConfig(data string) (string, error) {
	startMarker := "cat > \"$config_file\" << EOF\n"
	start := strings.Index(data, startMarker)
	if start < 0 {
		return "", os.ErrNotExist
	}
	start += len(startMarker)
	end := strings.Index(data[start:], "\nEOF")
	if end < 0 {
		return "", os.ErrNotExist
	}
	return strings.TrimSpace(data[start:start+end]) + "\n", nil
}

func extractPowerShellInstallerConfig(data string) (string, error) {
	startMarker := "@\"\n"
	start := strings.Index(data, startMarker)
	if start < 0 {
		return "", os.ErrNotExist
	}
	start += len(startMarker)
	end := strings.Index(data[start:], "\n\"@ | Out-File")
	if end < 0 {
		return "", os.ErrNotExist
	}
	return strings.TrimSpace(data[start:start+end]) + "\n", nil
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}
