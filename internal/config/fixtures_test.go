package config

import (
	"os"
	"path/filepath"
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
			embedded, err := extractEmbeddedGuardianWAFConfig(string(data))
			if err != nil {
				t.Fatalf("extractEmbeddedGuardianWAFConfig() error = %v", err)
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

func TestInvalidConfigFixtureFailsValidation(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "testdata/configs/invalid.yml"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate() error = nil, want validation failure")
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

func extractEmbeddedGuardianWAFConfig(data string) (string, error) {
	lines := strings.Split(data, "\n")
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
			return "", os.ErrNotExist
		}
		if minIndent < 0 {
			minIndent = 0
		}
		for j, blockLine := range blockLines {
			if len(blockLine) >= minIndent {
				blockLines[j] = blockLine[minIndent:]
			}
		}
		return strings.TrimSpace(strings.Join(blockLines, "\n")) + "\n", nil
	}
	return "", os.ErrNotExist
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}
