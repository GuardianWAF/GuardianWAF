package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubernetesHelmDocsCoverProductionDeploymentExamples(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "kubernetes-helm.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)

	required := []string{
		"## Secret Management",
		"kubectl create secret generic guardianwaf-dashboard-auth",
		"apiKey:",
		"existingSecret: guardianwaf-dashboard-auth",
		"adminKey:",
		"## Persistent State",
		"persistence:",
		"enabled: true",
		"ReadWriteOnce",
		"ReadWriteMany",
		"existingClaim: guardianwaf-state",
		"## Proxy and Dashboard Ingress",
		"host: waf.example.com",
		"host: dashboard.example.com",
		"trusted_proxies",
		"automountServiceAccountToken: false",
		"service account token automounting disabled",
		"## Network Policy",
		"networkPolicy:",
		"guardianwaf-ingress",
		"kubernetes.io/metadata.name: ingress-nginx",
		"./scripts/validate-k8s.sh",
		"./scripts/validate-helm.sh",
		"./scripts/kind-smoke.sh",
	}
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Fatalf("%s missing Kubernetes/Helm deployment guidance %q", path, want)
		}
	}
}

func TestValidateHelmPrefersCurrentSourceOverStaleDistBinary(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "validate-helm.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	sourceCheck := `if command -v go >/dev/null 2>&1 && [ -d "${ROOT_DIR}/internal/dashboard/dist" ]; then`
	distCheck := `if [ -x "${ROOT_DIR}/dist/guardianwaf-linux-amd64" ]; then`
	sourceIndex := strings.Index(content, sourceCheck)
	distIndex := strings.Index(content, distCheck)
	if sourceIndex < 0 || distIndex < 0 {
		t.Fatalf("%s must retain both current-source and dist validator branches", path)
	}
	if sourceIndex > distIndex {
		t.Fatalf("%s must prefer current source over a possibly stale dist validator", path)
	}
}

func TestReadmeLinksKubernetesHelmDeploymentGuide(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "docs/kubernetes-helm.md") {
		t.Fatal("README.md must link the Kubernetes and Helm deployment guide")
	}
}
