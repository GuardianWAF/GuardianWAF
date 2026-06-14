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

func TestReadmeLinksKubernetesHelmDeploymentGuide(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "docs/kubernetes-helm.md") {
		t.Fatal("README.md must link the Kubernetes and Helm deployment guide")
	}
}
