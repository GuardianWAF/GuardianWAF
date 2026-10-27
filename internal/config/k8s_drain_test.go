package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every reference workload must delay shutdown with a preStop sleep:
// serve stops accepting on SIGTERM, and without the delay a rolling update
// refuses connections until kube-proxy and the ingress drop the pod. The
// StatefulSets (Helm and the cluster manifest) used to lack it.
func TestKubernetesWorkloadsDrainBeforeStopping(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, fixture := range []string{
		"contrib/k8s/deployment.yaml",
		"contrib/k8s/cluster-statefulset.yaml",
		"contrib/k8s/helm/templates/deployment.yaml",
		"contrib/k8s/helm/templates/statefulset.yaml",
	} {
		raw, err := os.ReadFile(filepath.Join(root, fixture))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", fixture, err)
		}
		text := string(raw)
		if !strings.Contains(text, "preStop:") || !strings.Contains(text, `"sleep 5"`) {
			t.Errorf("%s has no preStop sleep before shutdown", fixture)
		}
		if !strings.Contains(text, "terminationGracePeriodSeconds: 45") {
			t.Errorf("%s must keep terminationGracePeriodSeconds above the 30s drain plus the preStop delay", fixture)
		}
	}
}

// The multi-document cluster manifest is outside the structured image-version
// fixtures, and had drifted to 0.5.0 while every other manifest shipped 0.6.0.
func TestClusterStatefulSetImageMatchesReleaseVersion(t *testing.T) {
	root := filepath.Join("..", "..")
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "contrib/k8s/cluster-statefulset.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "image: ghcr.io/guardianwaf/guardianwaf:" + strings.TrimSpace(string(version))
	if !strings.Contains(string(raw), want) {
		t.Fatalf("contrib/k8s/cluster-statefulset.yaml does not use %q", want)
	}
}
