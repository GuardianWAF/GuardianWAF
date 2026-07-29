package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployableGuardianWAFImagesMatchReleaseVersion(t *testing.T) {
	root := filepath.Join("..", "..")
	versionData, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatalf("ReadFile(VERSION) error = %v", err)
	}
	version := strings.TrimSpace(string(versionData))
	if version == "" {
		t.Fatal("VERSION is empty")
	}
	wantImage := "ghcr.io/guardianwaf/guardianwaf:" + version

	composeFixtures := []string{
		"docker-compose.yml",
		"examples/sidecar/docker-compose.yml",
	}
	for _, fixture := range composeFixtures {
		t.Run(fixture, func(t *testing.T) {
			doc := parseYAMLFixture(t, filepath.Join(root, fixture))
			image := doc.GetPath("services", "guardianwaf", "image")
			if image == nil {
				t.Fatal("services.guardianwaf.image not found")
			}
			if got := image.String(); got != wantImage {
				t.Fatalf("services.guardianwaf.image = %q, want %q", got, wantImage)
			}
		})
	}

	workloadFixtures := []string{
		"contrib/k8s/deployment.yaml",
		"examples/kubernetes/deployment.yaml",
		"examples/kubernetes/sidecar-deployment.yaml",
	}
	for _, fixture := range workloadFixtures {
		t.Run(fixture, func(t *testing.T) {
			doc := parseKubernetesWorkloadHardeningFixture(t, filepath.Join(root, fixture))
			containers := doc.GetPath("spec", "template", "spec", "containers")
			if containers == nil || containers.Kind != SequenceNode {
				t.Fatal("spec.template.spec.containers is not a sequence")
			}
			for _, container := range containers.Items {
				if container.Get("name").String() != "guardianwaf" {
					continue
				}
				if got := container.Get("image").String(); got != wantImage {
					t.Fatalf("guardianwaf image = %q, want %q", got, wantImage)
				}
				return
			}
			t.Fatal("guardianwaf container not found")
		})
	}

	chart := parseYAMLFixture(t, filepath.Join(root, "contrib/k8s/helm/Chart.yaml"))
	if got := chart.Get("version").String(); got != version {
		t.Fatalf("Helm chart version = %q, want %q", got, version)
	}
	if got := chart.Get("appVersion").String(); got != version {
		t.Fatalf("Helm appVersion = %q, want %q", got, version)
	}
}

func TestComposeGuardianWAFServiceHardenedForReadOnlyRoot(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := parseYAMLFixture(t, filepath.Join(root, "docker-compose.yml"))
	service := doc.GetPath("services", "guardianwaf")
	if service == nil {
		t.Fatal("services.guardianwaf not found")
	}

	assertBoolNode(t, service.Get("read_only"), true, "services.guardianwaf.read_only")
	assertSequenceContainsScalar(t, service.Get("security_opt"), "no-new-privileges:true", "services.guardianwaf.security_opt")
	assertComposeMount(t, service.Get("volumes"), "/etc/guardianwaf/guardianwaf.yaml", true)
	assertComposeMount(t, service.Get("volumes"), "/var/lib/guardianwaf", false)
	assertComposeMount(t, service.Get("volumes"), "/var/log/guardianwaf", false)
}

func TestKubernetesGuardianWAFWorkloadsHardenedForReadOnlyRoot(t *testing.T) {
	root := filepath.Join("..", "..")
	fixtures := []string{
		"examples/kubernetes/deployment.yaml",
		"examples/kubernetes/sidecar-deployment.yaml",
		"contrib/k8s/deployment.yaml",
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			doc := parseKubernetesWorkloadHardeningFixture(t, filepath.Join(root, fixture))
			podSpec := doc.GetPath("spec", "template", "spec")
			if podSpec == nil {
				t.Fatal("spec.template.spec not found")
			}
			podSecurity := podSpec.Get("securityContext")
			assertBoolNode(t, podSpec.Get("automountServiceAccountToken"), false, "pod automountServiceAccountToken")
			assertIntNode(t, podSecurity.Get("fsGroup"), 1000, "pod securityContext.fsGroup")

			containers := podSpec.Get("containers")
			if containers == nil || containers.Kind != SequenceNode {
				t.Fatal("spec.template.spec.containers is not a sequence")
			}
			checked := 0
			for _, container := range containers.Items {
				if container.Get("name").String() != "guardianwaf" {
					continue
				}
				checked++
				assertGuardianWAFContainerHardened(t, podSecurity, container)
			}
			if checked == 0 {
				t.Fatal("guardianwaf container not found")
			}
		})
	}
}

func TestHelmDefaultsHardenGuardianWAFContainerForReadOnlyRoot(t *testing.T) {
	root := filepath.Join("..", "..")
	values := parseYAMLFixture(t, filepath.Join(root, "contrib/k8s/helm/values.yaml"))

	security := values.Get("securityContext")
	assertBoolNode(t, security.Get("allowPrivilegeEscalation"), false, "securityContext.allowPrivilegeEscalation")
	assertBoolNode(t, security.Get("readOnlyRootFilesystem"), true, "securityContext.readOnlyRootFilesystem")
	assertBoolNode(t, security.Get("runAsNonRoot"), true, "securityContext.runAsNonRoot")
	assertIntNode(t, security.Get("runAsUser"), 1000, "securityContext.runAsUser")
	assertIntNode(t, security.Get("runAsGroup"), 1000, "securityContext.runAsGroup")
	assertSequenceContainsScalar(t, security.GetPath("capabilities", "drop"), "ALL", "securityContext.capabilities.drop")

	podSecurity := values.Get("podSecurityContext")
	assertIntNode(t, podSecurity.Get("fsGroup"), 1000, "podSecurityContext.fsGroup")
	assertBoolNode(t, values.GetPath("serviceAccount", "automountToken"), false, "serviceAccount.automountToken")

	template, err := os.ReadFile(filepath.Join(root, "contrib/k8s/helm/templates/deployment.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	renderSource := string(template)
	for _, want := range []string{
		"mountPath: /etc/guardianwaf",
		"readOnly: true",
		"mountPath: /var/cache/guardianwaf",
		"mountPath: /var/lib/guardianwaf",
		"mountPath: /var/log/guardianwaf",
		"subPath: logs",
		"automountServiceAccountToken: {{ .Values.serviceAccount.automountToken }}",
		"toYaml .Values.securityContext",
		"toYaml .Values.podSecurityContext",
	} {
		if !strings.Contains(renderSource, want) {
			t.Fatalf("Helm deployment template missing %q", want)
		}
	}
}

func TestKubernetesNetworkPolicyFixturesConstrainGuardianWAFIngress(t *testing.T) {
	root := filepath.Join("..", "..")
	staticPolicy, err := os.ReadFile(filepath.Join(root, "contrib/k8s/networkpolicy.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	staticSource := string(staticPolicy)
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: guardianwaf-ingress",
		"podSelector:",
		"app: guardianwaf",
		"policyTypes:",
		"- Ingress",
		"kubernetes.io/metadata.name: ingress-nginx",
		"port: 8088",
		"port: 9443",
	} {
		if !strings.Contains(staticSource, want) {
			t.Fatalf("contrib/k8s/networkpolicy.yaml missing %q", want)
		}
	}

	values := parseYAMLFixture(t, filepath.Join(root, "contrib/k8s/helm/values.yaml"))
	assertBoolNode(t, values.GetPath("networkPolicy", "enabled"), false, "networkPolicy.enabled")

	template, err := os.ReadFile(filepath.Join(root, "contrib/k8s/helm/templates/networkpolicy.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	templateSource := string(template)
	for _, want := range []string{
		"{{- if .Values.networkPolicy.enabled }}",
		"kind: NetworkPolicy",
		"include \"guardianwaf.selectorLabels\"",
		"toYaml .Values.networkPolicy.ingress.from",
		"toYaml .Values.networkPolicy.ingress.ports",
	} {
		if !strings.Contains(templateSource, want) {
			t.Fatalf("Helm NetworkPolicy template missing %q", want)
		}
	}
}

func assertGuardianWAFContainerHardened(t *testing.T, podSecurity, container *Node) {
	t.Helper()
	security := container.Get("securityContext")
	if security == nil {
		t.Fatal("guardianwaf securityContext not found")
	}

	assertBoolNode(t, security.Get("allowPrivilegeEscalation"), false, "guardianwaf.securityContext.allowPrivilegeEscalation")
	assertBoolNode(t, security.Get("readOnlyRootFilesystem"), true, "guardianwaf.securityContext.readOnlyRootFilesystem")
	assertBoolAtEitherScope(t, podSecurity, security, "runAsNonRoot", true)
	assertIntAtEitherScope(t, podSecurity, security, "runAsUser", 1000)
	assertIntAtEitherScope(t, podSecurity, security, "runAsGroup", 1000)
	assertSequenceContainsScalar(t, security.GetPath("capabilities", "drop"), "ALL", "guardianwaf.securityContext.capabilities.drop")

	mounts := container.Get("volumeMounts")
	assertKubernetesMount(t, mounts, "/var/lib/guardianwaf", false)
	assertKubernetesMount(t, mounts, "/var/log/guardianwaf", false)
	if hasKubernetesMount(mounts, "/etc/guardianwaf") {
		assertKubernetesMount(t, mounts, "/etc/guardianwaf", true)
	}
}

func parseYAMLFixture(t *testing.T, path string) *Node {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	node, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", path, err)
	}
	return node
}

func parseKubernetesWorkloadHardeningFixture(t *testing.T, path string) *Node {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	text := string(data)
	for _, marker := range []string{"\n      affinity:", "\n      nodeSelector:", "\n      tolerations:"} {
		if idx := strings.Index(text, marker); idx >= 0 {
			text = text[:idx] + "\n"
			break
		}
	}
	node, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", path, err)
	}
	return node
}

func assertBoolAtEitherScope(t *testing.T, podSecurity, containerSecurity *Node, key string, want bool) {
	t.Helper()
	if node := containerSecurity.Get(key); node != nil {
		assertBoolNode(t, node, want, "guardianwaf.securityContext."+key)
		return
	}
	assertBoolNode(t, podSecurity.Get(key), want, "pod securityContext."+key)
}

func assertIntAtEitherScope(t *testing.T, podSecurity, containerSecurity *Node, key string, want int) {
	t.Helper()
	if node := containerSecurity.Get(key); node != nil {
		assertIntNode(t, node, want, "guardianwaf.securityContext."+key)
		return
	}
	assertIntNode(t, podSecurity.Get(key), want, "pod securityContext."+key)
}

func assertBoolNode(t *testing.T, node *Node, want bool, label string) {
	t.Helper()
	if node == nil {
		t.Fatalf("%s not found", label)
	}
	got, err := node.Bool()
	if err != nil {
		t.Fatalf("%s: Bool() error = %v", label, err)
	}
	if got != want {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}

func assertIntNode(t *testing.T, node *Node, want int, label string) {
	t.Helper()
	if node == nil {
		t.Fatalf("%s not found", label)
	}
	got, err := node.Int()
	if err != nil {
		t.Fatalf("%s: Int() error = %v", label, err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", label, got, want)
	}
}

func assertSequenceContainsScalar(t *testing.T, node *Node, want, label string) {
	t.Helper()
	if node == nil || node.Kind != SequenceNode {
		t.Fatalf("%s is not a sequence", label)
	}
	for _, item := range node.Items {
		if item.String() == want {
			return
		}
	}
	t.Fatalf("%s does not contain %q", label, want)
}

func assertKubernetesMount(t *testing.T, mounts *Node, mountPath string, wantReadOnly bool) {
	t.Helper()
	mount := findKubernetesMount(mounts, mountPath)
	if mount == nil {
		t.Fatalf("volumeMount %s not found", mountPath)
	}
	readOnly := false
	if ro := mount.Get("readOnly"); ro != nil {
		var err error
		readOnly, err = ro.Bool()
		if err != nil {
			t.Fatalf("volumeMount %s readOnly: %v", mountPath, err)
		}
	}
	if readOnly != wantReadOnly {
		t.Fatalf("volumeMount %s readOnly = %v, want %v", mountPath, readOnly, wantReadOnly)
	}
}

func hasKubernetesMount(mounts *Node, mountPath string) bool {
	return findKubernetesMount(mounts, mountPath) != nil
}

func findKubernetesMount(mounts *Node, mountPath string) *Node {
	if mounts == nil || mounts.Kind != SequenceNode {
		return nil
	}
	for _, mount := range mounts.Items {
		if mount.Get("mountPath").String() == mountPath {
			return mount
		}
	}
	return nil
}

func assertComposeMount(t *testing.T, volumes *Node, containerPath string, wantReadOnly bool) {
	t.Helper()
	if volumes == nil || volumes.Kind != SequenceNode {
		t.Fatal("compose volumes is not a sequence")
	}
	for _, volume := range volumes.Items {
		parts := strings.Split(volume.String(), ":")
		if len(parts) < 2 || parts[1] != containerPath {
			continue
		}
		readOnly := len(parts) >= 3 && parts[2] == "ro"
		if readOnly != wantReadOnly {
			t.Fatalf("compose mount %s readOnly = %v, want %v", containerPath, readOnly, wantReadOnly)
		}
		return
	}
	t.Fatalf("compose mount %s not found", containerPath)
}
