package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestParseLabels_Full(t *testing.T) {
	labels := map[string]string{
		"gwaf.enable":          "true",
		"gwaf.host":            "api.example.com",
		"gwaf.path":            "/api",
		"gwaf.port":            "8088",
		"gwaf.weight":          "3",
		"gwaf.strip_prefix":    "true",
		"gwaf.lb":              "weighted",
		"gwaf.upstream":        "api-pool",
		"gwaf.tls":             "auto",
		"gwaf.health.path":     "/healthz",
		"gwaf.health.interval": "15s",
	}

	svc := ParseLabels(labels, "gwaf")
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Host != "api.example.com" {
		t.Errorf("host: got %q", svc.Host)
	}
	if svc.Path != "/api" {
		t.Errorf("path: got %q", svc.Path)
	}
	if svc.Port != 8088 {
		t.Errorf("port: got %d", svc.Port)
	}
	if svc.Weight != 3 {
		t.Errorf("weight: got %d", svc.Weight)
	}
	if !svc.StripPrefix {
		t.Error("strip_prefix should be true")
	}
	if svc.LBStrategy != "weighted" {
		t.Errorf("lb: got %q", svc.LBStrategy)
	}
	if svc.UpstreamName != "api-pool" {
		t.Errorf("upstream: got %q", svc.UpstreamName)
	}
	if svc.TLS != "auto" {
		t.Errorf("tls: got %q", svc.TLS)
	}
	if svc.HealthPath != "/healthz" {
		t.Errorf("health path: got %q", svc.HealthPath)
	}
	if svc.HealthInterval != 15*time.Second {
		t.Errorf("health interval: got %v", svc.HealthInterval)
	}
}

func TestParseLabels_Minimal(t *testing.T) {
	labels := map[string]string{
		"gwaf.enable": "true",
		"gwaf.host":   "web.example.com",
	}

	svc := ParseLabels(labels, "gwaf")
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Path != "/" {
		t.Errorf("default path should be /, got %q", svc.Path)
	}
	if svc.Weight != 1 {
		t.Errorf("default weight should be 1, got %d", svc.Weight)
	}
	if svc.LBStrategy != "round_robin" {
		t.Errorf("default LB should be round_robin, got %q", svc.LBStrategy)
	}
}

func TestParseLabels_Disabled(t *testing.T) {
	labels := map[string]string{
		"gwaf.enable": "false",
		"gwaf.host":   "disabled.example.com",
	}
	svc := ParseLabels(labels, "gwaf")
	if svc != nil {
		t.Error("expected nil for disabled container")
	}
}

func TestParseLabels_CustomPrefix(t *testing.T) {
	labels := map[string]string{
		"myapp.enable": "true",
		"myapp.host":   "custom.example.com",
	}
	svc := ParseLabels(labels, "myapp")
	if svc == nil {
		t.Fatal("expected non-nil service with custom prefix")
	}
	if svc.Host != "custom.example.com" {
		t.Errorf("host: got %q", svc.Host)
	}
}

func TestDiscoveredService_TargetURL(t *testing.T) {
	svc := &DiscoveredService{IPAddress: "172.17.0.2", Port: 8088}
	if svc.TargetURL() != "http://172.17.0.2:8088" {
		t.Errorf("got %q", svc.TargetURL())
	}

	svc.TLS = "auto"
	if svc.TargetURL() != "https://172.17.0.2:8088" {
		t.Errorf("got %q", svc.TargetURL())
	}
}

func TestDiscoverFromContainers(t *testing.T) {
	containers := []Container{
		{
			ID:    "abc123def456",
			Names: []string{"/api-server"},
			Image: "my-api:latest",
			State: "running",
			Labels: map[string]string{
				"gwaf.enable":   "true",
				"gwaf.host":     "api.example.com",
				"gwaf.port":     "3000",
				"gwaf.upstream": "api-pool",
			},
			Ports: []ContainerPort{{PrivatePort: 3000, Type: "tcp"}},
		},
		{
			ID:    "xyz789abc012",
			Names: []string{"/web-frontend"},
			Image: "my-web:latest",
			State: "running",
			Labels: map[string]string{
				"gwaf.enable": "true",
				"gwaf.host":   "www.example.com",
			},
			Ports: []ContainerPort{{PrivatePort: 80, Type: "tcp"}},
		},
	}

	// Set network IPs
	containers[0].NetworkSettings.Networks = map[string]NetworkInfo{
		"bridge": {IPAddress: "172.17.0.2"},
	}
	containers[1].NetworkSettings.Networks = map[string]NetworkInfo{
		"bridge": {IPAddress: "172.17.0.3"},
	}

	services := DiscoverFromContainers(containers, "gwaf", "bridge")
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	api := services[0]
	if api.Host != "api.example.com" {
		t.Errorf("api host: got %q", api.Host)
	}
	if api.UpstreamName != "api-pool" {
		t.Errorf("api upstream: got %q", api.UpstreamName)
	}
	if api.TargetURL() != "http://172.17.0.2:3000" {
		t.Errorf("api target: got %q", api.TargetURL())
	}

	web := services[1]
	if web.UpstreamName != "web-frontend" {
		t.Errorf("web upstream should default to container name, got %q", web.UpstreamName)
	}
}

func TestBuildConfig(t *testing.T) {
	staticCfg := config.DefaultConfig()
	staticCfg.Upstreams = []config.UpstreamConfig{
		{Name: "static-backend", Targets: []config.TargetConfig{{URL: "http://localhost:3000", Weight: 1}}},
	}
	staticCfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "static-backend"},
	}

	services := []DiscoveredService{
		{
			ContainerID: "abc123", ContainerName: "api",
			Host: "api.example.com", Path: "/api", Port: 8088,
			Weight: 1, LBStrategy: "round_robin", UpstreamName: "api-pool",
			IPAddress: "172.17.0.2", HealthPath: "/health", HealthInterval: 10 * time.Second,
		},
		{
			ContainerID: "def456", ContainerName: "api2",
			Host: "api.example.com", Path: "/api", Port: 8088,
			Weight: 2, LBStrategy: "round_robin", UpstreamName: "api-pool",
			IPAddress: "172.17.0.3",
		},
	}

	merged := BuildConfig(services, staticCfg)

	// Static upstream should be preserved
	found := false
	for _, u := range merged.Upstreams {
		if u.Name == "static-backend" {
			found = true
		}
	}
	if !found {
		t.Error("static upstream should be preserved")
	}

	// api-pool should be added with 2 targets
	for _, u := range merged.Upstreams {
		if u.Name == "api-pool" {
			if len(u.Targets) != 2 {
				t.Errorf("api-pool should have 2 targets, got %d", len(u.Targets))
			}
			if !u.HealthCheck.Enabled {
				t.Error("health check should be enabled")
			}
			return
		}
	}
	t.Error("api-pool upstream not found in merged config")
}

func TestServiceSummary(t *testing.T) {
	services := []DiscoveredService{
		{ContainerID: "abc123def456", ContainerName: "api", Host: "api.example.com",
			Path: "/", Port: 8088, Weight: 1, IPAddress: "172.17.0.2", UpstreamName: "api"},
	}
	summaries := ServiceSummary(services)
	if len(summaries) != 1 {
		t.Fatalf("expected 1, got %d", len(summaries))
	}
	if summaries[0]["container_name"] != "api" {
		t.Errorf("got %v", summaries[0])
	}
}

func TestContainerName(t *testing.T) {
	c := Container{ID: "abcdef123456", Names: []string{"/my-app"}}
	if ContainerName(c) != "my-app" {
		t.Errorf("got %q", ContainerName(c))
	}

	c2 := Container{ID: "abcdef123456"}
	if ContainerName(c2) != "abcdef123456" {
		t.Errorf("got %q", ContainerName(c2))
	}
}

func TestClient_ListContainers_MockServer(t *testing.T) {
	// Mock Docker API via HTTP (not Unix socket, but tests the parsing)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containers := []Container{
			{
				ID: "test123", Names: []string{"/test-app"}, State: "running",
				Labels: map[string]string{"gwaf.enable": "true", "gwaf.host": "test.com"},
				Ports:  []ContainerPort{{PrivatePort: 8088, Type: "tcp"}},
			},
		}
		containers[0].NetworkSettings.Networks = map[string]NetworkInfo{
			"bridge": {IPAddress: "172.17.0.5"},
		}
		_ = json.NewEncoder(w).Encode(containers)
	}))
	defer srv.Close()

	// Can't easily test Unix socket client with httptest, but we can test the parsing
	// by calling the mock server directly
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mock request failed: %v", err)
	}
	defer resp.Body.Close()

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	services := DiscoverFromContainers(containers, "gwaf", "bridge")
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Host != "test.com" {
		t.Errorf("host: got %q", services[0].Host)
	}
}

func TestAutoDetectPort(t *testing.T) {
	c := Container{
		Ports: []ContainerPort{
			{PrivatePort: 8088, Type: "tcp"},
			{PrivatePort: 443, Type: "tcp"},
		},
	}
	if autoDetectPort(c) != 8088 {
		t.Errorf("expected 8088, got %d", autoDetectPort(c))
	}

	// No ports → default 80
	c2 := Container{}
	if autoDetectPort(c2) != 80 {
		t.Errorf("expected 80, got %d", autoDetectPort(c2))
	}
}
