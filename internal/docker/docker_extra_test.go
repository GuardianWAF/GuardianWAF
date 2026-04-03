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

// --- NewClient ---

func TestNewClient_Default(t *testing.T) {
	c := NewClient("")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.hostFlag != "" {
		t.Errorf("expected empty hostFlag, got %q", c.hostFlag)
	}
}

func TestNewClient_WithSocket(t *testing.T) {
	c := NewClient("/var/run/docker.sock")
	if c.socketPath != "/var/run/docker.sock" {
		t.Errorf("expected socket path, got %q", c.socketPath)
	}
}

// --- NewHTTPClient ---

func TestNewHTTPClient(t *testing.T) {
	client := NewHTTPClient("/var/run/docker.sock")
	if client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.Timeout)
	}
}

// --- Ping (requires Docker) ---

func TestClient_Ping_NoDocker(t *testing.T) {
	c := NewClient("")
	// This will fail if Docker is not available, which is expected in CI
	err := c.Ping()
	if err == nil {
		t.Log("Docker is available — ping succeeded")
	} else {
		t.Logf("Docker not available (expected in CI): %v", err)
	}
}

// --- ListContainers (requires Docker) ---

func TestClient_ListContainers_NoDocker(t *testing.T) {
	c := NewClient("")
	_, err := c.ListContainers("gwaf")
	if err == nil {
		t.Log("Docker is available — list succeeded")
	} else {
		t.Logf("Docker not available (expected in CI): %v", err)
	}
}

// --- InspectContainer (requires Docker) ---

func TestClient_InspectContainer_NoDocker(t *testing.T) {
	c := NewClient("")
	_, err := c.InspectContainer("nonexistent123")
	if err == nil {
		t.Log("Unexpected success for nonexistent container")
	} else {
		t.Logf("Expected error (Docker not available or container missing): %v", err)
	}
}

// --- StreamEvents (requires Docker) ---

func TestClient_StreamEvents_Cancel(t *testing.T) {
	c := NewClient("")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ch := make(chan Event, 1)
	err := c.StreamEvents(ctx, "gwaf", ch)
	// Should return quickly since context is cancelled
	_ = err
}

// --- Watcher lifecycle ---

func TestWatcher_StartStop(t *testing.T) {
	c := NewClient("")
	w := NewWatcher(c, "gwaf", "bridge", 100*time.Millisecond)

	onChangeCalled := false
	w.SetOnChange(func() { onChangeCalled = true })
	w.SetLogger(func(level, msg string) {})

	// Start will call sync() which calls ListContainers — may fail without Docker
	w.Start()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Check Services() works
	services := w.Services()
	_ = services

	count := w.ServiceCount()
	_ = count

	w.Stop()

	_ = onChangeCalled // may or may not be called depending on Docker availability
}

// --- Watcher sync ---

func TestWatcher_Sync_NoChange(t *testing.T) {
	// When Docker is unavailable, sync returns false
	c := NewClient("")
	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	changed := w.sync()
	if changed {
		t.Error("expected no change when Docker unavailable")
	}
}

// --- Watcher notifyChange ---

func TestWatcher_NotifyChange_NoCallback(t *testing.T) {
	w := NewWatcher(NewClient(""), "gwaf", "bridge", time.Second)
	// Should not panic with nil onChange
	w.notifyChange()
}

// --- BuildConfig with health check interval ---

func TestBuildConfig_WithHealthCheck(t *testing.T) {
	services := []DiscoveredService{
		{
			ContainerID: "abc", ContainerName: "api",
			Host: "api.com", Path: "/", Port: 8080,
			Weight: 1, IPAddress: "172.17.0.2", UpstreamName: "api",
			HealthPath: "/health", HealthInterval: 5 * time.Second,
		},
	}
	staticCfg := config.DefaultConfig()
	merged := BuildConfig(services, staticCfg)

	for _, u := range merged.Upstreams {
		if u.Name == "api" {
			if !u.HealthCheck.Enabled {
				t.Error("expected health check enabled")
			}
			if u.HealthCheck.Interval != 5*time.Second {
				t.Errorf("expected 5s interval, got %v", u.HealthCheck.Interval)
			}
			return
		}
	}
	t.Error("api upstream not found")
}

// --- BuildConfig with strip_prefix label ---

func TestBuildConfig_StripPrefix(t *testing.T) {
	services := []DiscoveredService{
		{
			ContainerID: "abc", ContainerName: "api",
			Host: "api.com", Path: "/api", Port: 8080,
			Weight: 1, IPAddress: "172.17.0.2", UpstreamName: "api",
			StripPrefix: true,
		},
	}
	staticCfg := config.DefaultConfig()
	merged := BuildConfig(services, staticCfg)

	for _, r := range merged.VirtualHosts[0].Routes {
		if r.Path == "/api" && !r.StripPrefix {
			t.Error("expected StripPrefix to be true")
		}
	}
}

// --- DiscoveredService with TLS ---

func TestDiscoveredService_TLS(t *testing.T) {
	svc := DiscoveredService{IPAddress: "172.17.0.2", Port: 443, TLS: "auto"}
	if svc.TargetURL() != "https://172.17.0.2:443" {
		t.Errorf("expected https URL, got %q", svc.TargetURL())
	}

	svc.TLS = ""
	if svc.TargetURL() != "http://172.17.0.2:443" {
		t.Errorf("expected http URL, got %q", svc.TargetURL())
	}
}

// --- Container JSON parsing via HTTP ---

func TestContainerJSON_Parsing(t *testing.T) {
	containers := []Container{
		{
			ID: "abc123", Names: []string{"/test"}, State: "running",
			Labels: map[string]string{"gwaf.enable": "true", "gwaf.host": "test.com"},
			Ports:  []ContainerPort{{PrivatePort: 8080, Type: "tcp"}},
		},
	}
	containers[0].NetworkSettings.Networks = map[string]NetworkInfo{
		"bridge": {IPAddress: "172.17.0.2", Gateway: "172.17.0.1", NetworkID: "net123"},
	}

	// Serialize and deserialize to verify JSON roundtrip
	data, err := json.Marshal(containers)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()

	var parsed []Container
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if parsed[0].ID != "abc123" {
		t.Errorf("expected ID abc123, got %q", parsed[0].ID)
	}
	if parsed[0].NetworkSettings.Networks["bridge"].Gateway != "172.17.0.1" {
		t.Errorf("expected gateway, got %v", parsed[0].NetworkSettings.Networks["bridge"])
	}
}

// --- Event JSON parsing ---

func TestEventJSON_Parsing(t *testing.T) {
	eventJSON := `{"Type":"container","Action":"start","Actor":{"ID":"abc123","Attributes":{"name":"myapp"}},"time":1700000000}`
	var event Event
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if event.Action != "start" {
		t.Errorf("expected start, got %q", event.Action)
	}
	if event.Actor.ID != "abc123" {
		t.Errorf("expected abc123, got %q", event.Actor.ID)
	}
	if event.Actor.Attributes["name"] != "myapp" {
		t.Errorf("expected myapp, got %q", event.Actor.Attributes["name"])
	}
}

// --- ContainerDetail JSON parsing ---

func TestContainerDetailJSON_Parsing(t *testing.T) {
	detailJSON := `[{
		"Id": "def456",
		"Name": "/my-api",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "api.com"},
			"ExposedPorts": {"8080/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
			"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`

	var details []ContainerDetail
	if err := json.Unmarshal([]byte(detailJSON), &details); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(details))
	}
	d := details[0]
	if d.ID != "def456" {
		t.Errorf("expected def456, got %q", d.ID)
	}
	if d.Name != "/my-api" {
		t.Errorf("expected /my-api, got %q", d.Name)
	}
	if !d.State.Running {
		t.Error("expected Running=true")
	}
	if d.NetworkSettings.Networks["bridge"].IPAddress != "172.17.0.5" {
		t.Errorf("unexpected IP: %v", d.NetworkSettings.Networks["bridge"])
	}
	if len(d.NetworkSettings.Ports["8080/tcp"]) != 1 {
		t.Errorf("unexpected ports: %v", d.NetworkSettings.Ports)
	}
}

// --- PortBinding parsing ---

func TestPortBinding_Parsing(t *testing.T) {
	pbJSON := `{"HostIp": "0.0.0.0", "HostPort": "9090"}`
	var pb PortBinding
	if err := json.Unmarshal([]byte(pbJSON), &pb); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if pb.HostIP != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %q", pb.HostIP)
	}
	if pb.HostPort != "9090" {
		t.Errorf("expected 9090, got %q", pb.HostPort)
	}
}

// --- handleEvent: die ---

func TestWatcher_HandleEvent_Die(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	w.services["xyz"] = &DiscoveredService{ContainerID: "xyz", IPAddress: "10.0.0.1", Port: 80}

	changed := false
	w.SetOnChange(func() { changed = true })

	evt := Event{Action: "die"}
	evt.Actor.ID = "xyz"
	evt.Actor.Attributes = map[string]string{"name": "svc"}
	w.handleEvent(evt)

	if !changed {
		t.Error("expected onChange on die event")
	}
	if w.ServiceCount() != 0 {
		t.Error("expected 0 services after die event")
	}
}

// --- handleEvent: start (with Docker client, sync may fail) ---

func TestWatcher_HandleEvent_Start_WithClient(t *testing.T) {
	c := NewClient("")
	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	changed := false
	w.SetOnChange(func() { changed = true })

	evt := Event{Action: "start"}
	evt.Actor.ID = "abc123"
	evt.Actor.Attributes = map[string]string{"name": "test-app"}
	w.handleEvent(evt)

	// sync fails without Docker but onChange should still be called
	if !changed {
		t.Error("expected onChange to be called on start event")
	}
}

// --- pollLoop stops on stopCh ---

func TestWatcher_PollLoop_StopsOnChannel(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 10*time.Millisecond)
	w.SetLogger(func(_, _ string) {})

	// Close stopCh to unblock pollLoop immediately
	close(w.stopCh)

	done := make(chan struct{})
	go func() {
		w.pollLoop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pollLoop should return when stopCh is closed")
	}
}

// --- Event JSON with all fields ---

func TestEventJSON_AllActions(t *testing.T) {
	for _, action := range []string{"start", "stop", "die", "destroy", "restart", "pause"} {
		eventJSON := `{"Type":"container","Action":"` + action + `","Actor":{"ID":"abc","Attributes":{"name":"test"}},"time":1700000000}`
		var event Event
		if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
			t.Fatalf("unmarshal %s: %v", action, err)
		}
		if event.Action != action {
			t.Errorf("expected %s, got %q", action, event.Action)
		}
	}
}
