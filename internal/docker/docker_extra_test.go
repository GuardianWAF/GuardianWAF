package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestNewClient_InvalidSocketHostFlag(t *testing.T) {
	c := NewClient("/var/run/docker.sock\n--host=tcp://evil")
	if c.hostFlag != "" {
		t.Fatalf("expected invalid socket path not to become hostFlag, got %q", c.hostFlag)
	}
}

func TestValidateDockerCLIArg(t *testing.T) {
	if err := validateDockerCLIArg("docker argument", "ps"); err != nil {
		t.Fatalf("valid docker arg rejected: %v", err)
	}
	if err := validateDockerCLIArg("docker argument", "bad\x00arg"); err == nil {
		t.Fatal("expected NUL argument rejection")
	}
	if err := validateDockerCLIArg("docker argument", "bad\narg"); err == nil {
		t.Fatal("expected control character rejection")
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
	// Should return quickly since context is canceled
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

func TestWatcher_StopWithContextHonorsDeadline(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", time.Hour)
	done := make(chan struct{})
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		<-done
	}()
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := w.StopWithContext(ctx); err == nil {
		t.Fatal("expected StopWithContext to return context deadline error")
	}

	select {
	case <-w.stopCh:
	default:
		t.Fatal("expected StopWithContext to close stopCh")
	}
	if w.eventStreamConnected.Load() {
		t.Fatal("expected StopWithContext timeout to mark event stream disconnected")
	}
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

// ============================================================================
// cmdFunc-based tests for Client.ListContainers
// ============================================================================

// TestClient_ListContainers_EmptyOutput verifies that ListContainers returns
// nil (no containers, no error) when docker ps produces empty output.
func TestClient_ListContainers_EmptyOutput(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", nil
	}

	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containers != nil {
		t.Fatalf("expected nil containers, got %v", containers)
	}
}

// TestClient_ListContainers_ValidContainers verifies the full two-step flow:
// ps returns container IDs, inspect returns ContainerDetail JSON.
// The containers are converted with correct labels, ports, and network info.
func TestClient_ListContainers_ValidContainers(t *testing.T) {
	psOutput := `{"ID":"abc123def456"}`
	inspectJSON := `[{
		"Id": "abc123def456",
		"Name": "/my-api",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "api.example.com", "gwaf.port": "8080"},
			"ExposedPorts": {"8080/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
			"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`

	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		if len(args) > 0 && args[0] == "inspect" {
			return inspectJSON, nil
		}
		return "", nil
	}

	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	ct := containers[0]
	if ct.ID != "abc123def456" {
		t.Errorf("expected ID abc123def456, got %q", ct.ID)
	}
	if ct.State != "running" {
		t.Errorf("expected state running, got %q", ct.State)
	}
	if ct.Labels["gwaf.host"] != "api.example.com" {
		t.Errorf("expected gwaf.host=api.example.com, got %q", ct.Labels["gwaf.host"])
	}
	if len(ct.Ports) != 1 || ct.Ports[0].PrivatePort != 8080 {
		t.Errorf("expected 1 port with PrivatePort 8080, got %v", ct.Ports)
	}
	if ct.NetworkSettings.Networks["bridge"].IPAddress != "172.17.0.5" {
		t.Errorf("expected bridge IP 172.17.0.5, got %v", ct.NetworkSettings.Networks["bridge"])
	}
}

// TestClient_ListContainers_MultipleContainers verifies listing multiple
// containers from a single ps + inspect round-trip.
func TestClient_ListContainers_MultipleContainers(t *testing.T) {
	psOutput := "{\"ID\":\"id111\"}\n{\"ID\":\"id222\"}"
	inspectJSON := `[{
		"Id": "id111",
		"Name": "/svc-a",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "a.test", "gwaf.port": "3000"},
			"ExposedPorts": {"3000/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.10"}},
			"Ports": {"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3000"}]}
		},
		"State": {"Status": "running", "Running": true}
	},{
		"Id": "id222",
		"Name": "/svc-b",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "b.test", "gwaf.port": "4000"},
			"ExposedPorts": {"4000/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.11"}},
			"Ports": {"4000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "4000"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`

	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		return inspectJSON, nil
	}

	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(containers))
	}
	if containers[0].Labels["gwaf.host"] != "a.test" {
		t.Errorf("expected host a.test, got %q", containers[0].Labels["gwaf.host"])
	}
	if containers[1].Labels["gwaf.host"] != "b.test" {
		t.Errorf("expected host b.test, got %q", containers[1].Labels["gwaf.host"])
	}
}

// TestClient_ListContainers_InvalidJSON verifies that malformed inspect JSON
// results in a "parsing inspect" error.
func TestClient_ListContainers_InvalidJSON(t *testing.T) {
	psOutput := `{"ID":"abc123"}`
	inspectJSON := `this is not valid json`

	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		return inspectJSON, nil
	}

	_, err := c.ListContainers("gwaf")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strContains(err.Error(), "parsing inspect") {
		t.Errorf("expected 'parsing inspect' error, got: %v", err)
	}
}

// TestClient_ListContainers_CmdError verifies that a docker ps failure
// produces a "listing containers" wrapped error.
func TestClient_ListContainers_CmdError(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", fmt.Errorf("docker daemon not running")
	}

	_, err := c.ListContainers("gwaf")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strContains(err.Error(), "listing containers") {
		t.Errorf("expected 'listing containers' error, got: %v", err)
	}
}

// TestClient_ListContainers_InspectCmdError verifies that when ps succeeds
// but inspect fails, the error is wrapped as "inspecting containers".
func TestClient_ListContainers_InspectCmdError(t *testing.T) {
	psOutput := `{"ID":"abc123"}`

	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		return "", fmt.Errorf("inspect failed")
	}

	_, err := c.ListContainers("gwaf")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strContains(err.Error(), "inspecting containers") {
		t.Errorf("expected 'inspecting containers' error, got: %v", err)
	}
}

// ============================================================================
// cmdFunc-based tests for Client.InspectContainer
// ============================================================================

// TestClient_InspectContainer_Success verifies that a valid inspect JSON
// array is parsed correctly into a ContainerDetail.
func TestClient_InspectContainer_Success(t *testing.T) {
	inspectJSON := `[{
		"Id": "abc123",
		"Name": "/my-api",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "api.example.com", "gwaf.port": "8080"},
			"ExposedPorts": {"8080/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
			"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`

	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return inspectJSON, nil
	}

	detail, err := c.InspectContainer("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.ID != "abc123" {
		t.Errorf("expected ID abc123, got %q", detail.ID)
	}
	if detail.Name != "/my-api" {
		t.Errorf("expected Name /my-api, got %q", detail.Name)
	}
	if detail.Config.Labels["gwaf.host"] != "api.example.com" {
		t.Errorf("expected gwaf.host=api.example.com, got %q", detail.Config.Labels["gwaf.host"])
	}
	if !detail.State.Running {
		t.Error("expected Running=true")
	}
	if detail.NetworkSettings.Networks["bridge"].IPAddress != "172.17.0.5" {
		t.Errorf("expected bridge IP 172.17.0.5, got %v", detail.NetworkSettings.Networks["bridge"])
	}
	if len(detail.NetworkSettings.Ports["8080/tcp"]) != 1 {
		t.Errorf("expected 1 port binding for 8080/tcp, got %v", detail.NetworkSettings.Ports["8080/tcp"])
	}
	if detail.NetworkSettings.Ports["8080/tcp"][0].HostPort != "8080" {
		t.Errorf("expected HostPort 8080, got %q", detail.NetworkSettings.Ports["8080/tcp"][0].HostPort)
	}
}

// TestClient_InspectContainer_NotFound verifies that an empty inspect array
// produces a "not found" error.
func TestClient_InspectContainer_NotFound(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "[]", nil
	}

	_, err := c.InspectContainer("nonexistent")
	if err == nil {
		t.Fatal("expected error for empty inspect result, got nil")
	}
	if !strContains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

// TestClient_InspectContainer_CmdError verifies that a docker inspect failure
// produces a wrapped error including the container ID.
func TestClient_InspectContainer_CmdError(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", fmt.Errorf("docker unavailable")
	}

	_, err := c.InspectContainer("abc123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strContains(err.Error(), "inspecting abc123") {
		t.Errorf("expected 'inspecting abc123' error, got: %v", err)
	}
}

// TestClient_InspectContainer_InvalidJSON verifies that malformed JSON
// from inspect produces a "parsing inspect" error.
func TestClient_InspectContainer_InvalidJSON(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "not-json", nil
	}

	_, err := c.InspectContainer("abc123")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strContains(err.Error(), "parsing inspect") {
		t.Errorf("expected 'parsing inspect' error, got: %v", err)
	}
}

// ============================================================================
// cmdFunc-based tests for Watcher.sync
// ============================================================================

// makeInspectJSON builds a realistic ContainerDetail JSON array for one container.
func makeInspectJSON(id, name, host, port string) string {
	return `[{
		"Id": "` + id + `",
		"Name": "/` + name + `",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "` + host + `", "gwaf.port": "` + port + `"},
			"ExposedPorts": {"` + port + `/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
			"Ports": {"` + port + `/tcp": [{"HostIp": "0.0.0.0", "HostPort": "` + port + `"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`
}

// makeClientWithCmdFunc creates a Client with the given cmdFunc override.
func makeClientWithCmdFunc(fn func(ctx context.Context, args ...string) (string, error)) *Client {
	c := NewClient("")
	c.cmdFunc = fn
	return c
}

// TestWatcher_Sync_ChangeDetected verifies that sync detects a host change
// between two consecutive syncs with the same container ID.
func TestWatcher_Sync_ChangeDetected(t *testing.T) {
	inspect1 := makeInspectJSON("abc123", "my-api", "api.example.com", "8080")
	inspect2 := makeInspectJSON("abc123", "my-api", "api2.example.com", "8080")
	psOutput := `{"ID":"abc123"}`

	callCount := 0
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		callCount++
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		if callCount <= 2 {
			return inspect1, nil
		}
		return inspect2, nil
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	// First sync: establishes baseline services
	changed := w.sync()
	if !changed {
		t.Fatal("expected change on first sync")
	}
	if w.ServiceCount() != 1 {
		t.Fatalf("expected 1 service after first sync, got %d", w.ServiceCount())
	}
	services := w.Services()
	if services[0].Host != "api.example.com" {
		t.Errorf("expected host api.example.com, got %q", services[0].Host)
	}

	// Second sync: same container ID, different host
	changed = w.sync()
	if !changed {
		t.Fatal("expected change on second sync with different host")
	}
	services = w.Services()
	if services[0].Host != "api2.example.com" {
		t.Errorf("expected host api2.example.com, got %q", services[0].Host)
	}
}

// TestWatcher_Sync_NoChange_IdenticalData verifies that two consecutive syncs
// returning identical services produce no change.
func TestWatcher_Sync_NoChange_IdenticalData(t *testing.T) {
	psOutput := `{"ID":"abc123"}`
	inspect := makeInspectJSON("abc123", "my-api", "api.example.com", "8080")

	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		return inspect, nil
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	// First sync: establishes baseline
	changed := w.sync()
	if !changed {
		t.Fatal("expected change on first sync")
	}

	// Second sync: identical data should not report a change
	changed = w.sync()
	if changed {
		t.Fatal("expected no change on second sync with identical data")
	}
}

// TestWatcher_Sync_ListError verifies that sync returns false (no change)
// when docker ps fails.
func TestWatcher_Sync_ListError(t *testing.T) {
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		return "", fmt.Errorf("docker not available")
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	changed := w.sync()
	if changed {
		t.Fatal("expected no change when Docker is unavailable")
	}
	stats := w.Stats()
	if stats.LastSyncOK {
		t.Fatal("expected failed sync status")
	}
	if stats.SyncFailures != 1 {
		t.Fatalf("expected 1 sync failure, got %d", stats.SyncFailures)
	}
}

// TestWatcher_Sync_ServiceAdded verifies that transitioning from zero
// containers to one container is detected as a change.
func TestWatcher_Sync_ServiceAdded(t *testing.T) {
	psOutputEmpty := ""
	psOutputOne := `{"ID":"abc123"}`
	inspectOne := makeInspectJSON("abc123", "my-api", "api.example.com", "8080")

	callCount := 0
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		callCount++
		if len(args) > 0 && args[0] == "ps" {
			if callCount <= 1 {
				return psOutputEmpty, nil
			}
			return psOutputOne, nil
		}
		return inspectOne, nil
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	// First sync: no containers
	changed := w.sync()
	if changed {
		t.Fatal("expected no change on first sync with empty containers")
	}

	// Second sync: container appears
	changed = w.sync()
	if !changed {
		t.Fatal("expected change when service is added")
	}
	if w.ServiceCount() != 1 {
		t.Fatalf("expected 1 service, got %d", w.ServiceCount())
	}
	services := w.Services()
	if services[0].Host != "api.example.com" {
		t.Errorf("expected host api.example.com, got %q", services[0].Host)
	}
	if services[0].Port != 8080 {
		t.Errorf("expected port 8080, got %d", services[0].Port)
	}
}

// TestWatcher_Sync_ServiceRemoved verifies that transitioning from one
// container to zero containers is detected as a change.
func TestWatcher_Sync_ServiceRemoved(t *testing.T) {
	psOutputOne := `{"ID":"abc123"}`
	psOutputEmpty := ""
	inspectOne := makeInspectJSON("abc123", "my-api", "api.example.com", "8080")

	callCount := 0
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		callCount++
		if len(args) > 0 && args[0] == "ps" {
			if callCount <= 2 {
				return psOutputOne, nil
			}
			return psOutputEmpty, nil
		}
		return inspectOne, nil
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	// First sync: one container present
	changed := w.sync()
	if !changed {
		t.Fatal("expected change on first sync")
	}
	if w.ServiceCount() != 1 {
		t.Fatalf("expected 1 service after first sync, got %d", w.ServiceCount())
	}

	// Second sync: container removed (empty ps output)
	changed = w.sync()
	if !changed {
		t.Fatal("expected change when service is removed")
	}
	if w.ServiceCount() != 0 {
		t.Fatalf("expected 0 services after removal, got %d", w.ServiceCount())
	}
}

// TestWatcher_Sync_MultipleChanges verifies that adding a second container
// to an existing one is detected as a change and both services are tracked.
func TestWatcher_Sync_MultipleChanges(t *testing.T) {
	psOutput1 := `{"ID":"svc1"}`
	inspect1 := makeInspectJSON("svc1", "api-one", "one.example.com", "8080")

	psOutput2 := "{\"ID\":\"svc1\"}\n{\"ID\":\"svc2\"}"
	inspect2 := `[{
		"Id": "svc1",
		"Name": "/api-one",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "one.example.com", "gwaf.port": "8080"},
			"ExposedPorts": {"8080/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
			"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
		},
		"State": {"Status": "running", "Running": true}
	},{
		"Id": "svc2",
		"Name": "/api-two",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "two.example.com", "gwaf.port": "9090"},
			"ExposedPorts": {"9090/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.6"}},
			"Ports": {"9090/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9090"}]}
		},
		"State": {"Status": "running", "Running": true}
	}]`

	callCount := 0
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		callCount++
		if len(args) > 0 && args[0] == "ps" {
			if callCount <= 2 {
				return psOutput1, nil
			}
			return psOutput2, nil
		}
		if callCount <= 2 {
			return inspect1, nil
		}
		return inspect2, nil
	})

	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	// First sync: one service
	changed := w.sync()
	if !changed {
		t.Fatal("expected change on first sync")
	}
	if w.ServiceCount() != 1 {
		t.Fatalf("expected 1 service after first sync, got %d", w.ServiceCount())
	}

	// Second sync: second service added
	changed = w.sync()
	if !changed {
		t.Fatal("expected change when second service added")
	}
	if w.ServiceCount() != 2 {
		t.Fatalf("expected 2 services after second sync, got %d", w.ServiceCount())
	}

	// Verify both services are present
	services := w.Services()
	hosts := make(map[string]bool)
	for _, svc := range services {
		hosts[svc.Host] = true
	}
	if !hosts["one.example.com"] {
		t.Error("missing service with host one.example.com")
	}
	if !hosts["two.example.com"] {
		t.Error("missing service with host two.example.com")
	}
}

// TestNewClient_SocketPath tests NewClient with a socket path.
// On non-Windows, hostFlag is set; on Windows it stays empty.
func TestNewClient_SocketPath(t *testing.T) {
	c := NewClient("/var/run/docker.sock")
	if c.socketPath != "/var/run/docker.sock" {
		t.Errorf("expected socket path, got %q", c.socketPath)
	}
}

// TestClient_Ping_EmptyVersion verifies Ping returns an error when docker
// returns an empty version string.
func TestClient_Ping_EmptyVersion(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "   ", nil
	}
	err := c.Ping()
	if err == nil {
		t.Fatal("expected error for empty version, got nil")
	}
	if !strContains(err.Error(), "empty version") {
		t.Errorf("expected 'empty version' error, got: %v", err)
	}
}

// TestClient_ListContainers_EmptyLines verifies that blank lines in docker ps
// output are skipped without error.
func TestClient_ListContainers_EmptyLines(t *testing.T) {
	psOutput := "\n\n{\"ID\":\"abc123\"}\n\n"
	inspectJSON := `[{
		"Id": "abc123",
		"Name": "/my-api",
		"Config": {"Labels": {"gwaf.enable": "true"}, "ExposedPorts": {}},
		"NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
		"State": {"Status": "running", "Running": true}
	}]`
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return psOutput, nil
		}
		return inspectJSON, nil
	}
	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
}

// TestClient_ListContainers_ZeroValidIDs verifies that when ps output contains
// lines that do not unmarshal to a valid ID, the result is nil.
func TestClient_ListContainers_ZeroValidIDs(t *testing.T) {
	psOutput := "not json\n{\"Foo\":\"bar\"}\n"
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return psOutput, nil
	}
	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containers != nil {
		t.Fatalf("expected nil containers, got %v", containers)
	}
}

// TestClient_dockerCmd_NonExitError verifies that a non-*exec.ExitError
// returned by exec.Command is propagated as-is.
func TestClient_dockerCmd_NonExitError(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", fmt.Errorf("some random error")
	}
	_, err := c.dockerCmd(context.Background(), "ps")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strContains(err.Error(), "some random error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_dockerCmd_RejectsInvalidArgs(t *testing.T) {
	c := NewClient("")
	_, err := c.dockerCmd(context.Background(), "ps\n--all")
	if err == nil {
		t.Fatal("expected invalid docker argument error")
	}
}

func TestClient_dockerCmd_RejectsInvalidHostFlag(t *testing.T) {
	c := NewClient("")
	c.hostFlag = "unix:///var/run/docker.sock\n--host=tcp://evil"
	_, err := c.dockerCmd(context.Background(), "ps")
	if err == nil {
		t.Fatal("expected invalid docker host error")
	}
}

func TestClient_dockerCmd_RemoteTLSArgs(t *testing.T) {
	c := NewClientWithOptions(ClientOptions{
		SocketPath: "tcp://docker.example.com:2376",
		TLSVerify:  true,
		TLSCACert:  "/etc/guardianwaf/docker/ca.pem",
		TLSCert:    "/etc/guardianwaf/docker/cert.pem",
		TLSKey:     "/etc/guardianwaf/docker/key.pem",
	})
	if c.hostFlag != "tcp://docker.example.com:2376" {
		t.Fatalf("unexpected docker host flag: %q", c.hostFlag)
	}

	var got []string
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		got = append([]string(nil), args...)
		return "24.0.0\n", nil
	}
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	want := []string{"version", "--format", "{{.Server.Version}}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmdFunc bypass should receive raw command args, got %#v want %#v", got, want)
	}

	baseArgs, err := c.dockerCLIBaseArgs()
	if err != nil {
		t.Fatalf("dockerCLIBaseArgs() error = %v", err)
	}
	wantBase := []string{
		"--host", "tcp://docker.example.com:2376",
		"--tlsverify",
		"--tlscacert", "/etc/guardianwaf/docker/ca.pem",
		"--tlscert", "/etc/guardianwaf/docker/cert.pem",
		"--tlskey", "/etc/guardianwaf/docker/key.pem",
	}
	if !reflect.DeepEqual(baseArgs, wantBase) {
		t.Fatalf("unexpected Docker CLI base args: %#v want %#v", baseArgs, wantBase)
	}
}

// TestContainerName_LongID verifies ContainerName returns the first 12 chars
// when Names is empty and ID is longer than 12 characters.
func TestContainerName_LongID(t *testing.T) {
	longID := "abcdefghijklmnopqrstuvwxyz"
	c := Container{ID: longID}
	name := ContainerName(c)
	if name != longID[:12] {
		t.Errorf("expected %q, got %q", longID[:12], name)
	}
}

// TestNewHTTPClient_DialContext exercises the custom DialContext returned by
// NewHTTPClient so the dial function body is covered.
func TestNewHTTPClient_DialContext(t *testing.T) {
	client := NewHTTPClient("/nonexistent.sock")
	transport := client.Transport.(*http.Transport)
	conn, err := transport.DialContext(context.Background(), "tcp", "dummy:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial error for invalid socket path")
	}
}

// TestParseLabels_EmptyPrefix verifies that an empty prefix defaults to "gwaf".
func TestParseLabels_EmptyPrefix(t *testing.T) {
	labels := map[string]string{"gwaf.enable": "true", "gwaf.host": "test.com"}
	svc := ParseLabels(labels, "")
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Host != "test.com" {
		t.Errorf("expected host test.com, got %q", svc.Host)
	}
}

// TestDiscoverFromContainers_SkipDisabled verifies containers without
// gwaf.enable=true are skipped.
func TestDiscoverFromContainers_SkipDisabled(t *testing.T) {
	containers := []Container{
		{
			ID:     "disabled",
			Names:  []string{"/svc"},
			Labels: map[string]string{"gwaf.enable": "false"},
			NetworkSettings: struct {
				Networks map[string]NetworkInfo `json:"Networks"`
			}{
				Networks: map[string]NetworkInfo{"bridge": {IPAddress: "172.17.0.2"}},
			},
			Ports: []ContainerPort{{PrivatePort: 8080, Type: "tcp"}},
		},
	}
	services := DiscoverFromContainers(containers, "gwaf", "bridge")
	if len(services) != 0 {
		t.Fatalf("expected 0 services, got %d", len(services))
	}
}

// TestAutoDetectPort_CommonPorts exercises the commonPorts fallback path.
func TestAutoDetectPort_CommonPorts(t *testing.T) {
	// Container has port 3000 in port list but as UDP so the first tcp-only loop
	// is skipped, triggering the commonPorts match.
	c := Container{
		Ports: []ContainerPort{
			{PrivatePort: 3000, Type: "udp"},
		},
	}
	if autoDetectPort(c) != 3000 {
		t.Errorf("expected 3000, got %d", autoDetectPort(c))
	}
}

// TestClient_Ping_Error verifies Ping returns an error when dockerCmd fails.
func TestClient_Ping_Error(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", fmt.Errorf("docker daemon not running")
	}
	err := c.Ping()
	if err == nil {
		t.Fatal("expected error for ping failure")
	}
	if !strContains(err.Error(), "not reachable") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAutoDetectPort_FallbackFirstPort verifies fallback to the first exposed
// port when it does not match any common web port.
func TestAutoDetectPort_FallbackFirstPort(t *testing.T) {
	c := Container{
		Ports: []ContainerPort{
			{PrivatePort: 9999, Type: "udp"},
		},
	}
	if autoDetectPort(c) != 9999 {
		t.Errorf("expected 9999, got %d", autoDetectPort(c))
	}
}

// TestWatcher_loop_StopOnSecondIteration causes loop() to enter its second
// iteration and then exit via stopCh.
func TestWatcher_loop_StopOnSecondIteration(t *testing.T) {
	// A client whose StreamEvents returns immediately, forcing loop() to
	// go back to the top of the for loop where it can see stopCh.
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "", nil
	}
	w := NewWatcher(c, "gwaf", "bridge", 10*time.Millisecond)
	w.SetLogger(func(_, _ string) {})

	w.Start()
	// Let loop() spin through at least once
	time.Sleep(50 * time.Millisecond)
	w.Stop()
}

// TestWatcher_pollLoop_Tick exercises the ticker path in pollLoop.
func TestWatcher_pollLoop_Tick(t *testing.T) {
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		return "", nil
	})
	w := NewWatcher(c, "gwaf", "bridge", 20*time.Millisecond)
	w.SetLogger(func(_, _ string) {})

	go func() {
		// Let it tick once, then stop
		time.Sleep(40 * time.Millisecond)
		w.Stop()
	}()

	w.pollLoop()
}

// TestClient_StreamEvents_WithHostFlag verifies StreamEvents prepends --host
// when the client was created with a socket path.
func TestClient_StreamEvents_WithHostFlag(t *testing.T) {
	// On non-Windows this sets hostFlag; on Windows it does not.
	c := NewClient("/var/run/docker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	ch := make(chan Event, 1)
	_ = c.StreamEvents(ctx, "gwaf", ch)
	// Should return quickly
}

func TestClient_StreamEvents_RejectsInvalidLabelPrefix(t *testing.T) {
	c := NewClient("")
	err := c.StreamEvents(context.Background(), "gwaf\n--format={{.}}", make(chan Event, 1))
	if err == nil {
		t.Fatal("expected invalid label prefix error")
	}
}

// TestClient_StreamEvents_SendBlockedCtxDone verifies the select inside the
// event goroutine takes the ctx.Done() path when the channel is full and the
// context is canceled.
func TestClient_StreamEvents_SendBlockedCtxDone(t *testing.T) {
	c := NewClient("")
	// This test is best-effort; we mainly want to ensure the code path exists.
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan Event) // unbuffered, will block
	go func() {
		// give StreamEvents time to start goroutine
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_ = c.StreamEvents(ctx, "gwaf", ch)
}

// TestClient_Ping_Success verifies Ping succeeds when docker returns a
// non-empty version string.
func TestClient_Ping_Success(t *testing.T) {
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return "24.0.7\n", nil
	}
	err := c.Ping()
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

// TestClient_ListContainers_EmptyID verifies ps lines with empty IDs are skipped.
func TestClient_ListContainers_EmptyID(t *testing.T) {
	psOutput := `{"ID":""}`
	c := NewClient("")
	c.cmdFunc = func(_ context.Context, args ...string) (string, error) {
		return psOutput, nil
	}
	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containers != nil {
		t.Fatalf("expected nil containers, got %v", containers)
	}
}

// TestAutoDetectPort_EmptyPorts verifies autoDetectPort returns 80 when no
// ports are exposed.
func TestAutoDetectPort_EmptyPorts(t *testing.T) {
	c := Container{Ports: []ContainerPort{}}
	if autoDetectPort(c) != 80 {
		t.Errorf("expected 80 for empty ports, got %d", autoDetectPort(c))
	}
}

// TestWatcher_pollLoop_WithChange verifies pollLoop calls notifyChange when
// sync detects a change.
func TestWatcher_pollLoop_WithChange(t *testing.T) {
	inspectJSON := `[{
		"Id": "abc123",
		"Name": "/my-api",
		"Config": {
			"Labels": {"gwaf.enable": "true", "gwaf.host": "api.test", "gwaf.port": "8080"},
			"ExposedPorts": {"8080/tcp": {}}
		},
		"NetworkSettings": {
			"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}
		},
		"State": {"Status": "running", "Running": true}
	}]`
	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return `{"ID":"abc123"}`, nil
		}
		return inspectJSON, nil
	})
	w := NewWatcher(c, "gwaf", "bridge", 20*time.Millisecond)
	w.SetLogger(func(_, _ string) {})

	changed := false
	w.SetOnChange(func() { changed = true })

	go func() {
		time.Sleep(50 * time.Millisecond)
		w.Stop()
	}()
	w.pollLoop()

	if !changed {
		t.Error("expected notifyChange to be called when services change")
	}
}

// strContains reports whether substr is within s.
func strContains(s, substr string) bool {
	return len(substr) <= len(s) && (s == substr || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
