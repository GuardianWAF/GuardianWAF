// Package docker provides Docker container auto-discovery for GuardianWAF.
// It connects to the Docker daemon via CLI commands (platform-agnostic:
// works with Unix sockets, Windows named pipes, remote daemons, and Docker contexts).
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Client communicates with the Docker daemon.
// Primary method: Docker CLI (works everywhere — Unix socket, Windows npipe, remote).
// Fallback for event streaming: direct HTTP over Unix socket (Linux/macOS only).
type Client struct {
	socketPath string
	hostFlag   string // --host flag for docker CLI, empty = use default context
}

// NewClient creates a Docker client.
// socketPath is used for direct socket connections on Linux; on Windows the CLI is always used.
func NewClient(socketPath string) *Client {
	c := &Client{socketPath: socketPath}
	if socketPath != "" && runtime.GOOS != "windows" {
		c.hostFlag = "unix://" + socketPath
	}
	return c
}

// Container represents a Docker container from the list API.
type Container struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Image           string            `json:"Image"`
	State           string            `json:"State"`
	Status          string            `json:"Status"`
	Labels          map[string]string `json:"Labels"`
	Ports           []ContainerPort   `json:"Ports"`
	Created         int64             `json:"Created"`
	NetworkSettings struct {
		Networks map[string]NetworkInfo `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ContainerPort represents a port mapping.
type ContainerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// NetworkInfo holds container network details.
type NetworkInfo struct {
	IPAddress string `json:"IPAddress"`
	Gateway   string `json:"Gateway"`
	NetworkID string `json:"NetworkID"`
}

// ContainerDetail is the full inspect response.
type ContainerDetail struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels       map[string]string `json:"Labels"`
		ExposedPorts map[string]any    `json:"ExposedPorts"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]NetworkInfo   `json:"Networks"`
		Ports    map[string][]PortBinding `json:"Ports"`
	} `json:"NetworkSettings"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
}

// PortBinding represents a host-to-container port mapping.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// Event represents a Docker daemon event.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// Ping checks if Docker daemon is reachable.
func (c *Client) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.dockerCmd(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return fmt.Errorf("docker not reachable: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("docker returned empty version")
	}
	return nil
}

// ListContainers returns all running containers with the given label prefix enable=true.
func (c *Client) ListContainers(labelPrefix string) ([]Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	filter := fmt.Sprintf("label=%s.enable=true", labelPrefix)
	out, err := c.dockerCmd(ctx, "ps", "--filter", filter, "--format", "{{json .}}", "--no-trunc")
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	if strings.TrimSpace(out) == "" {
		return nil, nil
	}

	// docker ps --format json returns one JSON object per line
	// We need to inspect each to get full network info
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			ID string `json:"ID"`
		}
		if unmarshalErr := json.Unmarshal([]byte(line), &row); unmarshalErr == nil && row.ID != "" {
			ids = append(ids, row.ID)
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Inspect all containers in one call
	args := append([]string{"inspect"}, ids...)
	inspectOut, err := c.dockerCmd(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("inspecting containers: %w", err)
	}

	var details []ContainerDetail
	if unmarshalErr := json.Unmarshal([]byte(inspectOut), &details); unmarshalErr != nil {
		return nil, fmt.Errorf("parsing inspect: %w", unmarshalErr)
	}

	// Convert to Container format
	containers := make([]Container, 0, len(details))
	for _, d := range details {
		c := Container{
			ID:     d.ID,
			Names:  []string{d.Name},
			State:  d.State.Status,
			Labels: d.Config.Labels,
		}
		c.NetworkSettings.Networks = d.NetworkSettings.Networks

		// Convert exposed ports
		for portKey := range d.Config.ExposedPorts {
			parts := strings.SplitN(portKey, "/", 2)
			if len(parts) >= 1 {
				var port int
				_, _ = fmt.Sscanf(parts[0], "%d", &port)
				proto := "tcp"
				if len(parts) == 2 {
					proto = parts[1]
				}
				c.Ports = append(c.Ports, ContainerPort{
					PrivatePort: port,
					Type:        proto,
				})
			}
		}

		containers = append(containers, c)
	}

	return containers, nil
}

// InspectContainer returns detailed info about a container.
func (c *Client) InspectContainer(id string) (*ContainerDetail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := c.dockerCmd(ctx, "inspect", id)
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", id, err)
	}

	var details []ContainerDetail
	if unmarshalErr := json.Unmarshal([]byte(out), &details); unmarshalErr != nil {
		return nil, fmt.Errorf("parsing inspect: %w", unmarshalErr)
	}
	if len(details) == 0 {
		return nil, fmt.Errorf("container %s not found", id)
	}
	return &details[0], nil
}

// StreamEvents opens a long-lived `docker events` subprocess.
// Sends container start/stop/die events to the channel.
// Blocks until ctx is canceled or the process exits.
func (c *Client) StreamEvents(ctx context.Context, labelPrefix string, ch chan<- Event) error {
	filter := fmt.Sprintf("label=%s.enable=true", labelPrefix)
	args := []string{
		"events", "--filter", "type=container",
		"--filter", "event=start", "--filter", "event=stop",
		"--filter", "event=die", "--filter", "event=destroy",
		"--filter", filter, "--format", "{{json .}}",
	}

	if c.hostFlag != "" {
		args = append([]string{"--host", c.hostFlag}, args...)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating pipe: %w", err)
	}

	if startErr := cmd.Start(); startErr != nil {
		return fmt.Errorf("starting docker events: %w", startErr)
	}

	decoder := json.NewDecoder(stdout)
	go func() {
		defer func() { _ = cmd.Wait() }()
		for {
			var event Event
			if decodeErr := decoder.Decode(&event); decodeErr != nil {
				return
			}
			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	return nil
}

// dockerCmd executes a docker CLI command and returns stdout.
func (c *Client) dockerCmd(ctx context.Context, args ...string) (string, error) {
	if c.hostFlag != "" {
		args = append([]string{"--host", c.hostFlag}, args...)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%w: %s", err, string(exitErr.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

// ContainerName returns the clean name (strips leading /).
func ContainerName(c Container) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

// NewHTTPClient creates a direct HTTP client over Unix socket.
// Only used on Linux/macOS for low-latency polling; not used on Windows.
func NewHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 5*time.Second)
			},
		},
		Timeout: 30 * time.Second,
	}
}
