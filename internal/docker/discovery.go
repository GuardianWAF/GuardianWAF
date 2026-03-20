package docker

import (
	"fmt"
	"strconv"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

const defaultLabelPrefix = "gwaf"

// DiscoveredService represents a container discovered via Docker labels.
type DiscoveredService struct {
	ContainerID    string        `json:"container_id"`
	ContainerName  string        `json:"container_name"`
	Image          string        `json:"image"`
	Host           string        `json:"host"`            // gwaf.host
	Path           string        `json:"path"`            // gwaf.path
	Port           int           `json:"port"`            // gwaf.port
	Weight         int           `json:"weight"`          // gwaf.weight
	StripPrefix    bool          `json:"strip_prefix"`    // gwaf.strip_prefix
	LBStrategy     string        `json:"lb_strategy"`     // gwaf.lb
	UpstreamName   string        `json:"upstream_name"`   // gwaf.upstream
	TLS            string        `json:"tls"`             // gwaf.tls
	HealthPath     string        `json:"health_path"`     // gwaf.health.path
	HealthInterval time.Duration `json:"health_interval"` // gwaf.health.interval
	IPAddress      string        `json:"ip_address"`      // from Docker network
	Status         string        `json:"status"`          // running, stopped
}

// TargetURL builds the backend URL for this service.
func (s *DiscoveredService) TargetURL() string {
	scheme := "http"
	if s.TLS == "manual" || s.TLS == "auto" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, s.IPAddress, s.Port)
}

// ParseLabels extracts a DiscoveredService from Docker container labels.
func ParseLabels(labels map[string]string, prefix string) *DiscoveredService {
	if prefix == "" {
		prefix = defaultLabelPrefix
	}

	get := func(key string) string {
		return labels[prefix+"."+key]
	}

	// Must have enable=true
	if get("enable") != "true" {
		return nil
	}

	svc := &DiscoveredService{
		Host:         get("host"),
		Path:         get("path"),
		TLS:          get("tls"),
		LBStrategy:   get("lb"),
		UpstreamName: get("upstream"),
		HealthPath:   get("health.path"),
	}

	if svc.Path == "" {
		svc.Path = "/"
	}
	if svc.LBStrategy == "" {
		svc.LBStrategy = "round_robin"
	}

	// Parse port
	if p := get("port"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			svc.Port = v
		}
	}

	// Parse weight
	svc.Weight = 1
	if w := get("weight"); w != "" {
		if v, err := strconv.Atoi(w); err == nil && v > 0 {
			svc.Weight = v
		}
	}

	// Parse strip_prefix
	svc.StripPrefix = get("strip_prefix") == "true"

	// Parse health interval
	if interval := get("health.interval"); interval != "" {
		if d, err := time.ParseDuration(interval); err == nil {
			svc.HealthInterval = d
		}
	}
	if svc.HealthInterval == 0 {
		svc.HealthInterval = 10 * time.Second
	}

	return svc
}

// DiscoverFromContainers converts Docker containers to discovered services.
func DiscoverFromContainers(containers []Container, prefix, network string) []DiscoveredService {
	if prefix == "" {
		prefix = defaultLabelPrefix
	}
	if network == "" {
		network = "bridge"
	}

	var services []DiscoveredService

	for _, c := range containers {
		svc := ParseLabels(c.Labels, prefix)
		if svc == nil {
			continue
		}

		svc.ContainerID = c.ID
		svc.ContainerName = ContainerName(c)
		svc.Image = c.Image
		svc.Status = c.State

		// Get IP from specified network, fallback to any network
		if nw, ok := c.NetworkSettings.Networks[network]; ok && nw.IPAddress != "" {
			svc.IPAddress = nw.IPAddress
		} else {
			for _, nw := range c.NetworkSettings.Networks {
				if nw.IPAddress != "" {
					svc.IPAddress = nw.IPAddress
					break
				}
			}
		}

		// Auto-detect port if not specified
		if svc.Port == 0 {
			svc.Port = autoDetectPort(c)
		}

		if svc.IPAddress != "" && svc.Port > 0 {
			// Default upstream name to container name
			if svc.UpstreamName == "" {
				svc.UpstreamName = svc.ContainerName
			}
			services = append(services, *svc)
		}
	}

	return services
}

// BuildConfig merges discovered services with static config.
// Discovered upstreams/routes are appended to static ones.
func BuildConfig(services []DiscoveredService, staticCfg *config.Config) *config.Config {
	// Deep copy static config
	merged := *staticCfg

	// Group services by upstream name
	groups := make(map[string][]DiscoveredService)
	for _, svc := range services {
		groups[svc.UpstreamName] = append(groups[svc.UpstreamName], svc)
	}

	// Track existing upstream names to avoid conflicts
	existingUpstreams := make(map[string]bool)
	for _, u := range merged.Upstreams {
		existingUpstreams[u.Name] = true
	}

	// Build upstreams from discovered services
	for name, svcs := range groups {
		// Skip if upstream already exists in static config
		if existingUpstreams[name] {
			continue
		}

		upstream := config.UpstreamConfig{
			Name:         name,
			LoadBalancer: svcs[0].LBStrategy,
		}

		// Health check from first service in group
		if svcs[0].HealthPath != "" {
			upstream.HealthCheck = config.HealthCheckConfig{
				Enabled:  true,
				Interval: svcs[0].HealthInterval,
				Timeout:  5 * time.Second,
				Path:     svcs[0].HealthPath,
			}
		}

		// Add targets (one per container in the group)
		for _, svc := range svcs {
			upstream.Targets = append(upstream.Targets, config.TargetConfig{
				URL:    svc.TargetURL(),
				Weight: svc.Weight,
			})
		}

		merged.Upstreams = append(merged.Upstreams, upstream)

		// Build virtual host routes from host labels
		host := svcs[0].Host
		if host != "" {
			addVHostRoute(&merged, host, svcs[0].Path, name, svcs[0].StripPrefix)
		} else {
			// No host → add as default route
			addDefaultRoute(&merged, svcs[0].Path, name, svcs[0].StripPrefix)
		}
	}

	return &merged
}

// addVHostRoute adds a route to an existing or new virtual host.
func addVHostRoute(cfg *config.Config, host, path, upstream string, strip bool) {
	route := config.RouteConfig{
		Path:        path,
		Upstream:    upstream,
		StripPrefix: strip,
	}

	// Check if vhost already exists
	for i, vh := range cfg.VirtualHosts {
		for _, d := range vh.Domains {
			if d == host {
				cfg.VirtualHosts[i].Routes = append(cfg.VirtualHosts[i].Routes, route)
				return
			}
		}
	}

	// Create new vhost
	cfg.VirtualHosts = append(cfg.VirtualHosts, config.VirtualHostConfig{
		Domains: []string{host},
		Routes:  []config.RouteConfig{route},
	})
}

// addDefaultRoute adds a default (non-vhost) route.
func addDefaultRoute(cfg *config.Config, path, upstream string, strip bool) {
	// Check if route with same path already exists
	for _, r := range cfg.Routes {
		if r.Path == path {
			return
		}
	}
	cfg.Routes = append(cfg.Routes, config.RouteConfig{
		Path:        path,
		Upstream:    upstream,
		StripPrefix: strip,
	})
}

// autoDetectPort tries to find the main exposed port from a container.
func autoDetectPort(c Container) int {
	// Prefer exposed ports from port mappings
	for _, p := range c.Ports {
		if p.Type == "tcp" && p.PrivatePort > 0 {
			return p.PrivatePort
		}
	}
	// Common web ports
	commonPorts := []int{80, 8088, 3000, 5000, 8000, 443, 8443}
	for _, port := range commonPorts {
		key := fmt.Sprintf("%d/tcp", port)
		for _, p := range c.Ports {
			if p.PrivatePort == port {
				return port
			}
		}
		// Check if port string exists in port list as key
		_ = key
	}
	// Fallback: first exposed port
	if len(c.Ports) > 0 {
		return c.Ports[0].PrivatePort
	}
	return 80
}

// ServiceSummary is a lightweight view for dashboard display.
func ServiceSummary(services []DiscoveredService) []map[string]any {
	result := make([]map[string]any, len(services))
	for i, svc := range services {
		result[i] = map[string]any{
			"container_id":   svc.ContainerID[:min(12, len(svc.ContainerID))],
			"container_name": svc.ContainerName,
			"image":          svc.Image,
			"host":           svc.Host,
			"path":           svc.Path,
			"target":         svc.TargetURL(),
			"upstream":       svc.UpstreamName,
			"weight":         svc.Weight,
			"lb_strategy":    svc.LBStrategy,
			"health_path":    svc.HealthPath,
			"status":         svc.Status,
		}
	}
	return result
}
