package dashboard

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/docker"
)

// dockerWatcherInterface defines what the dashboard needs from the Docker watcher.
type dockerWatcherInterface interface {
	Services() []docker.DiscoveredService
	ServiceCount() int
}

// SetDockerWatcher injects the Docker watcher for dashboard API access.
func (d *Dashboard) SetDockerWatcher(w dockerWatcherInterface) {
	d.dockerWatcher = w
}

// handleDockerServices returns discovered Docker containers.
func (d *Dashboard) handleDockerServices(w http.ResponseWriter, r *http.Request) {
	if d.dockerWatcher == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "services": []any{}})
		return
	}
	services := d.dockerWatcher.Services()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"count":    len(services),
		"services": docker.ServiceSummary(services),
	})
}
