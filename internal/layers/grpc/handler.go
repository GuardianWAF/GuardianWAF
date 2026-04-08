package grpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Handler provides HTTP API for gRPC monitoring.
type Handler struct {
	security *Security
}

// NewHandler creates a new gRPC handler.
func NewHandler(security *Security) *Handler {
	return &Handler{security: security}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.security == nil {
		http.Error(w, "gRPC security not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.URL.Path {
	case "/api/v1/grpc/stats":
		h.handleStats(w, r)
	case "/api/v1/grpc/streams":
		h.handleStreams(w, r)
	case "/api/v1/grpc/services":
		h.handleServices(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleStats returns gRPC statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.security.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// StreamInfo represents stream information for API response.
type StreamInfo struct {
	ID           uint32        `json:"id"`
	Service      string        `json:"service"`
	Method       string        `json:"method"`
	ClientStream bool          `json:"client_stream"`
	ServerStream bool          `json:"server_stream"`
	StartTime    time.Time     `json:"start_time"`
	Duration     time.Duration `json:"duration"`
	LastActivity time.Time     `json:"last_activity"`
	MessagesSent int64         `json:"messages_sent"`
	MessagesRecv int64         `json:"messages_recv"`
}

// handleStreams returns active streams.
func (h *Handler) handleStreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get service filter from query
	serviceFilter := r.URL.Query().Get("service")

	streams := h.security.GetAllStreams()

	var streamInfos []StreamInfo
	for _, stream := range streams {
		// Apply service filter
		if serviceFilter != "" && stream.Service != serviceFilter {
			continue
		}

		stream.mu.RLock()
		info := StreamInfo{
			ID:           stream.ID,
			Service:      stream.Service,
			Method:       stream.Method,
			ClientStream: stream.ClientStream,
			ServerStream: stream.ServerStream,
			StartTime:    stream.StartTime,
			Duration:     time.Since(stream.StartTime),
			LastActivity: stream.LastActivity,
			MessagesSent: stream.MessagesSent,
			MessagesRecv: stream.MessagesRecv,
		}
		stream.mu.RUnlock()
		streamInfos = append(streamInfos, info)
	}

	// Sort by start time (newest first)
	sort.Slice(streamInfos, func(i, j int) bool {
		return streamInfos[i].StartTime.After(streamInfos[j].StartTime)
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"streams": streamInfos,
		"count":   len(streamInfos),
	}); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// ServiceInfo represents service information for API response.
type ServiceInfo struct {
	Name          string   `json:"name"`
	StreamCount   int      `json:"stream_count"`
	Methods       []string `json:"methods,omitempty"`
	Allowed       bool     `json:"allowed"`
	Blocked       bool     `json:"blocked"`
}

// handleServices returns configured services.
func (h *Handler) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := h.security.config

	// Build service info from active streams and config
	serviceMap := make(map[string]*ServiceInfo)

	// Add active services from streams
	streams := h.security.GetAllStreams()
	for _, stream := range streams {
		if info, ok := serviceMap[stream.Service]; ok {
			info.StreamCount++
			// Add method if not already present
			found := false
			for _, m := range info.Methods {
				if m == stream.Method {
					found = true
					break
				}
			}
			if !found {
				info.Methods = append(info.Methods, stream.Method)
			}
		} else {
			serviceMap[stream.Service] = &ServiceInfo{
				Name:        stream.Service,
				StreamCount: 1,
				Methods:     []string{stream.Method},
				Allowed:     h.security.IsAllowedService(stream.Service),
				Blocked:     h.security.IsBlockedService(stream.Service),
			}
		}
	}

	// Add allowed services from config
	for _, svc := range config.AllowedServices {
		if _, ok := serviceMap[svc]; !ok {
			serviceMap[svc] = &ServiceInfo{
				Name:    svc,
				Allowed: true,
				Blocked: false,
			}
		}
	}

	// Convert to slice
	var services []ServiceInfo
	for _, info := range serviceMap {
		services = append(services, *info)
	}

	// Sort by name
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"services": services,
		"count":    len(services),
	}); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// HealthCheck performs a health check on the gRPC layer.
func (h *Handler) HealthCheck() error {
	if h.security == nil {
		return fmt.Errorf("gRPC security not initialized")
	}
	return nil
}
