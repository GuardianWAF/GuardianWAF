package docker

import (
	"context"
	"sync"
	"time"
)

// Watcher monitors Docker for container changes and triggers proxy rebuilds.
type Watcher struct {
	client       *Client
	labelPrefix  string
	network      string
	pollInterval time.Duration
	onChange     func() // called when services change
	logFn        func(level, msg string)

	mu       sync.RWMutex
	services map[string]*DiscoveredService // containerID → service
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewWatcher creates a Docker container watcher.
func NewWatcher(client *Client, labelPrefix, network string, pollInterval time.Duration) *Watcher {
	if labelPrefix == "" {
		labelPrefix = defaultLabelPrefix
	}
	if network == "" {
		network = "bridge"
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	return &Watcher{
		client:       client,
		labelPrefix:  labelPrefix,
		network:      network,
		pollInterval: pollInterval,
		services:     make(map[string]*DiscoveredService),
		stopCh:       make(chan struct{}),
		logFn:        func(_, _ string) {},
	}
}

// SetOnChange sets the callback for when services change.
func (w *Watcher) SetOnChange(fn func()) {
	w.onChange = fn
}

// SetLogger sets the log function.
func (w *Watcher) SetLogger(fn func(level, msg string)) {
	w.logFn = fn
}

// Start begins watching Docker for container changes.
// It does an initial sync, then tries event streaming with poll fallback.
func (w *Watcher) Start() {
	// Initial sync
	w.sync()

	w.wg.Add(1)
	go w.loop()
}

// Stop gracefully stops the watcher.
func (w *Watcher) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

// Services returns the current discovered services.
func (w *Watcher) Services() []DiscoveredService {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]DiscoveredService, 0, len(w.services))
	for _, svc := range w.services {
		result = append(result, *svc)
	}
	return result
}

// ServiceCount returns the number of discovered services.
func (w *Watcher) ServiceCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.services)
}

// loop is the main watcher loop that tries event streaming with poll fallback.
func (w *Watcher) loop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopCh:
			return
		default:
		}

		// Try event-driven mode first
		err := w.streamEvents()
		if err != nil {
			w.logFn("warn", "Docker event stream disconnected: "+err.Error()+", falling back to polling")
		}

		// If streaming fails, fall back to polling
		w.pollLoop()
	}
}

// streamEvents connects to Docker event stream.
// Returns when stream disconnects or stop is requested.
func (w *Watcher) streamEvents() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stop on shutdown
	go func() {
		<-w.stopCh
		cancel()
	}()

	eventCh := make(chan Event, 32)
	errCh := make(chan error, 1)

	go func() {
		errCh <- w.client.StreamEvents(ctx, w.labelPrefix, eventCh)
	}()

	w.logFn("info", "Docker event stream connected")

	for {
		select {
		case event := <-eventCh:
			w.handleEvent(event)

		case err := <-errCh:
			return err

		case <-w.stopCh:
			cancel()
			return nil
		}
	}
}

// pollLoop falls back to periodic polling when event streaming isn't available.
func (w *Watcher) pollLoop() {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			changed := w.sync()
			if changed {
				w.notifyChange()
			}

		case <-w.stopCh:
			return
		}
	}
}

// handleEvent processes a single Docker event.
func (w *Watcher) handleEvent(event Event) {
	switch event.Action {
	case "start":
		w.logFn("info", "Docker: container started: "+event.Actor.Attributes["name"])
		w.sync()
		w.notifyChange()

	case "stop", "die", "destroy":
		w.logFn("info", "Docker: container stopped: "+event.Actor.Attributes["name"])
		w.mu.Lock()
		delete(w.services, event.Actor.ID)
		w.mu.Unlock()
		w.notifyChange()
	}
}

// sync fetches the current container list and updates the services map.
// Returns true if services changed.
func (w *Watcher) sync() bool {
	containers, err := w.client.ListContainers(w.labelPrefix)
	if err != nil {
		w.logFn("warn", "Docker: list containers failed: "+err.Error())
		return false
	}

	services := DiscoverFromContainers(containers, w.labelPrefix, w.network)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if services actually changed
	if len(services) == len(w.services) {
		changed := false
		for _, svc := range services {
			existing, ok := w.services[svc.ContainerID]
			if !ok || existing.TargetURL() != svc.TargetURL() || existing.Host != svc.Host {
				changed = true
				break
			}
		}
		if !changed {
			return false
		}
	}

	// Rebuild services map
	w.services = make(map[string]*DiscoveredService, len(services))
	for i := range services {
		w.services[services[i].ContainerID] = &services[i]
	}

	w.logFn("info", "Docker: discovered "+itoa(len(services))+" services")
	return true
}

// notifyChange calls the onChange callback if set.
func (w *Watcher) notifyChange() {
	if w.onChange != nil {
		w.onChange()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}
