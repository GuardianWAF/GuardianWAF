package dashboard

import (
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"net/http"
	"net/url"
)

// routingControllerAdapter wraps rebuild/save closures into a RoutingController.
type routingControllerAdapter struct {
	rebuildFn func() error
	saveFn    func() error
}

func (r routingControllerAdapter) Rebuild() error {
	if r.rebuildFn == nil {
		return nil
	}
	return r.rebuildFn()
}
func (r routingControllerAdapter) Save() error {
	if r.saveFn == nil {
		return nil
	}
	return r.saveFn()
}

// SetRoutingController injects the routing controller (rebuild + save) and
// optional upstream/certificate status providers. This is the preferred wiring
// method; the individual setters below remain for backward compatibility.
func (d *Dashboard) SetRoutingController(routingCtrl RoutingController) {
	d.routingCtrl = routingCtrl
}

// SetUpstreamsFn wires the upstream health status provider (implements UpstreamStatusProvider).
func (d *Dashboard) SetUpstreamsFn(fn func() any) {
	if fn == nil {
		return
	}
	d.upstreamStatus = &upstreamStatusAdapter{fn: fn}
}

// SetCertFn wires the SSL certificate status provider (implements CertificateProvider).
func (d *Dashboard) SetCertFn(fn func() any) {
	if fn == nil {
		return
	}
	d.certProvider = &certProviderAdapter{fn: fn}
}

// SetRebuildFn and SetSaveFn remain for backward compatibility with existing tests
// and cmd/guardianwaf code that uses the individual setters. Internally they
// wrap into routingControllerAdapter to satisfy RoutingController.
func (d *Dashboard) SetRebuildFn(fn func() error) {
	if d.routingCtrl == nil {
		d.routingCtrl = &routingControllerAdapter{}
	}
	if adapter, ok := d.routingCtrl.(*routingControllerAdapter); ok {
		adapter.rebuildFn = fn
	} else {
		// routingCtrl was set via SetRoutingController; replace it
		d.routingCtrl = &routingControllerAdapter{rebuildFn: fn}
	}
}

func (d *Dashboard) SetSaveFn(fn func() error) {
	if d.routingCtrl == nil {
		d.routingCtrl = &routingControllerAdapter{}
	}
	if adapter, ok := d.routingCtrl.(*routingControllerAdapter); ok {
		adapter.saveFn = fn
	} else {
		d.routingCtrl = &routingControllerAdapter{saveFn: fn}
	}
}

// upstreamStatusAdapter wraps a func() any as an UpstreamStatusProvider.
type upstreamStatusAdapter struct{ fn func() any }

func (a *upstreamStatusAdapter) GetUpstreamStatus() any { return a.fn() }

// certProviderAdapter wraps a func() any as a CertificateProvider.
type certProviderAdapter struct{ fn func() any }

func (a *certProviderAdapter) GetCertificateStatus() any { return a.fn() }

// --- Routing (Upstreams + Virtual Hosts + Routes) ---

func (d *Dashboard) handleGetRouting(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()

	// Serialize upstreams
	upstreams := make([]map[string]any, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		targets := make([]map[string]any, len(u.Targets))
		for j, t := range u.Targets {
			targets[j] = map[string]any{"url": t.URL, "weight": t.Weight}
		}
		upstreams[i] = map[string]any{
			"name":          u.Name,
			"load_balancer": u.LoadBalancer,
			"targets":       targets,
			"health_check": map[string]any{
				"enabled":  u.HealthCheck.Enabled,
				"interval": u.HealthCheck.Interval.String(),
				"timeout":  u.HealthCheck.Timeout.String(),
				"path":     u.HealthCheck.Path,
			},
		}
	}

	// Serialize virtual hosts
	vhosts := make([]map[string]any, len(cfg.VirtualHosts))
	for i, vh := range cfg.VirtualHosts {
		routes := make([]map[string]any, len(vh.Routes))
		for j, r := range vh.Routes {
			routes[j] = map[string]any{
				"path":         r.Path,
				"upstream":     r.Upstream,
				"strip_prefix": r.StripPrefix,
			}
		}
		vhosts[i] = map[string]any{
			"domains": vh.Domains,
			"tls": map[string]any{
				"cert_file": vh.TLS.CertFile,
				"key_file":  vh.TLS.KeyFile,
			},
			"routes": routes,
		}
	}

	// Serialize default routes
	routes := make([]map[string]any, len(cfg.Routes))
	for i, r := range cfg.Routes {
		routes[i] = map[string]any{
			"path":         r.Path,
			"upstream":     r.Upstream,
			"strip_prefix": r.StripPrefix,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"upstreams":     upstreams,
		"virtual_hosts": vhosts,
		"routes":        routes,
	})
}

func (d *Dashboard) handleUpdateRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Upstreams    []map[string]any `json:"upstreams"`
		VirtualHosts []map[string]any `json:"virtual_hosts"`
		Routes       []map[string]any `json:"routes"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.Upstreams == nil && body.VirtualHosts == nil && body.Routes == nil {
		writeError(w, http.StatusBadRequest, "at least one of upstreams, virtual_hosts, or routes is required")
		return
	}

	cfg := deepCopyConfig(d.engine.Config())

	// Parse upstreams from raw JSON maps
	if body.Upstreams != nil {
		var upstreams []config.UpstreamConfig
		for _, raw := range body.Upstreams {
			u := config.UpstreamConfig{}
			if v, ok := raw["name"].(string); ok {
				u.Name = v
			}
			if v, ok := raw["load_balancer"].(string); ok {
				u.LoadBalancer = v
			}
			if targets, ok := raw["targets"].([]any); ok {
				for _, t := range targets {
					tm, ok := t.(map[string]any)
					if !ok {
						continue
					}
					tc := config.TargetConfig{Weight: 1}
					if v, ok := tm["url"].(string); ok {
						parsed, urlErr := url.Parse(v)
						if urlErr != nil {
							writeError(w, http.StatusBadRequest, sanitizeErr(urlErr))
							return
						}
						if cfg.AllowPrivateUpstreams == nil || !*cfg.AllowPrivateUpstreams {
							if ssrfErr := proxy.IsPrivateOrReservedIP(parsed.Hostname()); ssrfErr != nil {
								writeError(w, http.StatusBadRequest, sanitizeErr(ssrfErr))
								return
							}
						}
						tc.URL = v
					}
					if v, ok := tm["weight"].(float64); ok {
						tc.Weight = int(v)
					}
					u.Targets = append(u.Targets, tc)
				}
			}
			// Preserve existing health check config if upstream name matches
			for _, existing := range cfg.Upstreams {
				if existing.Name == u.Name {
					u.HealthCheck = existing.HealthCheck
					break
				}
			}
			upstreams = append(upstreams, u)
		}
		cfg.Upstreams = upstreams
	}

	// Parse virtual hosts
	if body.VirtualHosts != nil {
		var vhosts []config.VirtualHostConfig
		for _, raw := range body.VirtualHosts {
			vh := config.VirtualHostConfig{}
			if domains, ok := raw["domains"].([]any); ok {
				for _, d := range domains {
					if s, ok := d.(string); ok {
						vh.Domains = append(vh.Domains, s)
					}
				}
			}
			if tls, ok := raw["tls"].(map[string]any); ok {
				if v, ok := tls["cert_file"].(string); ok {
					vh.TLS.CertFile = v
				}
				if v, ok := tls["key_file"].(string); ok {
					vh.TLS.KeyFile = v
				}
			}
			if routes, ok := raw["routes"].([]any); ok {
				for _, r := range routes {
					rm, ok := r.(map[string]any)
					if !ok {
						continue
					}
					rc := config.RouteConfig{}
					if v, ok := rm["path"].(string); ok {
						rc.Path = v
					}
					if v, ok := rm["upstream"].(string); ok {
						rc.Upstream = v
					}
					if v, ok := rm["strip_prefix"].(bool); ok {
						rc.StripPrefix = v
					}
					vh.Routes = append(vh.Routes, rc)
				}
			}
			vhosts = append(vhosts, vh)
		}
		cfg.VirtualHosts = vhosts
	}

	// Parse default routes
	if body.Routes != nil {
		var routes []config.RouteConfig
		for _, raw := range body.Routes {
			rc := config.RouteConfig{}
			if v, ok := raw["path"].(string); ok {
				rc.Path = v
			}
			if v, ok := raw["upstream"].(string); ok {
				rc.Upstream = v
			}
			if v, ok := raw["strip_prefix"].(bool); ok {
				rc.StripPrefix = v
			}
			routes = append(routes, rc)
		}
		cfg.Routes = routes
	}

	// Validate
	ve := &config.ValidationError{}
	config.ValidateUpstreamsExported(cfg.Upstreams, ve)
	config.ValidateRoutesExported(cfg.Routes, cfg.Upstreams, ve)
	config.ValidateVirtualHostsExported(cfg.VirtualHosts, cfg.Upstreams, ve)
	if ve.HasErrors() {
		writeError(w, http.StatusBadRequest, sanitizeErr(ve))
		return
	}

	// Reload config
	if err := d.engine.Reload(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
		return
	}

	// Rebuild proxy
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Rebuild(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "proxy rebuild failed"})
			return
		}
	}

	// Persist to disk
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Routing updated (disk sync pending)"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Routing updated and saved"})
}

// registerRouting registers routing and SPA routes.
func (d *Dashboard) registerRouting(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/routing", d.authWrap(d.handleGetRouting))
	mux.HandleFunc("PUT /api/v1/routing", d.authWrap(d.handleUpdateRouting))
	mux.HandleFunc("OPTIONS /api/v1/routing", handleCORS)

	// SPA serving — React build output from dist/ with fallback to legacy static/
	mux.HandleFunc("GET /assets/", d.handleDistAssets) // Vite hashed assets — public (content-hashed, no secrets)

	mux.HandleFunc("GET /ssl", d.authWrap(d.handleSPA))      // SPA routes
	mux.HandleFunc("GET /config", d.authWrap(d.handleSPA))   // SPA routes
	mux.HandleFunc("GET /routing", d.authWrap(d.handleSPA))  // SPA routes
	mux.HandleFunc("GET /alerting", d.authWrap(d.handleSPA)) // SPA routes
	mux.HandleFunc("GET /logs", d.authWrap(d.handleSPA))     // SPA routes
	mux.HandleFunc("GET /rules", d.authWrap(d.handleSPA))    // SPA routes
	mux.HandleFunc("GET /ai", d.authWrap(d.handleSPA))       // SPA routes
	mux.HandleFunc("/", d.authWrap(d.handleSPA))             // SPA catch-all
}

func (d *Dashboard) handleGetUpstreams(w http.ResponseWriter, r *http.Request) {
	if d.upstreamStatus == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, d.upstreamStatus.GetUpstreamStatus())
}

// --- SSL Certs ---

func (d *Dashboard) handleGetCerts(w http.ResponseWriter, r *http.Request) {
	if d.certProvider == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"certs":   []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, d.certProvider.GetCertificateStatus())
}
