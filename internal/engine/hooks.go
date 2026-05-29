package engine

import (
	"net/http"
)

// applyResponseHook calls the response hook function stored in context metadata.
// The response layer registers this hook during Process() so that security
// headers are applied without circular imports between engine and response packages.
// It also applies CORS headers stored by the CORS layer (Order 150) since the
// CORS layer runs before the response layer (Order 600) and stores headers in
// metadata rather than registering its own hook to avoid overwriting the response hook.
func applyResponseHook(w http.ResponseWriter, metadata map[string]any) {
	// Apply CORS headers from the CORS layer (runs before response layer).
	// The CORS layer stores headers in cors_headers/cors_preflight_headers metadata.
	applyCORSHook(w, metadata)

	// Apply the client-side CSP hook (clientside layer, Order 590) before the
	// response layer's hook (Order 600) so response-layer headers take final
	// precedence, matching pipeline order.
	if hook, ok := metadata["clientside_csp_hook"]; ok {
		if fn, ok := hook.(func(http.ResponseWriter)); ok {
			fn(w)
		}
	}

	// Apply the main response hook (security headers from response layer).
	if hook, ok := metadata["response_hook"]; ok {
		if fn, ok := hook.(func(http.ResponseWriter)); ok {
			fn(w)
		}
	}
}

// applyCORSHook applies CORS headers stored in context metadata by the CORS layer.
func applyCORSHook(w http.ResponseWriter, metadata map[string]any) {
	// Preflight headers take precedence if set (handled by CORS layer directly)
	if headers, ok := metadata["cors_preflight_headers"].(map[string]string); ok {
		w.Header().Set("Vary", "Origin")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		return
	}
	// Regular CORS headers from the CORS layer's Process()
	if headers, ok := metadata["cors_headers"].(map[string]string); ok {
		w.Header().Set("Vary", "Origin")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if expose, ok := metadata["cors_expose_headers"].(string); ok && expose != "" {
			w.Header().Set("Access-Control-Expose-Headers", expose)
		}
	}
}
