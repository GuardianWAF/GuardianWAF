package engine

import (
	"net/http"
)

// applyResponseHook calls the response hook functions stored on the
// RequestContext. The response/clientside/CORS layers register these hooks
// during Process() so that security headers, CSP headers, and CORS headers
// are applied without circular imports between engine and those packages.
func applyResponseHook(w http.ResponseWriter, ctx *RequestContext) {
	// Apply CORS headers from the CORS layer (runs at Order 150).
	applyCORSHook(w, ctx)

	// Apply the client-side CSP hook (clientside layer, Order 590) before the
	// response layer's hook (Order 600) so response-layer headers take final
	// precedence, matching pipeline order.
	if ctx.ClientsideCSPHook != nil {
		ctx.ClientsideCSPHook(w)
	}

	// Apply the main response hook (security headers from response layer).
	if ctx.ResponseHook != nil {
		ctx.ResponseHook(w)
	}
}

// applyCORSHook applies CORS headers stored on the RequestContext by the CORS layer.
func applyCORSHook(w http.ResponseWriter, ctx *RequestContext) {
	// Preflight headers take precedence if set (handled by CORS layer directly)
	if ctx.CORSPreflightHeaders != nil {
		w.Header().Set("Vary", "Origin")
		for k, v := range ctx.CORSPreflightHeaders {
			w.Header().Set(k, v)
		}
		return
	}
	// Regular CORS headers from the CORS layer's Process()
	if ctx.CORSHeaders != nil {
		w.Header().Set("Vary", "Origin")
		for k, v := range ctx.CORSHeaders {
			w.Header().Set(k, v)
		}
		if ctx.CORSExposeHeaders != "" {
			w.Header().Set("Access-Control-Expose-Headers", ctx.CORSExposeHeaders)
		}
	}
}
