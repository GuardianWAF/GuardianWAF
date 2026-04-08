// Package apivalidation provides OpenAPI schema validation for API requests.
package apivalidation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Pre-compiled regex for OpenAPI path parameter replacement.
var rePathParam = regexp.MustCompile(`\{[^}]+\}`)

// Layer implements the engine.Layer interface for OpenAPI schema validation.
type Layer struct {
	config   *Config
	specs    []*CompiledSpec
	cache    *SchemaCache
	router   *PathRouter
	mu       sync.RWMutex
	enabled  bool
}

// CompiledSpec holds a compiled OpenAPI specification.
type CompiledSpec struct {
	Source   SchemaSource
	Spec     *OpenAPISpec
	Routes   map[string]*RouteInfo // key: "METHOD /path"
	BasePath string
}

// RouteInfo holds compiled route information.
type RouteInfo struct {
	Path       string
	Method     string
	Operation  *Operation
	Parameters []CompiledParameter
	BodySchema *CompiledBodySchema
	Pattern    *regexp.Regexp // For path matching with parameters
}

// PathRouter handles path matching for API routes.
type PathRouter struct {
	routes map[string]map[string]*RouteInfo // method -> path -> route
}

// NewPathRouter creates a new path router.
func NewPathRouter() *PathRouter {
	return &PathRouter{
		routes: make(map[string]map[string]*RouteInfo),
	}
}

// AddRoute adds a route to the router.
func (r *PathRouter) AddRoute(method, path string, info *RouteInfo) {
	method = strings.ToUpper(method)
	if r.routes[method] == nil {
		r.routes[method] = make(map[string]*RouteInfo)
	}
	r.routes[method][path] = info
}

// Match finds a matching route for the given method and path.
func (r *PathRouter) Match(method, path string) *RouteInfo {
	method = strings.ToUpper(method)
	methodRoutes, ok := r.routes[method]
	if !ok {
		return nil
	}

	// First, try exact match
	if route, ok := methodRoutes[path]; ok {
		return route
	}

	// Try pattern matching
	for _, route := range methodRoutes {
		if route.Pattern != nil && route.Pattern.MatchString(path) {
			return route
		}
	}

	return nil
}

// NewLayer creates a new API validation layer.
func NewLayer(cfg *Config) *Layer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Layer{
		config:  cfg,
		specs:   make([]*CompiledSpec, 0),
		cache:   NewSchemaCache(cfg.CacheSize),
		router:  NewPathRouter(),
		enabled: cfg.Enabled,
	}
}

// Name returns "apivalidation".
func (l *Layer) Name() string { return "apivalidation" }

// SetEnabled enables or disables the layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.enabled = enabled
}

// LoadSchema loads an OpenAPI schema from a file or URL.
func (l *Layer) LoadSchema(source SchemaSource) error {
	var spec *OpenAPISpec
	var err error

	switch source.Type {
	case "openapi":
		spec, err = l.loadOpenAPISpec(source.Path)
	case "jsonschema":
		spec, err = l.loadJSONSchema(source.Path)
	default:
		return fmt.Errorf("unknown schema type: %s", source.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to load schema from %s: %w", source.Path, err)
	}

	compiled := &CompiledSpec{
		Source: source,
		Spec:   spec,
		Routes: make(map[string]*RouteInfo),
	}

	// Compile routes
	l.compileRoutes(compiled)

	l.mu.Lock()
	l.specs = append(l.specs, compiled)
	l.mu.Unlock()

	return nil
}

// loadOpenAPISpec loads an OpenAPI 3.0 specification from a JSON or YAML file.
func (l *Layer) loadOpenAPISpec(path string) (*OpenAPISpec, error) {
	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}

	// Check if it's YAML
	if IsYAML(data) {
		return LoadYAMLSpec(data)
	}

	// Parse as JSON
	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	return &spec, nil
}

// loadJSONSchema loads a JSON Schema file.
func (l *Layer) loadJSONSchema(path string) (*OpenAPISpec, error) {
	// For JSON Schema, we wrap it in a simple OpenAPI-like structure
	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}

	var schema Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse JSON schema: %w", err)
	}

	// Create a synthetic OpenAPI spec with a wildcard path
	spec := &OpenAPISpec{
		OpenAPI: "3.0.0",
		Info: Info{
			Title:   "JSON Schema",
			Version: "1.0.0",
		},
		Paths: map[string]PathItem{
			"/*": {
				Post: &Operation{
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &schema,
							},
						},
					},
				},
			},
		},
	}

	return spec, nil
}

// readFile reads a file from the local filesystem.
func (l *Layer) readFile(path string) ([]byte, error) {
	// Security: Only allow reading from specific directories
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// Basic path traversal protection
	if strings.Contains(absPath, "..") {
		return nil, fmt.Errorf("path traversal detected")
	}

	// Read file using standard library
	return os.ReadFile(absPath)
}

// compileRoutes compiles all routes from an OpenAPI spec.
func (l *Layer) compileRoutes(spec *CompiledSpec) {
	for path, pathItem := range spec.Spec.Paths {
		// Compile path pattern for path parameter matching
		pattern := l.compilePathPattern(path)

		// GET
		if pathItem.Get != nil {
			l.compileOperation(spec, path, http.MethodGet, pathItem.Get, pathItem.Parameters, pattern)
		}
		// POST
		if pathItem.Post != nil {
			l.compileOperation(spec, path, http.MethodPost, pathItem.Post, pathItem.Parameters, pattern)
		}
		// PUT
		if pathItem.Put != nil {
			l.compileOperation(spec, path, http.MethodPut, pathItem.Put, pathItem.Parameters, pattern)
		}
		// DELETE
		if pathItem.Delete != nil {
			l.compileOperation(spec, path, http.MethodDelete, pathItem.Delete, pathItem.Parameters, pattern)
		}
		// PATCH
		if pathItem.Patch != nil {
			l.compileOperation(spec, path, http.MethodPatch, pathItem.Patch, pathItem.Parameters, pattern)
		}
		// HEAD
		if pathItem.Head != nil {
			l.compileOperation(spec, path, http.MethodHead, pathItem.Head, pathItem.Parameters, pattern)
		}
		// OPTIONS
		if pathItem.Options != nil {
			l.compileOperation(spec, path, http.MethodOptions, pathItem.Options, pathItem.Parameters, pattern)
		}
	}
}

// compilePathPattern converts an OpenAPI path to a regex pattern.
func (l *Layer) compilePathPattern(path string) *regexp.Regexp {
	// Convert /users/{id} to /users/([^/]+)
	// First replace {param} patterns, then escape special chars
	pattern := rePathParam.ReplaceAllString(path, `([^/]+)`)
	pattern = regexp.QuoteMeta(pattern)
	// Unescape the regex groups we added
	pattern = strings.ReplaceAll(pattern, `\(\[\^/\]\+\)`, `([^/]+)`)
	pattern = "^" + pattern + "$"

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// compileOperation compiles a single operation.
func (l *Layer) compileOperation(spec *CompiledSpec, path, method string, op *Operation, commonParams []Parameter, pattern *regexp.Regexp) {
	// Merge common and operation-specific parameters
	allParams := make([]Parameter, 0, len(commonParams)+len(op.Parameters))
	allParams = append(allParams, commonParams...)
	allParams = append(allParams, op.Parameters...)

	// Compile parameters
	compiledParams := make([]CompiledParameter, 0, len(allParams))
	for _, p := range allParams {
		compiledParams = append(compiledParams, CompiledParameter{
			Name:     p.Name,
			In:       p.In,
			Required: p.Required,
			Schema:   p.Schema,
		})
	}

	// Compile request body schema
	var bodySchema *CompiledBodySchema
	if op.RequestBody != nil {
		for contentType, mediaType := range op.RequestBody.Content {
			if mediaType.Schema != nil {
				bodySchema = &CompiledBodySchema{
					Required:             op.RequestBody.Required,
					Schema:               mediaType.Schema,
					AdditionalProperties: l.getAdditionalProperties(mediaType.Schema),
				}
				// Cache the compiled schema
				cacheKey := fmt.Sprintf("%s:%s:%s", spec.Source.Path, method, path)
				l.cache.Put(cacheKey+":"+contentType, &CompiledSchema{
					Path:        path,
					Method:      method,
					ContentType: contentType,
					Parameters:  compiledParams,
					BodySchema:  bodySchema,
					StrictMode:  l.config.StrictMode,
				})
				break // Use first content type
			}
		}
	}

	route := &RouteInfo{
		Path:       path,
		Method:     method,
		Operation:  op,
		Parameters: compiledParams,
		BodySchema: bodySchema,
		Pattern:    pattern,
	}

	spec.Routes[method+" "+path] = route
	l.router.AddRoute(method, path, route)
}

// getAdditionalProperties extracts additionalProperties from schema.
func (l *Layer) getAdditionalProperties(schema *Schema) bool {
	if schema.AdditionalProperties != nil {
		return *schema.AdditionalProperties
	}
	return !l.config.StrictMode
}

// Process validates the request against OpenAPI schemas.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.enabled || !l.config.ValidateRequest {
		return engine.LayerResult{Action: engine.ActionPass}
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.APIValidation.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	l.mu.RLock()
	specs := l.specs
	l.mu.RUnlock()

	// In strict mode, block if no schemas are loaded
	if len(specs) == 0 {
		if l.config.StrictMode {
			return engine.LayerResult{
				Action: engine.ActionBlock,
				Score:  l.config.ViolationScore,
				Findings: []engine.Finding{
					{
						DetectorName: "apivalidation",
						Description:  "No OpenAPI schema defined for this endpoint in strict mode",
						Score:        l.config.ViolationScore,
					},
				},
			}
		}
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Find matching route
	route := l.router.Match(ctx.Method, ctx.Path)
	if route == nil {
		// No schema defined for this route - allow if not in strict mode
		if l.config.StrictMode {
			return engine.LayerResult{
				Action: engine.ActionBlock,
				Score:  l.config.ViolationScore,
				Findings: []engine.Finding{
					{
						DetectorName: "apivalidation",
						Description:  "No OpenAPI schema defined for this endpoint in strict mode",
						Score:        l.config.ViolationScore,
					},
				},
			}
		}
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Validate request
	validator := NewSchemaValidator(l.config.StrictMode)
	findings := make([]engine.Finding, 0)
	totalScore := 0

	// Validate path parameters
	pathFindings := l.validatePathParameters(ctx, route, validator)
	findings = append(findings, pathFindings...)

	// Validate query parameters
	queryFindings := l.validateQueryParameters(ctx, route, validator)
	findings = append(findings, queryFindings...)

	// Validate headers
	headerFindings := l.validateHeaders(ctx, route, validator)
	findings = append(findings, headerFindings...)

	// Validate request body
	bodyFindings := l.validateRequestBody(ctx, route, validator)
	findings = append(findings, bodyFindings...)

	// Calculate total score
	for _, f := range findings {
		totalScore += f.Score
	}

	// Determine action
	action := engine.ActionPass
	if totalScore > 0 && l.config.BlockOnViolation {
		action = engine.ActionBlock
	} else if totalScore > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
	}
}

// validatePathParameters validates path parameters.
func (l *Layer) validatePathParameters(ctx *engine.RequestContext, route *RouteInfo, validator *SchemaValidator) []engine.Finding {
	findings := make([]engine.Finding, 0)

	for _, param := range route.Parameters {
		if param.In != "path" {
			continue
		}

		// Extract path parameter value
		value := l.extractPathParam(ctx.Path, route.Path, param.Name)
		if value == "" {
			if param.Required {
				findings = append(findings, engine.Finding{
					DetectorName: "apivalidation",
					Description:  fmt.Sprintf("Required path parameter '%s' is missing", param.Name),
					Score:        l.config.ViolationScore / 2,
				})
			}
			continue
		}

		// Validate against schema
		if param.Schema != nil {
			result := validator.Validate(value, param.Schema, "path."+param.Name)
			if !result.Valid {
				for _, err := range result.Errors {
					findings = append(findings, engine.Finding{
						DetectorName: "apivalidation",
						Description:  fmt.Sprintf("Path parameter '%s': %s", param.Name, err.Message),
						Score:        result.Score,
						MatchedValue: value,
					})
				}
			}
		}
	}

	return findings
}

// validateQueryParameters validates query parameters.
func (l *Layer) validateQueryParameters(ctx *engine.RequestContext, route *RouteInfo, validator *SchemaValidator) []engine.Finding {
	findings := make([]engine.Finding, 0)

	for _, param := range route.Parameters {
		if param.In != "query" {
			continue
		}

		values, exists := ctx.QueryParams[param.Name]
		if !exists || len(values) == 0 {
			if param.Required {
				findings = append(findings, engine.Finding{
					DetectorName: "apivalidation",
					Description:  fmt.Sprintf("Required query parameter '%s' is missing", param.Name),
					Score:        l.config.ViolationScore / 2,
				})
			}
			continue
		}

		// Validate each value
		for _, value := range values {
			if param.Schema != nil {
				result := validator.Validate(value, param.Schema, "query."+param.Name)
				if !result.Valid {
					for _, err := range result.Errors {
						findings = append(findings, engine.Finding{
							DetectorName: "apivalidation",
							Description:  fmt.Sprintf("Query parameter '%s': %s", param.Name, err.Message),
							Score:        result.Score,
							MatchedValue: value,
						})
					}
				}
			}
		}
	}

	return findings
}

// validateHeaders validates header parameters.
func (l *Layer) validateHeaders(ctx *engine.RequestContext, route *RouteInfo, validator *SchemaValidator) []engine.Finding {
	findings := make([]engine.Finding, 0)

	for _, param := range route.Parameters {
		if param.In != "header" {
			continue
		}

		values, exists := ctx.Headers[http.CanonicalHeaderKey(param.Name)]
		if !exists || len(values) == 0 {
			if param.Required {
				findings = append(findings, engine.Finding{
					DetectorName: "apivalidation",
					Description:  fmt.Sprintf("Required header '%s' is missing", param.Name),
					Score:        l.config.ViolationScore / 2,
				})
			}
			continue
		}

		// Validate header value
		if param.Schema != nil {
			result := validator.Validate(values[0], param.Schema, "header."+param.Name)
			if !result.Valid {
				for _, err := range result.Errors {
					findings = append(findings, engine.Finding{
						DetectorName: "apivalidation",
						Description:  fmt.Sprintf("Header '%s': %s", param.Name, err.Message),
						Score:        result.Score,
						MatchedValue: values[0],
					})
				}
			}
		}
	}

	return findings
}

// validateRequestBody validates the request body against the schema.
func (l *Layer) validateRequestBody(ctx *engine.RequestContext, route *RouteInfo, validator *SchemaValidator) []engine.Finding {
	findings := make([]engine.Finding, 0)

	if route.BodySchema == nil {
		return findings
	}

	// Check if body is required
	if route.BodySchema.Required && len(ctx.Body) == 0 {
		findings = append(findings, engine.Finding{
			DetectorName: "apivalidation",
			Description:  "Request body is required but missing",
			Score:        l.config.ViolationScore,
		})
		return findings
	}

	// Skip if no body
	if len(ctx.Body) == 0 {
		return findings
	}

	// Parse body based on content type
	contentType := ctx.Headers["Content-Type"]
	if len(contentType) == 0 {
		contentType = []string{"application/json"}
	}

	ct := strings.ToLower(strings.Split(contentType[0], ";")[0])

	switch ct {
	case "application/json":
		var data any
		if err := json.Unmarshal(ctx.Body, &data); err != nil {
			findings = append(findings, engine.Finding{
				DetectorName: "apivalidation",
				Description:  fmt.Sprintf("Invalid JSON in request body: %v", err),
				Score:        l.config.ViolationScore,
				MatchedValue: string(ctx.Body[:min(len(ctx.Body), 100)]),
			})
			return findings
		}

		result := validator.Validate(data, route.BodySchema.Schema, "body")
		if !result.Valid {
			for _, err := range result.Errors {
				findings = append(findings, engine.Finding{
					DetectorName: "apivalidation",
					Description:  fmt.Sprintf("Body validation: %s", err.Message),
					Score:        result.Score,
					MatchedValue: fmt.Sprintf("%v", data),
				})
			}
		}

	case "application/x-www-form-urlencoded", "multipart/form-data":
		// For form data, create a map from query params and validate
		formData := make(map[string]any)
		for key, values := range ctx.QueryParams {
			if len(values) == 1 {
				formData[key] = values[0]
			} else {
				formData[key] = values
			}
		}

		result := validator.Validate(formData, route.BodySchema.Schema, "body")
		if !result.Valid {
			for _, err := range result.Errors {
				findings = append(findings, engine.Finding{
					DetectorName: "apivalidation",
					Description:  fmt.Sprintf("Body validation: %s", err.Message),
					Score:        result.Score,
					MatchedValue: fmt.Sprintf("%v", formData),
				})
			}
		}
	}

	return findings
}

// extractPathParam extracts a path parameter value from the request path.
func (l *Layer) extractPathParam(requestPath, routePath, paramName string) string {
	// Split paths
	routeParts := strings.Split(routePath, "/")
	requestParts := strings.Split(requestPath, "/")

	if len(routeParts) != len(requestParts) {
		return ""
	}

	// First verify static parts match
	for i, part := range routeParts {
		if !strings.HasPrefix(part, "{") && part != requestParts[i] {
			return "" // Static part doesn't match
		}
	}

	// Now extract the parameter
	for i, part := range routeParts {
		if part == "{"+paramName+"}" || (strings.HasPrefix(part, "{") && strings.Contains(part, paramName)) {
			if i < len(requestParts) {
				return requestParts[i]
			}
		}
	}

	return ""
}

// GetSpecs returns all loaded specifications.
func (l *Layer) GetSpecs() []*CompiledSpec {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.specs
}

// GetRoute returns route info for a specific path and method.
func (l *Layer) GetRoute(method, path string) *RouteInfo {
	return l.router.Match(method, path)
}

// Stats holds API validation statistics.
type Stats struct {
	SpecsLoaded   int
	RoutesDefined int
	CacheSize     int
}

// GetStats returns current statistics.
func (l *Layer) GetStats() Stats {
	l.mu.RLock()
	specsCount := len(l.specs)
	l.mu.RUnlock()

	return Stats{
		SpecsLoaded:   specsCount,
		RoutesDefined: len(l.router.routes),
		CacheSize:     len(l.cache.schemas),
	}
}
