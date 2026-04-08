package discovery

import (
	"encoding/json"
	"fmt"
)

// OpenAPISpec represents an OpenAPI 3.0 specification.
type OpenAPISpec struct {
	OpenAPI string                 `json:"openapi"`
	Info    OpenAPIInfo            `json:"info"`
	Servers []OpenAPIServer        `json:"servers,omitempty"`
	Paths   map[string]PathItem    `json:"paths"`
}

// OpenAPIInfo contains API information.
type OpenAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version"`
	Contact     *Contact `json:"contact,omitempty"`
}

// Contact information.
type Contact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// OpenAPIServer represents a server.
type OpenAPIServer struct {
	URL         string            `json:"url"`
	Description string            `json:"description,omitempty"`
	Variables   map[string]any `json:"variables,omitempty"`
}

// PathItem represents a path item.
type PathItem struct {
	Summary     string      `json:"summary,omitempty"`
	Description string      `json:"description,omitempty"`
	Get         *Operation  `json:"get,omitempty"`
	Post        *Operation  `json:"post,omitempty"`
	Put         *Operation  `json:"put,omitempty"`
	Delete      *Operation  `json:"delete,omitempty"`
	Patch       *Operation  `json:"patch,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
}

// Operation represents an API operation.
type Operation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description,omitempty"`
	OperationID string              `json:"operationId"`
	Tags        []string            `json:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
}

// RequestBody represents a request body.
type RequestBody struct {
	Description string                `json:"description,omitempty"`
	Required    bool                  `json:"required,omitempty"`
	Content     map[string]MediaType  `json:"content"`
}

// MediaType represents a media type.
type MediaType struct {
	Schema Schema `json:"schema"`
}

// Schema represents an OpenAPI schema.
type Schema struct {
	Type        string            `json:"type,omitempty"`
	Format      string            `json:"format,omitempty"`
	Description string            `json:"description,omitempty"`
	Pattern     string            `json:"pattern,omitempty"`
	Enum        []string          `json:"enum,omitempty"`
	Required    []string          `json:"required,omitempty"`
	Properties  map[string]Schema `json:"properties,omitempty"`
	Items       *Schema           `json:"items,omitempty"`
	Example     any       `json:"example,omitempty"`
}

// Response represents an API response.
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// SchemaGenerator generates OpenAPI specifications.
type SchemaGenerator struct {
	info OpenAPIInfo
}

// NewSchemaGenerator creates a new schema generator.
func NewSchemaGenerator() *SchemaGenerator {
	return &SchemaGenerator{
		info: OpenAPIInfo{
			Title:       "Discovered API",
			Description: "API discovered by GuardianWAF",
			Version:     "1.0.0",
		},
	}
}

// SetInfo sets the API information.
func (g *SchemaGenerator) SetInfo(info OpenAPIInfo) {
	g.info = info
}

// Generate generates OpenAPI spec from inventory.
func (g *SchemaGenerator) Generate(inventory *Inventory) *OpenAPISpec {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info:    g.info,
		Paths:   make(map[string]PathItem),
	}

	for _, endpoint := range inventory.Endpoints {
		pathItem := g.endpointToPathItem(endpoint)
		spec.Paths[endpoint.Pattern] = pathItem
	}

	return spec
}

// endpointToPathItem converts an endpoint to a path item.
func (g *SchemaGenerator) endpointToPathItem(endpoint *Endpoint) PathItem {
	pathItem := PathItem{
		Summary:     fmt.Sprintf("%s operations", endpoint.Pattern),
		Description: g.generateDescription(endpoint),
	}

	// Convert methods to operations
	for _, method := range endpoint.Methods {
		op := g.methodToOperation(method, endpoint)
		switch method {
		case "GET":
			pathItem.Get = op
		case "POST":
			pathItem.Post = op
		case "PUT":
			pathItem.Put = op
		case "DELETE":
			pathItem.Delete = op
		case "PATCH":
			pathItem.Patch = op
		}
	}

	// Common parameters (path params)
	var commonParams []Parameter
	for _, param := range endpoint.Parameters {
		if param.In == "path" {
			commonParams = append(commonParams, param)
		}
	}
	if len(commonParams) > 0 {
		pathItem.Parameters = commonParams
	}

	return pathItem
}

// methodToOperation converts a method/endpoint to an operation.
func (g *SchemaGenerator) methodToOperation(method string, endpoint *Endpoint) *Operation {
	op := &Operation{
		Summary:     fmt.Sprintf("%s %s", method, endpoint.Pattern),
		OperationID: fmt.Sprintf("%s_%s", sanitizeOperationID(endpoint.Pattern), method),
		Tags:        endpoint.Tags,
		Responses:   g.generateResponses(endpoint),
	}

	// Add query parameters
	for _, param := range endpoint.Parameters {
		if param.In == "query" {
			op.Parameters = append(op.Parameters, param)
		}
	}

	// Add request body for POST/PUT/PATCH
	if method == "POST" || method == "PUT" || method == "PATCH" {
		op.RequestBody = g.generateRequestBody(endpoint)
	}

	return op
}

// generateDescription generates a description for an endpoint.
func (g *SchemaGenerator) generateDescription(endpoint *Endpoint) string {
	desc := fmt.Sprintf("Discovered endpoint: %s\n\n", endpoint.Pattern)
	desc += fmt.Sprintf("- Methods: %v\n", endpoint.Methods)
	desc += fmt.Sprintf("- Total requests: %d\n", endpoint.Count)
	desc += fmt.Sprintf("- First seen: %s\n", endpoint.FirstSeen.Format("YYYY-MM-DD"))

	if len(endpoint.Tags) > 0 {
		desc += fmt.Sprintf("\nTags: %v", endpoint.Tags)
	}

	return desc
}

// generateResponses generates response definitions.
func (g *SchemaGenerator) generateResponses(endpoint *Endpoint) map[string]Response {
	responses := make(map[string]Response)

	// Add discovered status codes
	for codeStr := range endpoint.StatusCodes {
		code := codeStr
		desc := g.getStatusCodeDescription(code)
		responses[code] = Response{
			Description: desc,
		}
	}

	// Ensure we have at least 200
	if _, ok := responses["200"]; !ok {
		responses["200"] = Response{
			Description: "Success",
		}
	}

	return responses
}

// generateRequestBody generates request body definition.
func (g *SchemaGenerator) generateRequestBody(endpoint *Endpoint) *RequestBody {
	// Simple schema based on endpoint tags
	schema := Schema{
		Type: "object",
	}

	// Add example properties based on endpoint pattern
	if contains(endpoint.Pattern, "user") {
		schema.Properties = map[string]Schema{
			"name":  {Type: "string"},
			"email": {Type: "string", Format: "email"},
		}
		schema.Required = []string{"name", "email"}
	}

	return &RequestBody{
		Description: "Request body",
		Required:    true,
		Content: map[string]MediaType{
			"application/json": {Schema: schema},
		},
	}
}

// parameterToOpenAPI converts a Parameter to OpenAPI format.
func parameterToOpenAPI(param Parameter) Parameter {
	// Already in correct format
	return param
}

// schemaForType creates a schema for a data type.
func schemaForType(dataType string) Schema {
	switch dataType {
	case "integer":
		return Schema{Type: "integer"}
	case "number":
		return Schema{Type: "number"}
	case "boolean":
		return Schema{Type: "boolean"}
	case "array":
		return Schema{Type: "array", Items: &Schema{Type: "string"}}
	case "object":
		return Schema{Type: "object"}
	default:
		return Schema{Type: "string"}
	}
}

// Helper functions

func sanitizeOperationID(pattern string) string {
	// Replace special characters with underscores
	result := ""
	for _, c := range pattern {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result += string(c)
		} else {
			result += "_"
		}
	}
	return result
}

func (g *SchemaGenerator) getStatusCodeDescription(code string) string {
	descriptions := map[string]string{
		"200": "OK",
		"201": "Created",
		"204": "No Content",
		"400": "Bad Request",
		"401": "Unauthorized",
		"403": "Forbidden",
		"404": "Not Found",
		"500": "Internal Server Error",
	}

	if desc, ok := descriptions[code]; ok {
		return desc
	}
	return fmt.Sprintf("Status %s", code)
}

func contains(s, substr string) bool {
	return findSubstring(s, substr) >= 0
}

func findSubstring(s, substr string) int {
	// Simple substring search
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// ToJSON serializes the OpenAPI spec to JSON.
func (s *OpenAPISpec) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
