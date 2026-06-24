// Package mcp implements a JSON-RPC 2.0 server for the Model Context Protocol (MCP).
// It provides tool-based access to GuardianWAF engine operations over stdio.
package mcp

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/logging"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError holds a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
	ErrCodeUnauthorized   = -32001 // Authentication required
)

// ToolHandler handles a single MCP tool invocation.
type ToolHandler func(params json.RawMessage) (any, error)

// AuditContext carries transport authentication metadata for structured audit logs.
// It intentionally excludes credentials and tool arguments.
type AuditContext struct {
	Transport  string
	AuthType   string
	Principal  string
	RemoteAddr string
}

// EngineInterface defines what the MCP server needs from the WAF engine.
// This interface avoids circular imports between the mcp and engine packages.
type EngineInterface interface {
	GetStats() any
	GetConfig() any
	GetMode() string
	SetMode(mode string) error
	AddWhitelist(ip string) error
	RemoveWhitelist(ip string) error
	AddBlacklist(ip string) error
	RemoveBlacklist(ip string) error
	AddRateLimit(rule any) error
	RemoveRateLimit(id string) error
	AddExclusion(path string, detectors []string, reason string) error
	RemoveExclusion(path string) error
	GetEvents(params json.RawMessage) (any, error)
	GetTopIPs(n int) any
	GetDetectors() any
	TestRequest(method, url string, headers map[string]string) (any, error)
	// Alerting management
	GetAlertingStatus() any
	AddWebhook(name, url, webhookType string, events []string, minScore int, cooldown string) error
	RemoveWebhook(name string) error
	AddEmailTarget(name, smtpHost string, smtpPort int, username, password, from string, to []string, useTLS bool, events []string, minScore int) error
	RemoveEmailTarget(name string) error
	TestAlert(target string) error
	// CRS management
	GetCRSRules(phase int, severity string) (any, error)
	EnableCRSRule(ruleID string, enabled bool) error
	SetParanoiaLevel(level int) error
	AddCRSExclusion(ruleID, path, parameter, reason string) error
	// Virtual Patch management
	GetVirtualPatches(severity string, activeOnly bool) (any, error)
	EnableVirtualPatch(patchID string, enabled bool) error
	AddCustomPatch(id, name, description, cveID, pattern, patternType, target, action, severity string, score int) error
	UpdateCVEDatabase() error
	// API Validation management
	GetAPISchemas() (any, error)
	UploadAPISchema(name, content, format string, strictMode bool) error
	RemoveAPISchema(name string) error
	SetAPIValidationMode(validateRequest, validateResponse, strictMode, blockOnViolation *bool) error
	TestAPISchema(method, path, body string) (any, error)
	// Client-Side Protection management
	GetClientSideStats() (any, error)
	SetClientSideMode(mode string, magecartDetection, agentInjection, cspEnabled *bool) error
	AddSkimmingDomain(domain string) error
	GetCSPReports(limit int) (any, error)
	// DLP management
	GetDLPAlerts(limit int, patternType string) (any, error)
	AddDLPPattern(id, name, pattern, description, action string, score int) error
	RemoveDLPPattern(id string) error
	TestDLPPattern(pattern, testData string) (any, error)
	// HTTP/3 management
	GetHTTP3Status() (any, error)
	SetHTTP3Config(enabled, enable0RTT, advertiseAltSvc *bool) error
}

// Server is a JSON-RPC 2.0 MCP server that communicates over stdio.
type Server struct {
	mu            sync.Mutex
	reader        *bufio.Reader
	writer        io.Writer
	tools         map[string]ToolHandler
	engine        EngineInterface
	apiKey        string
	authenticated bool // true once client sends valid api_key in initialize

	serverName    string
	serverVersion string
	log           *slog.Logger
}

// SetAPIKey sets the API key required for MCP server authentication.
// When set, all tool calls must include the key in the initialize request.
// Empty string disables authentication (default for stdio transport).
func (s *Server) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKey = key
}

func (s *Server) isAuthenticated(key string) bool {
	if s.apiKey == "" {
		return true // No auth required when no key is set
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) == 1
}

func (s *Server) checkAuth() bool {
	s.mu.Lock()
	authenticated := s.authenticated
	s.mu.Unlock()
	return authenticated
}

func (s *Server) markAuthenticated() {
	s.mu.Lock()
	s.authenticated = true
	s.mu.Unlock()
}

// NewServer creates a new MCP server. Pass nil reader/writer for SSE-only mode.
func NewServer(reader io.Reader, writer io.Writer) *Server {
	s := &Server{
		writer:        writer,
		tools:         make(map[string]ToolHandler),
		serverName:    "guardianwaf",
		serverVersion: "1.0.0",
		log:           logging.NewLogger("mcp"),
	}
	if reader != nil {
		s.reader = bufio.NewReader(reader)
	}
	return s
}

// SetEngine sets the engine interface for tool handlers.
func (s *Server) SetEngine(eng EngineInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engine = eng
}

// SetServerInfo sets the server name and version returned during initialization.
func (s *Server) SetServerInfo(name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverName = name
	s.serverVersion = version
}

// RegisterTool registers a tool handler by name.
func (s *Server) RegisterTool(name string, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[name] = handler
}

// ToolCount returns the number of registered tools.
func (s *Server) ToolCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tools)
}

// ValidateTools verifies that the set of registered tool handlers exactly
// matches the set of advertised tool definitions in AllTools(). Tool names are
// declared twice — in AllTools() (the schema clients discover) and in
// RegisterAllTools() (the handler wiring) — so a typo in either place silently
// breaks a tool. Calling this in a test catches that drift at build time.
func (s *Server) ValidateTools() error {
	defined := make(map[string]bool)
	for _, t := range AllTools() {
		defined[t.Name] = true
	}

	s.mu.Lock()
	registered := make(map[string]bool, len(s.tools))
	for name := range s.tools {
		registered[name] = true
	}
	s.mu.Unlock()

	var missingHandler, missingDef []string
	for name := range defined {
		if !registered[name] {
			missingHandler = append(missingHandler, name)
		}
	}
	for name := range registered {
		if !defined[name] {
			missingDef = append(missingDef, name)
		}
	}
	if len(missingHandler) == 0 && len(missingDef) == 0 {
		return nil
	}
	sort.Strings(missingHandler)
	sort.Strings(missingDef)
	return fmt.Errorf("MCP tool drift: defined-but-not-registered=%v registered-but-not-defined=%v", missingHandler, missingDef)
}

// Run starts the server loop, reading JSON-RPC requests line-by-line from
// the reader and writing responses to the writer. It returns when the reader
// reaches EOF or encounters an unrecoverable read error.
func (s *Server) Run() error {
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Skip empty lines
		if len(line) == 0 || (len(line) == 1 && line[0] == '\n') {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, ErrCodeParseError, "Parse error")
			continue
		}

		if req.JSONRPC != "2.0" {
			s.sendError(req.ID, ErrCodeInvalidRequest, "Invalid JSON-RPC version")
			continue
		}

		s.handleRequest(req)
	}
}

// handleRequest dispatches a parsed JSON-RPC request to the appropriate handler.
func (s *Server) handleRequest(req JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// Acknowledgment notification — no response needed
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	default:
		s.sendError(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// handleInitialize responds to the MCP initialize handshake.
// It also authenticates the client when api_key is provided in params.
func (s *Server) handleInitialize(req JSONRPCRequest) {
	s.mu.Lock()
	name := s.serverName
	ver := s.serverVersion
	s.mu.Unlock()

	// Check if authentication is required
	if s.apiKey != "" && !s.checkAuth() {
		// Try to authenticate from params
		var initParams map[string]any
		if req.Params != nil {
			_ = json.Unmarshal(req.Params, &initParams)
		}
		if apiKey, ok := initParams["api_key"].(string); ok && s.isAuthenticated(apiKey) {
			s.markAuthenticated()
		} else {
			s.sendError(req.ID, ErrCodeUnauthorized, "authentication required: provide api_key in initialize params")
			return
		}
	}

	result := map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    name,
			"version": ver,
		},
	}
	s.sendResult(req.ID, result)
}

// handleToolsList returns the list of all registered tool definitions.
func (s *Server) handleToolsList(req JSONRPCRequest) {
	tools := AllTools()
	result := map[string]any{
		"tools": tools,
	}
	s.sendResult(req.ID, result)
}

// toolsCallParams holds the parsed parameters for a tools/call request.
type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

var mutatingMCPTools = map[string]struct{}{
	"guardianwaf_add_whitelist":           {},
	"guardianwaf_remove_whitelist":        {},
	"guardianwaf_add_blacklist":           {},
	"guardianwaf_remove_blacklist":        {},
	"guardianwaf_add_ratelimit":           {},
	"guardianwaf_remove_ratelimit":        {},
	"guardianwaf_add_exclusion":           {},
	"guardianwaf_remove_exclusion":        {},
	"guardianwaf_set_mode":                {},
	"guardianwaf_add_webhook":             {},
	"guardianwaf_remove_webhook":          {},
	"guardianwaf_add_email_target":        {},
	"guardianwaf_remove_email_target":     {},
	"guardianwaf_test_alert":              {},
	"guardianwaf_enable_crs_rule":         {},
	"guardianwaf_set_paranoia_level":      {},
	"guardianwaf_add_crs_exclusion":       {},
	"guardianwaf_enable_virtual_patch":    {},
	"guardianwaf_add_custom_patch":        {},
	"guardianwaf_update_cve_database":     {},
	"guardianwaf_upload_api_schema":       {},
	"guardianwaf_remove_api_schema":       {},
	"guardianwaf_set_api_validation_mode": {},
	"guardianwaf_set_clientside_mode":     {},
	"guardianwaf_add_skimming_domain":     {},
	"guardianwaf_add_dlp_pattern":         {},
	"guardianwaf_remove_dlp_pattern":      {},
	"guardianwaf_set_http3_config":        {},
}

func isMutatingMCPTool(name string) bool {
	_, ok := mutatingMCPTools[name]
	return ok
}

func (s *Server) auditToolCall(name, outcome string, ctx *AuditContext) {
	if !isMutatingMCPTool(name) {
		return
	}
	attrs := []any{"tool", name, "outcome", outcome}
	if ctx != nil {
		if ctx.Transport != "" {
			attrs = append(attrs, "transport", ctx.Transport)
		}
		if ctx.AuthType != "" {
			attrs = append(attrs, "auth_type", ctx.AuthType)
		}
		if ctx.Principal != "" {
			attrs = append(attrs, "principal", ctx.Principal)
		}
		if ctx.RemoteAddr != "" {
			attrs = append(attrs, "remote_addr", ctx.RemoteAddr)
		}
	}
	s.log.Info("MCP mutating tool call", attrs...)
}

// handleToolsCall dispatches a tools/call request to the registered handler.
func (s *Server) handleToolsCall(req JSONRPCRequest) {
	// Reject tool calls if authentication is required but client is not authenticated
	if s.apiKey != "" && !s.checkAuth() {
		s.sendError(req.ID, ErrCodeUnauthorized, "authentication required: call initialize first with api_key")
		return
	}

	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, ErrCodeInvalidParams, "Invalid params for tools/call")
		return
	}

	s.mu.Lock()
	handler, ok := s.tools[params.Name]
	s.mu.Unlock()

	if !ok {
		s.sendError(req.ID, ErrCodeInvalidParams, fmt.Sprintf("Unknown tool: %s", params.Name))
		return
	}

	result, err := handler(params.Arguments)
	if err != nil {
		s.auditToolCall(params.Name, "error", &AuditContext{Transport: "stdio"})
		// Return as tool error content, not JSON-RPC error
		s.sendResult(req.ID, map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": fmt.Sprintf("Error: %v", err),
				},
			},
			"isError": true,
		})
		return
	}
	s.auditToolCall(params.Name, "success", &AuditContext{Transport: "stdio"})

	// Marshal result to text for MCP content
	resultJSON, _ := json.Marshal(result)
	s.sendResult(req.ID, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": string(resultJSON),
			},
		},
	})
}

// sendResult writes a successful JSON-RPC response.
func (s *Server) sendResult(id, result any) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

// sendError writes an error JSON-RPC response.
func (s *Server) sendError(id any, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	s.writeResponse(resp)
}

// writeResponse marshals and writes a JSON-RPC response followed by a newline.
func (s *Server) writeResponse(resp JSONRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer == nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if _, err := s.writer.Write(data); err != nil {
		s.log.Warn("failed to write response", "error", err)
	}
}

// HandleRequestJSON processes a JSON-RPC request and returns the response.
// Thread-safe — uses a per-request buffer instead of swapping the server writer.
func (s *Server) HandleRequestJSON(reqData []byte) ([]byte, error) {
	return s.HandleRequestJSONWithAuditContext(reqData, nil)
}

// HandleRequestJSONWithAuditContext processes a JSON-RPC request with transport
// metadata available to mutating-tool audit logs.
func (s *Server) HandleRequestJSONWithAuditContext(reqData []byte, auditCtx *AuditContext) ([]byte, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		resp := JSONRPCResponse{JSONRPC: "2.0", Error: &RPCError{Code: ErrCodeParseError, Message: "Parse error"}}
		return json.Marshal(resp)
	}
	if req.JSONRPC != "2.0" {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: ErrCodeInvalidRequest, Message: "Invalid JSON-RPC version"}}
		return json.Marshal(resp)
	}

	resp := s.processRequestWithAuditContext(req, auditCtx)
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// processRequest handles a JSON-RPC request and returns the response directly.
// Used by HandleRequestJSON for thread-safe per-request response handling.
func (s *Server) processRequest(req JSONRPCRequest) JSONRPCResponse {
	return s.processRequestWithAuditContext(req, nil)
}

func (s *Server) processRequestWithAuditContext(req JSONRPCRequest, auditCtx *AuditContext) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		s.mu.Lock()
		name := s.serverName
		ver := s.serverVersion
		s.mu.Unlock()
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": name, "version": ver},
			},
		}
	case "notifications/initialized":
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	case "tools/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"tools": AllTools()},
		}
	case "tools/call":
		s.mu.Lock()
		authed := s.authenticated
		apiKey := s.apiKey
		s.mu.Unlock()
		if apiKey != "" && !authed {
			return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: ErrCodeUnauthorized, Message: "authentication required"}}
		}
		return s.processToolsCall(req, auditCtx)
	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: ErrCodeMethodNotFound, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

// processToolsCall handles a tools/call request and returns a response directly.
func (s *Server) processToolsCall(req JSONRPCRequest, auditCtx *AuditContext) JSONRPCResponse {
	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: ErrCodeInvalidParams, Message: "Invalid params for tools/call"}}
	}

	s.mu.Lock()
	handler, ok := s.tools[params.Name]
	s.mu.Unlock()

	if !ok {
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: ErrCodeInvalidParams, Message: fmt.Sprintf("Unknown tool: %s", params.Name)}}
	}

	result, err := handler(params.Arguments)
	if err != nil {
		s.auditToolCall(params.Name, "error", auditCtx)
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("Error: %v", err)}},
				"isError": true,
			},
		}
	}
	s.auditToolCall(params.Name, "success", auditCtx)

	resultJSON, _ := json.Marshal(result)
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(resultJSON)}},
		},
	}
}
