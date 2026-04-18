// Package mcp implements a JSON-RPC 2.0 server for the Model Context Protocol (MCP).
// It provides tool-based access to GuardianWAF engine operations over stdio.
package mcp

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
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
	mu           sync.Mutex
	reader       *bufio.Reader
	writer       io.Writer
	tools        map[string]ToolHandler
	engine       EngineInterface
	apiKey       string
	authenticated bool // true once client sends valid api_key in initialize

	serverName    string
	serverVersion string
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
		log.Printf("[mcp] warning: failed to write response: %v", err)
	}
}

// HandleRequestJSON processes a JSON-RPC request and returns the response.
// Thread-safe — uses a per-request buffer instead of swapping the server writer.
func (s *Server) HandleRequestJSON(reqData []byte) ([]byte, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		resp := JSONRPCResponse{JSONRPC: "2.0", Error: &RPCError{Code: ErrCodeParseError, Message: "Parse error"}}
		return json.Marshal(resp)
	}
	if req.JSONRPC != "2.0" {
		resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: ErrCodeInvalidRequest, Message: "Invalid JSON-RPC version"}}
		return json.Marshal(resp)
	}

	resp := s.processRequest(req)
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// processRequest handles a JSON-RPC request and returns the response directly.
// Used by HandleRequestJSON for thread-safe per-request response handling.
func (s *Server) processRequest(req JSONRPCRequest) JSONRPCResponse {
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
				"capabilities":   map[string]any{"tools": map[string]any{}},
				"serverInfo":     map[string]any{"name": name, "version": ver},
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
		return s.processToolsCall(req)
	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: ErrCodeMethodNotFound, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

// processToolsCall handles a tools/call request and returns a response directly.
func (s *Server) processToolsCall(req JSONRPCRequest) JSONRPCResponse {
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
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("Error: %v", err)}},
				"isError": true,
			},
		}
	}

	resultJSON, _ := json.Marshal(result)
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(resultJSON)}},
		},
	}
}
