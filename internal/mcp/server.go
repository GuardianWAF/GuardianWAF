// Package mcp implements a JSON-RPC 2.0 server for the Model Context Protocol (MCP).
// It provides tool-based access to GuardianWAF engine operations over stdio.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError holds a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// ToolHandler handles a single MCP tool invocation.
type ToolHandler func(params json.RawMessage) (interface{}, error)

// EngineInterface defines what the MCP server needs from the WAF engine.
// This interface avoids circular imports between the mcp and engine packages.
type EngineInterface interface {
	GetStats() interface{}
	GetConfig() interface{}
	GetMode() string
	SetMode(mode string) error
	AddWhitelist(ip string) error
	RemoveWhitelist(ip string) error
	AddBlacklist(ip string) error
	RemoveBlacklist(ip string) error
	AddRateLimit(rule interface{}) error
	RemoveRateLimit(id string) error
	AddExclusion(path string, detectors []string, reason string) error
	RemoveExclusion(path string) error
	GetEvents(params json.RawMessage) (interface{}, error)
	GetTopIPs(n int) interface{}
	GetDetectors() interface{}
	TestRequest(method, url string, headers map[string]string) (interface{}, error)
}

// Server is a JSON-RPC 2.0 MCP server that communicates over stdio.
type Server struct {
	mu     sync.Mutex
	reader *bufio.Reader
	writer io.Writer
	tools  map[string]ToolHandler
	engine EngineInterface

	serverName    string
	serverVersion string
}

// NewServer creates a new MCP server reading from reader and writing to writer.
func NewServer(reader io.Reader, writer io.Writer) *Server {
	return &Server{
		reader:        bufio.NewReader(reader),
		writer:        writer,
		tools:         make(map[string]ToolHandler),
		serverName:    "guardianwaf",
		serverVersion: "1.0.0",
	}
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
			s.sendError(nil, ErrCodeParseError, "Parse error", nil)
			continue
		}

		if req.JSONRPC != "2.0" {
			s.sendError(req.ID, ErrCodeInvalidRequest, "Invalid JSON-RPC version", nil)
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
		s.sendError(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method), nil)
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (s *Server) handleInitialize(req JSONRPCRequest) {
	s.mu.Lock()
	name := s.serverName
	ver := s.serverVersion
	s.mu.Unlock()

	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    name,
			"version": ver,
		},
	}
	s.sendResult(req.ID, result)
}

// handleToolsList returns the list of all registered tool definitions.
func (s *Server) handleToolsList(req JSONRPCRequest) {
	tools := AllTools()
	result := map[string]interface{}{
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
	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, ErrCodeInvalidParams, "Invalid params for tools/call", nil)
		return
	}

	s.mu.Lock()
	handler, ok := s.tools[params.Name]
	s.mu.Unlock()

	if !ok {
		s.sendError(req.ID, ErrCodeInvalidParams, fmt.Sprintf("Unknown tool: %s", params.Name), nil)
		return
	}

	result, err := handler(params.Arguments)
	if err != nil {
		// Return as tool error content, not JSON-RPC error
		s.sendResult(req.ID, map[string]interface{}{
			"content": []map[string]interface{}{
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
	s.sendResult(req.ID, map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": string(resultJSON),
			},
		},
	})
}

// sendResult writes a successful JSON-RPC response.
func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

// sendError writes an error JSON-RPC response.
func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.writeResponse(resp)
}

// writeResponse marshals and writes a JSON-RPC response followed by a newline.
func (s *Server) writeResponse(resp JSONRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	data = append(data, '\n')
	s.writer.Write(data)
}
