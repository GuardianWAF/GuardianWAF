package main

import (
	"fmt"
	"io"
	"os"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/mcp"
)

// startMCPServer starts the MCP JSON-RPC server over stdio.
// It runs in a goroutine and blocks until stdin is closed.
func startMCPServer(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, stdin io.Reader, stdout io.Writer) {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	mcpSrv := mcp.NewServer(stdin, stdout)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(&mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store, alertMgr: alertMgr})
	mcpSrv.RegisterAllTools()
	if cfg.Dashboard.APIKey != "" {
		mcpSrv.SetAPIKey(cfg.Dashboard.APIKey)
	}

	if err := mcpSrv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
	}
}

func startMCPStdioRuntime(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, stdin io.Reader, stdout io.Writer) bool {
	if cfg == nil || !cfg.MCP.Enabled || cfg.MCP.Transport != "stdio" {
		return false
	}
	go startMCPServer(eng, cfg, store, alertMgr, stdin, stdout)
	return true
}

func buildMCPSSEHandler(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, apiKeyProvider ...func() string) *mcp.SSEHandler {
	mcpSrv := mcp.NewServer(nil, nil)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(&mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store, alertMgr: alertMgr})
	mcpSrv.RegisterAllTools()
	if len(apiKeyProvider) > 0 && apiKeyProvider[0] != nil {
		return mcp.NewSSEHandlerWithAPIKeyProvider(mcpSrv, apiKeyProvider[0])
	}
	return mcp.NewSSEHandler(mcpSrv, cfg.Dashboard.APIKey)
}
