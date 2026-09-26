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

// newMCPAdapter constructs the engine adapter with persistence wired when the
// operator's config path is known: config-mutating MCP tools then survive a
// restart (the round-74 persistence contract shared with the dashboard's
// config-mutating handlers).
func newMCPAdapter(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, cfgPath string) *mcpEngineAdapter {
	a := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store, alertMgr: alertMgr}
	if cfgPath != "" {
		a.persistFn = func() error { return config.SaveFile(cfgPath, eng.Config()) }
	}
	return a
}

// startMCPServer starts the MCP JSON-RPC server over stdio.
// It runs in a goroutine and blocks until stdin is closed.
func startMCPServer(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, stdin io.Reader, stdout io.Writer, cfgPath string) {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	mcpSrv := mcp.NewServer(stdin, stdout)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(newMCPAdapter(eng, cfg, store, alertMgr, cfgPath))
	mcpSrv.RegisterAllTools()
	if cfg.Dashboard.APIKey != "" {
		mcpSrv.SetAPIKey(cfg.Dashboard.APIKey)
	}

	if err := mcpSrv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
	}
}

func startMCPStdioRuntime(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, stdin io.Reader, stdout io.Writer, cfgPath string) bool {
	if cfg == nil || !cfg.MCP.Enabled || cfg.MCP.Transport != "stdio" {
		return false
	}
	go startMCPServer(eng, cfg, store, alertMgr, stdin, stdout, cfgPath)
	return true
}

func buildMCPSSEHandler(eng *engine.Engine, cfg *config.Config, store events.EventStore, alertMgr *alerting.Manager, cfgPath string, apiKeyProvider ...func() string) *mcp.SSEHandler {
	mcpSrv := mcp.NewServer(nil, nil)
	mcpSrv.SetServerInfo("guardianwaf", version)
	mcpSrv.SetEngine(newMCPAdapter(eng, cfg, store, alertMgr, cfgPath))
	mcpSrv.RegisterAllTools()
	if len(apiKeyProvider) > 0 && apiKeyProvider[0] != nil {
		return mcp.NewSSEHandlerWithAPIKeyProvider(mcpSrv, apiKeyProvider[0])
	}
	return mcp.NewSSEHandler(mcpSrv, cfg.Dashboard.APIKey)
}
