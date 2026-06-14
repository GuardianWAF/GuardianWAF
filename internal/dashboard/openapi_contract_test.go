package dashboard

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestDashboardUIAPIPathsAreDocumentedInOpenAPI(t *testing.T) {
	openAPIPaths := readOpenAPIPaths(t)
	uiPaths := readDashboardUIAPIPaths(t)

	var missing []string
	for path := range uiPaths {
		if !openAPIHasEquivalentPath(openAPIPaths, path) {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API paths missing from docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUIAPIMethodsAreDocumentedInOpenAPI(t *testing.T) {
	openAPIOperations := readOpenAPIOperations(t)
	uiOperations := readDashboardUIAPIOperations(t)
	requireOperationCoverage(t, "UI API operations", uiOperations, 45)

	var missing []string
	for operation := range uiOperations {
		if !openAPIHasEquivalentOperation(openAPIOperations, operation) {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations missing from docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUIMutatingRequestBodiesAreDocumentedInOpenAPI(t *testing.T) {
	openAPIRequestBodies := readOpenAPIRequestBodyOperations(t)
	uiRequestBodies := readDashboardUIAPIRequestBodyOperations(t)
	requireOperationCoverage(t, "UI JSON request-body operations", uiRequestBodies, 15)

	var missing []string
	for operation := range uiRequestBodies {
		if !openAPIHasEquivalentOperation(openAPIRequestBodies, operation) {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations with JSON request bodies missing requestBody in docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUIApiResultResponsesAreDocumentedInOpenAPI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	openAPI := string(raw)
	uiApiResultOperations := readDashboardUIApiResultOperations(t)
	requireOperationCoverage(t, "UI ApiResult operations", uiApiResultOperations, 10)

	var missing []string
	for operation := range uiApiResultOperations {
		block := openAPIEquivalentOperationBlock(openAPI, operation)
		if block == "" {
			missing = append(missing, operation.Method+" "+operation.Path+" (operation missing)")
			continue
		}
		if !strings.Contains(block, "$ref: '#/components/schemas/ApiResult'") {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations returning ApiResult missing ApiResult response schema in docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUITypedResponsesHaveOpenAPISchemas(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	openAPI := string(raw)
	uiTypedResponseOperations := readDashboardUITypedResponseOperations(t)
	requireOperationCoverage(t, "UI typed response operations", uiTypedResponseOperations, 35)

	var missing []string
	for operation := range uiTypedResponseOperations {
		block := openAPIEquivalentOperationBlock(openAPI, operation)
		if block == "" {
			missing = append(missing, operation.Method+" "+operation.Path+" (operation missing)")
			continue
		}
		if !openAPIOperationHas2xxResponseSchema(block) {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations with typed responses missing 2xx response schema in docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUIMutatingRequestBodiesUseJSONSchemas(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	openAPI := string(raw)
	uiRequestBodies := readDashboardUIAPIRequestBodyOperations(t)
	requireOperationCoverage(t, "UI JSON request-body operations", uiRequestBodies, 15)

	var missing []string
	for operation := range uiRequestBodies {
		block := openAPIEquivalentOperationBlock(openAPI, operation)
		if block == "" {
			missing = append(missing, operation.Method+" "+operation.Path+" (operation missing)")
			continue
		}
		if !openAPIOperationHasJSONRequestSchema(block) {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations with JSON request bodies missing application/json request schema in docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUIResponseSchemasUseJSONContent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	openAPI := string(raw)
	uiTypedResponseOperations := readDashboardUITypedResponseOperations(t)
	requireOperationCoverage(t, "UI typed response operations", uiTypedResponseOperations, 35)

	var missing []string
	for operation := range uiTypedResponseOperations {
		block := openAPIEquivalentOperationBlock(openAPI, operation)
		if block == "" {
			missing = append(missing, operation.Method+" "+operation.Path+" (operation missing)")
			continue
		}
		if !openAPIOperationHas2xxJSONResponseSchema(block) {
			missing = append(missing, operation.Method+" "+operation.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("UI API operations with typed JSON responses missing application/json 2xx response schema in docs/openapi.yaml: %s", strings.Join(missing, ", "))
	}
}

func TestDashboardUICoreResponseShapesAreDocumentedInOpenAPI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	openAPI := string(raw)

	assertOpenAPIPathContains(t, openAPI, "/api/v1/stats", []string{
		"total_requests:",
		"blocked_requests:",
		"challenged_requests:",
		"logged_requests:",
		"passed_requests:",
		"event_store_errors:",
		"avg_latency_us:",
		"alerting:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/events", []string{
		"type: object",
		"events:",
		"$ref: '#/components/schemas/WafEvent'",
		"total:",
		"limit:",
		"offset:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/config", []string{
		"$ref: '#/components/schemas/WafConfigResponse'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/routing", []string{
		"$ref: '#/components/schemas/RoutingConfig'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/upstreams", []string{
		"type: array",
		"$ref: '#/components/schemas/UpstreamStatus'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ssl", []string{
		"$ref: '#/components/schemas/SSLStatus'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/logs", []string{
		"type: object",
		"logs:",
		"time:",
		"level:",
		"message:",
		"total:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ipacl", []string{
		"$ref: '#/components/schemas/IPACLResponse'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/bans", []string{
		"bans:",
		"$ref: '#/components/schemas/BanEntry'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/rules", []string{
		"rules:",
		"$ref: '#/components/schemas/CustomRule'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/rules/{id}", []string{
		"$ref: '#/components/schemas/CustomRule'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/geoip/lookup", []string{
		"$ref: '#/components/schemas/GeoIPResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/alerting/status", []string{
		"$ref: '#/components/schemas/AlertingStatusResponse'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/alerting/webhooks", []string{
		"webhooks:",
		"$ref: '#/components/schemas/WebhookTarget'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/alerting/emails", []string{
		"emails:",
		"$ref: '#/components/schemas/EmailTarget'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/alerting/test", []string{
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/clusters", []string{
		"type: array",
		"$ref: '#/components/schemas/Cluster'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/nodes", []string{
		"type: array",
		"$ref: '#/components/schemas/ClusterNode'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/sync/stats", []string{
		"$ref: '#/components/schemas/SyncStats'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/sync/status", []string{
		"$ref: '#/components/schemas/SyncStatusResponse'",
	})
	assertOpenAPISchemaContains(t, openAPI, "UpstreamStatus", []string{
		"name:",
		"strategy:",
		"targets:",
		"healthy_count:",
		"total_count:",
		"url:",
		"healthy:",
		"circuit_state:",
		"active_conns:",
		"weight:",
	})
	assertOpenAPISchemaContains(t, openAPI, "WafConfigResponse", []string{
		"mode:",
		"tls:",
		"waf:",
		"docker:",
		"ai_analysis:",
		"alerting:",
	})
	assertOpenAPISchemaContains(t, openAPI, "RoutingConfig", []string{
		"upstreams:",
		"virtual_hosts:",
		"routes:",
		"$ref: '#/components/schemas/UpstreamConfig'",
		"$ref: '#/components/schemas/VirtualHostConfig'",
		"$ref: '#/components/schemas/RouteConfig'",
	})
	assertOpenAPISchemaContains(t, openAPI, "SSLStatus", []string{
		"enabled:",
		"cache_dir:",
		"domains:",
		"certs:",
		"$ref: '#/components/schemas/SSLCertInfo'",
	})
	assertOpenAPISchemaContains(t, openAPI, "SSLCertInfo", []string{
		"domain:",
		"dns_names:",
		"not_after:",
		"days_left:",
		"issuer_cn:",
		"needs_renewal:",
		"is_wildcard:",
	})
	assertOpenAPISchemaContains(t, openAPI, "ApiResult", []string{
		"status:",
		"message:",
		"error:",
	})
	assertOpenAPISchemaNotContains(t, openAPI, "WafConfigResponse", []string{
		"api_key:",
		"admin_key:",
		"password:",
	})
	assertOpenAPISchemaContains(t, openAPI, "Cluster", []string{
		"id:",
		"name:",
		"description:",
		"nodes:",
		"sync_scope:",
		"created_at:",
	})
	assertOpenAPISchemaContains(t, openAPI, "ClusterNode", []string{
		"id:",
		"name:",
		"address:",
		"healthy:",
		"version:",
		"last_seen:",
		"is_local:",
	})
	assertOpenAPISchemaContains(t, openAPI, "SyncStats", []string{
		"total_events_sent:",
		"total_events_received:",
		"total_conflicts:",
		"total_resolved:",
		"active_connections:",
		"last_conflict_at:",
	})
	assertOpenAPISchemaContains(t, openAPI, "SyncStatusResponse", []string{
		"local_node:",
		"nodes:",
		"$ref: '#/components/schemas/ReplicationStatus'",
	})
	assertOpenAPISchemaContains(t, openAPI, "ReplicationStatus", []string{
		"node_id:",
		"last_replication:",
		"pending_events:",
		"failed_attempts:",
		"lag_ms:",
		"sync_status:",
	})
	assertOpenAPISchemaContains(t, openAPI, "CustomRule", []string{
		"id:",
		"name:",
		"enabled:",
		"priority:",
		"conditions:",
		"action:",
		"score:",
	})
	assertOpenAPISchemaContains(t, openAPI, "IPACLResponse", []string{
		"whitelist:",
		"blacklist:",
	})
	assertOpenAPISchemaContains(t, openAPI, "BanEntry", []string{
		"ip:",
		"reason:",
		"expires_at:",
		"count:",
	})
	assertOpenAPISchemaContains(t, openAPI, "GeoIPResult", []string{
		"ip:",
		"country:",
		"name:",
	})
	assertOpenAPISchemaContains(t, openAPI, "AlertingStatusResponse", []string{
		"enabled:",
		"webhook_count:",
		"email_count:",
		"webhooks:",
		"emails:",
	})
	assertOpenAPISchemaContains(t, openAPI, "WebhookTarget", []string{
		"name:",
		"url:",
		"type:",
		"events:",
		"min_score:",
		"cooldown:",
	})
	assertOpenAPISchemaContains(t, openAPI, "EmailTarget", []string{
		"name:",
		"smtp_host:",
		"smtp_port:",
		"from:",
		"to:",
		"use_tls:",
		"events:",
		"min_score:",
		"cooldown:",
	})
	assertOpenAPISchemaNotContains(t, openAPI, "EmailTarget", []string{"password:"})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/tenants", []string{
		"$ref: '#/components/schemas/Tenant'",
		"name:",
		"domains:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/tenants/usage", []string{
		"$ref: '#/components/schemas/TenantUsage'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/admin/tenants", []string{
		"tenants:",
		"$ref: '#/components/schemas/AdminTenant'",
		"count:",
		"enabled:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/admin/tenants/{id}", []string{
		"$ref: '#/components/schemas/AdminTenantDetail'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/admin/usage/{tenantID}", []string{
		"$ref: '#/components/schemas/TenantUsage'",
	})
	assertOpenAPISchemaContains(t, openAPI, "Tenant", []string{
		"id:",
		"name:",
		"active:",
		"domains:",
		"created_at:",
		"updated_at:",
		"quota:",
	})
	assertOpenAPISchemaContains(t, openAPI, "AdminTenantDetail", []string{
		"allOf:",
		"$ref: '#/components/schemas/AdminTenant'",
		"api_key:",
		"quota:",
	})
	assertOpenAPISchemaContains(t, openAPI, "TenantUsage", []string{
		"tenant_id:",
		"requests_per_minute:",
		"total_requests:",
		"quota_status:",
	})
	assertOpenAPISchemaNotContains(t, openAPI, "Tenant", []string{"api_key_hash:"})
	assertOpenAPISchemaNotContains(t, openAPI, "AdminTenant", []string{"api_key_hash:"})
	assertOpenAPISchemaNotContains(t, openAPI, "AdminTenantDetail", []string{"api_key_hash:"})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ai/providers", []string{
		"providers:",
		"$ref: '#/components/schemas/AIProviderSummary'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ai/config", []string{
		"$ref: '#/components/schemas/AIConfig'",
		"$ref: '#/components/schemas/ApiResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ai/history", []string{
		"history:",
		"$ref: '#/components/schemas/AIAnalysisResult'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/ai/stats", []string{
		"$ref: '#/components/schemas/AIStats'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/docker/services", []string{
		"enabled:",
		"services:",
		"$ref: '#/components/schemas/DockerService'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/docker/containers", []string{
		"enabled:",
		"containers:",
		"$ref: '#/components/schemas/DockerService'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/docker/events", []string{
		"enabled:",
		"events:",
		"$ref: '#/components/schemas/DockerEvent'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/compliance/controls", []string{
		"controls:",
		"$ref: '#/components/schemas/ComplianceControl'",
		"frameworks:",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/compliance/report/{framework}", []string{
		"$ref: '#/components/schemas/ComplianceReport'",
	})
	assertOpenAPIPathContains(t, openAPI, "/api/v1/compliance/audit-chain", []string{
		"$ref: '#/components/schemas/AuditChainResponse'",
	})
	assertOpenAPISchemaContains(t, openAPI, "AuditChainResponse", []string{
		"valid:",
		"length:",
		"errors:",
		"integrity:",
		"head_hash:",
	})
	assertOpenAPISchemaContains(t, openAPI, "AIProviderSummary", []string{
		"id:",
		"name:",
		"api:",
		"doc:",
		"model_count:",
		"models:",
	})
	assertOpenAPISchemaContains(t, openAPI, "AIConfig", []string{
		"enabled:",
		"provider_id:",
		"provider_name:",
		"model_id:",
		"model_name:",
		"base_url:",
		"api_key_set:",
		"api_key_mask:",
	})
	assertOpenAPISchemaContains(t, openAPI, "AIStats", []string{
		"tokens_used_hour:",
		"tokens_used_day:",
		"requests_hour:",
		"requests_day:",
		"total_cost_usd:",
	})
	assertOpenAPISchemaContains(t, openAPI, "DockerService", []string{
		"name:",
		"container_name:",
		"image:",
		"host:",
		"port:",
		"upstream:",
		"target:",
		"labels:",
	})
	assertOpenAPISchemaContains(t, openAPI, "ComplianceReport", []string{
		"report_id:",
		"generated_at:",
		"period:",
		"framework:",
		"summary:",
		"controls:",
	})
	assertOpenAPISchemaNotContains(t, openAPI, "AIConfig", []string{"api_key:"})
}

type apiOperation struct {
	Method string
	Path   string
}

func readOpenAPIPaths(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	re := regexp.MustCompile(`(?m)^  (/[^:]+):`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		paths = append(paths, match[1])
	}
	return paths
}

func assertOpenAPIPathContains(t *testing.T, openAPI, path string, required []string) {
	t.Helper()
	block := openAPIPathBlock(openAPI, path)
	if block == "" {
		t.Fatalf("docs/openapi.yaml missing path %s", path)
	}
	for _, want := range required {
		if !strings.Contains(block, want) {
			t.Fatalf("OpenAPI path %s missing response-shape token %q in:\n%s", path, want, block)
		}
	}
}

func assertOpenAPISchemaContains(t *testing.T, openAPI, schema string, required []string) {
	t.Helper()
	block := openAPISchemaBlock(openAPI, schema)
	if block == "" {
		t.Fatalf("docs/openapi.yaml missing schema %s", schema)
	}
	for _, want := range required {
		if !strings.Contains(block, want) {
			t.Fatalf("OpenAPI schema %s missing token %q in:\n%s", schema, want, block)
		}
	}
}

func assertOpenAPISchemaNotContains(t *testing.T, openAPI, schema string, forbidden []string) {
	t.Helper()
	block := openAPISchemaBlock(openAPI, schema)
	if block == "" {
		t.Fatalf("docs/openapi.yaml missing schema %s", schema)
	}
	for _, bad := range forbidden {
		if strings.Contains(block, bad) {
			t.Fatalf("OpenAPI schema %s includes forbidden token %q in:\n%s", schema, bad, block)
		}
	}
}

func openAPIPathBlock(openAPI, path string) string {
	startMarker := "  " + path + ":\n"
	start := strings.Index(openAPI, startMarker)
	if start < 0 {
		return ""
	}
	rest := openAPI[start+len(startMarker):]
	nextPath := regexp.MustCompile(`(?m)^  /[^:]+:\s*$`).FindStringIndex(rest)
	if nextPath == nil {
		return rest
	}
	return rest[:nextPath[0]]
}

func openAPISchemaBlock(openAPI, schema string) string {
	startMarker := "    " + schema + ":\n"
	start := strings.Index(openAPI, startMarker)
	if start < 0 {
		return ""
	}
	rest := openAPI[start+len(startMarker):]
	nextSchema := regexp.MustCompile(`(?m)^    [A-Za-z0-9_]+:\s*$`).FindStringIndex(rest)
	if nextSchema == nil {
		return rest
	}
	return rest[:nextSchema[0]]
}

func readOpenAPIOperations(t *testing.T) []apiOperation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	return readOpenAPIOperationsFromString(string(raw))
}

func readOpenAPIOperationsFromString(openAPI string) []apiOperation {
	var operations []apiOperation
	var currentPath string
	pathRe := regexp.MustCompile(`^  (/[^:]+):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|delete|patch):\s*$`)
	for _, line := range strings.Split(openAPI, "\n") {
		if match := pathRe.FindStringSubmatch(line); match != nil {
			currentPath = match[1]
			continue
		}
		if currentPath == "" {
			continue
		}
		if match := methodRe.FindStringSubmatch(line); match != nil {
			operations = append(operations, apiOperation{
				Method: strings.ToUpper(match[1]),
				Path:   currentPath,
			})
		}
	}
	return operations
}

func readOpenAPIRequestBodyOperations(t *testing.T) []apiOperation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi: %v", err)
	}
	var operations []apiOperation
	for _, operation := range readOpenAPIOperations(t) {
		block := openAPIOperationBlock(string(raw), operation)
		if strings.Contains(block, "\n      requestBody:") {
			operations = append(operations, operation)
		}
	}
	return operations
}

func openAPIOperationBlock(openAPI string, operation apiOperation) string {
	pathBlock := openAPIPathBlock(openAPI, operation.Path)
	if pathBlock == "" {
		return ""
	}
	startMarker := "    " + strings.ToLower(operation.Method) + ":\n"
	start := strings.Index(pathBlock, startMarker)
	if start < 0 {
		return ""
	}
	rest := pathBlock[start+len(startMarker):]
	nextOperation := regexp.MustCompile(`(?m)^    (get|post|put|delete|patch):\s*$`).FindStringIndex(rest)
	if nextOperation == nil {
		return rest
	}
	return rest[:nextOperation[0]]
}

func openAPIEquivalentOperationBlock(openAPI string, candidate apiOperation) string {
	for _, operation := range readOpenAPIOperationsFromString(openAPI) {
		if operation.Method == candidate.Method && equivalentPathTemplate(operation.Path, candidate.Path) {
			return openAPIOperationBlock(openAPI, operation)
		}
	}
	return ""
}

func openAPIOperationHas2xxResponseSchema(block string) bool {
	responseRe := regexp.MustCompile(`(?m)^        '2[0-9][0-9]':\s*$`)
	matches := responseRe.FindAllStringIndex(block, -1)
	for i, match := range matches {
		responseBlock := block[match[1]:]
		if i+1 < len(matches) {
			responseBlock = block[match[1]:matches[i+1][0]]
		}
		if strings.Contains(responseBlock, "\n              schema:") {
			return true
		}
	}
	return false
}

func openAPIOperationHas2xxJSONResponseSchema(block string) bool {
	for _, responseBlock := range openAPI2xxResponseBlocks(block) {
		if strings.Contains(responseBlock, "\n            application/json:") &&
			strings.Contains(responseBlock, "\n              schema:") {
			return true
		}
	}
	return false
}

func openAPI2xxResponseBlocks(block string) []string {
	responseRe := regexp.MustCompile(`(?m)^        '2[0-9][0-9]':\s*$`)
	matches := responseRe.FindAllStringIndex(block, -1)
	blocks := make([]string, 0, len(matches))
	for i, match := range matches {
		responseBlock := block[match[1]:]
		if i+1 < len(matches) {
			responseBlock = block[match[1]:matches[i+1][0]]
		}
		blocks = append(blocks, responseBlock)
	}
	return blocks
}

func openAPIOperationHasJSONRequestSchema(block string) bool {
	requestBody := openAPIOperationRequestBodyBlock(block)
	return strings.Contains(requestBody, "\n          application/json:") &&
		strings.Contains(requestBody, "\n            schema:")
}

func openAPIOperationRequestBodyBlock(block string) string {
	startMarker := "\n      requestBody:\n"
	start := strings.Index(block, startMarker)
	if start < 0 {
		return ""
	}
	rest := block[start+len(startMarker):]
	nextPeer := regexp.MustCompile(`(?m)^      (responses|parameters|security|tags|summary|description|operationId):`).FindStringIndex(rest)
	if nextPeer == nil {
		return rest
	}
	return rest[:nextPeer[0]]
}

func requireOperationCoverage(t *testing.T, label string, operations map[apiOperation]struct{}, minimum int) {
	t.Helper()
	if len(operations) < minimum {
		t.Fatalf("%s extraction found %d operations, want at least %d; update the OpenAPI contract extractor if UI API call patterns changed", label, len(operations), minimum)
	}
}

func readDashboardUIAPIPaths(t *testing.T) map[string]struct{} {
	t.Helper()
	root := filepath.Join("ui", "src")
	paths := make(map[string]struct{})
	re := regexp.MustCompile("[`'\"](/api[^`'\"\\s)]*)[`'\"]")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.Contains(path, ".test.") {
			return nil
		}
		if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range re.FindAllStringSubmatch(string(raw), -1) {
			normalized := normalizeUIAPIPath(match[1])
			if normalized != "" {
				paths[normalized] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard UI sources: %v", err)
	}
	return paths
}

func readDashboardUIAPIOperations(t *testing.T) map[apiOperation]struct{} {
	t.Helper()
	root := filepath.Join("ui", "src")
	operations := make(map[apiOperation]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(path, ".test.") {
			return nil
		}
		if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, operation := range extractUIAPIOperations(string(raw)) {
			operations[operation] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard UI sources: %v", err)
	}
	return operations
}

func readDashboardUIAPIRequestBodyOperations(t *testing.T) map[apiOperation]struct{} {
	t.Helper()
	root := filepath.Join("ui", "src")
	operations := make(map[apiOperation]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(path, ".test.") {
			return nil
		}
		if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, operation := range extractUIAPIRequestBodyOperations(string(raw)) {
			operations[operation] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard UI sources: %v", err)
	}
	return operations
}

func readDashboardUIApiResultOperations(t *testing.T) map[apiOperation]struct{} {
	t.Helper()
	root := filepath.Join("ui", "src")
	operations := make(map[apiOperation]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(path, ".test.") {
			return nil
		}
		if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, operation := range extractUIApiResultOperations(string(raw)) {
			operations[operation] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard UI sources: %v", err)
	}
	return operations
}

func readDashboardUITypedResponseOperations(t *testing.T) map[apiOperation]struct{} {
	t.Helper()
	root := filepath.Join("ui", "src")
	operations := make(map[apiOperation]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(path, ".test.") {
			return nil
		}
		if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, operation := range extractUITypedResponseOperations(string(raw)) {
			operations[operation] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard UI sources: %v", err)
	}
	return operations
}

func extractUIAPIOperations(source string) []apiOperation {
	var operations []apiOperation
	requestRe := regexp.MustCompile(`request<[^>]+>\((.*)`)
	eventSourceRe := regexp.MustCompile(`EventSource\(([^)\n]+)\)`)
	fetchRe := regexp.MustCompile(`fetch\([^+\n]*([` + "`" + `'\"])(/api/[^` + "`" + `'\"\s?)]*)[^)\n]*\)`)
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, match := range requestRe.FindAllStringSubmatch(trimmed, -1) {
			if operation, ok := operationFromRequestArgs(match[1]); ok {
				operations = append(operations, operation)
			}
		}
		for _, match := range eventSourceRe.FindAllStringSubmatch(trimmed, -1) {
			if path := normalizeUIAPIExpression(match[1]); path != "" {
				operations = append(operations, apiOperation{Method: "GET", Path: path})
			}
		}
		for _, match := range fetchRe.FindAllStringSubmatch(trimmed, -1) {
			if path := normalizeUIAPIPath(match[2]); path != "" {
				operations = append(operations, apiOperation{Method: inferFetchMethod(trimmed), Path: path})
			}
		}
	}
	return operations
}

func extractUITypedResponseOperations(source string) []apiOperation {
	var operations []apiOperation
	requestRe := regexp.MustCompile(`request<(.+)>\((.*)`)
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, match := range requestRe.FindAllStringSubmatch(trimmed, -1) {
			if strings.TrimSpace(match[1]) == "void" {
				continue
			}
			if operation, ok := operationFromRequestArgs(match[2]); ok {
				operations = append(operations, operation)
			}
		}
	}
	return operations
}

func extractUIApiResultOperations(source string) []apiOperation {
	var operations []apiOperation
	requestRe := regexp.MustCompile(`request<ApiResult>\((.*)`)
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, match := range requestRe.FindAllStringSubmatch(trimmed, -1) {
			if operation, ok := operationFromRequestArgs(match[1]); ok {
				operations = append(operations, operation)
			}
		}
	}
	return operations
}

func extractUIAPIRequestBodyOperations(source string) []apiOperation {
	var operations []apiOperation
	requestRe := regexp.MustCompile(`request<[^>]+>\((.*)`)
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, match := range requestRe.FindAllStringSubmatch(trimmed, -1) {
			if !strings.Contains(match[1], "body:") {
				continue
			}
			if operation, ok := operationFromRequestArgs(match[1]); ok {
				operations = append(operations, operation)
			}
		}
	}
	return operations
}

func operationFromRequestArgs(args string) (apiOperation, bool) {
	path := normalizeUIAPIExpression(args)
	if path == "" {
		return apiOperation{}, false
	}
	return apiOperation{
		Method: inferRequestMethod(args),
		Path:   path,
	}, true
}

func normalizeUIAPIExpression(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	return normalizeUIAPIPath(joinUIAPIExpressionLiterals(expr))
}

func joinUIAPIExpressionLiterals(expr string) string {
	literalRe := regexp.MustCompile("([`'\"])(/[^`'\"]*)[`'\"]")
	matches := literalRe.FindAllStringSubmatch(expr, -1)
	if len(matches) == 0 {
		return ""
	}
	var joined strings.Builder
	for i, match := range matches {
		literal := match[2]
		if i == 0 && !strings.HasPrefix(literal, "/api/") {
			return ""
		}
		if i > 0 && !strings.HasPrefix(literal, "/") && !strings.HasPrefix(literal, "?") {
			continue
		}
		if strings.HasPrefix(literal, "?") {
			break
		}
		joined.WriteString(literal)
		if strings.HasSuffix(literal, "/") {
			joined.WriteString("{param}")
		}
	}
	return joined.String()
}

func inferRequestMethod(args string) string {
	methodRe := regexp.MustCompile(`method:\s*['"]([A-Z]+)['"]`)
	if match := methodRe.FindStringSubmatch(args); match != nil {
		return match[1]
	}
	return "GET"
}

func inferFetchMethod(line string) string {
	methodRe := regexp.MustCompile(`method:\s*['"]([A-Z]+)['"]`)
	if match := methodRe.FindStringSubmatch(line); match != nil {
		return match[1]
	}
	return "GET"
}

func normalizeUIAPIPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/api/") {
		return ""
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if strings.HasSuffix(path, "/") {
		path += "{param}"
	}
	return path
}

func openAPIHasEquivalentPath(openAPIPaths []string, uiPath string) bool {
	for _, documented := range openAPIPaths {
		if equivalentPathTemplate(documented, uiPath) {
			return true
		}
	}
	return false
}

func openAPIHasEquivalentOperation(openAPIOperations []apiOperation, candidate apiOperation) bool {
	for _, documented := range openAPIOperations {
		if documented.Method == candidate.Method && equivalentPathTemplate(documented.Path, candidate.Path) {
			return true
		}
	}
	return false
}

func equivalentPathTemplate(documented, candidate string) bool {
	if documented == candidate {
		return true
	}
	docSegments := strings.Split(strings.Trim(documented, "/"), "/")
	candidateSegments := strings.Split(strings.Trim(candidate, "/"), "/")
	if len(docSegments) != len(candidateSegments) {
		return false
	}
	for i := range docSegments {
		if isPathParam(docSegments[i]) || isPathParam(candidateSegments[i]) {
			continue
		}
		if docSegments[i] != candidateSegments[i] {
			return false
		}
	}
	return true
}

func isPathParam(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}
