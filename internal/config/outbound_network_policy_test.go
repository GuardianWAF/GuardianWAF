package config

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutboundNetworkPolicyDocumentsProductionIntegrations(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := readOutboundPolicyFixture(t, filepath.Join(root, "docs/outbound-network-policy.md"))
	readme := readOutboundPolicyFixture(t, filepath.Join(root, "README.md"))
	adrIndex := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/README.md"))
	siemADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0025-siem-integration.md"))

	for _, want := range []string{
		"# Outbound Network Policy",
		"## Policy Matrix",
		"Backend proxy targets",
		"Proxy upstream health checks",
		"AI provider calls",
		"AI provider calls | Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, and `.local` targets",
		"AI model catalog",
		"AI model catalog | Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, and `.local` targets",
		"Alert webhooks",
		"Dashboard-managed and runtime targets must be HTTPS, include a host, omit URL userinfo/credentials",
		"GeoIP downloads",
		"Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, and `.local` targets",
		"Threat-intel URL feeds",
		"Threat-intel URL feeds | Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, and `.local` targets",
		"API security JWKS",
		"Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, `.local`, and `.localhost` targets",
		"Virtual patch NVD client",
		"Operator-supplied endpoints must be HTTP(S), include a host, omit URL userinfo/credentials, and avoid private, loopback, link-local, multicast, localhost, `.internal`, and `.local` targets",
		"SIEM exporter",
		"SIEM exporter dials operator-configured TLS syslog endpoints",
		"ACME client",
		"OCSP responders",
		"hCaptcha and Turnstile verification",
		"dial-time validation rejects private, loopback, link-local, multicast, and unspecified resolved IPs",
		"Replay targets",
		"Canary health checks",
		"Cluster sync peers",
		"Docker Unix-socket polling",
		"Private networks are intentionally allowed for operator-managed peers",
		"`http.Get`, `http.Post`, `http.Head`, and `http.DefaultClient` must not be used directly",
		"`http.DefaultTransport` may only be used as a clone base",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("outbound network policy missing %q", want)
		}
	}
	if !strings.Contains(readme, "[Outbound Network Policy](docs/outbound-network-policy.md)") {
		t.Fatal("README documentation index does not link docs/outbound-network-policy.md")
	}
	// SIEM integration was implemented in v0.5.0 (internal/siem/).
	// The ADR index and status now correctly reflect this.
	if !strings.Contains(adrIndex, "| [0025](./0025-siem-integration.md) | SIEM Integration (CEF/LEEF/Splunk/Elastic) | Implemented |") {
		t.Fatal("ADR index does not list SIEM integration as Implemented")
	}
	if !strings.Contains(siemADR, "**Status:** Implemented") {
		t.Fatal("SIEM ADR does not show Implemented status")
	}
}

func TestProductionCodeAvoidsUnboundedHTTPConvenienceClients(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := []string{
		"http.Get(",
		"http.Post(",
		"http.Head(",
		"http.DefaultClient",
	}
	allowedFiles := map[string]bool{
		filepath.Join(root, "docs/outbound-network-policy.md"): true,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipProductionSourceDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "examples/") || strings.HasPrefix(rel, "scripts/attack-simulation/") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, token := range forbidden {
			if strings.Contains(text, token) && !allowedFiles[path] {
				t.Fatalf("%s uses forbidden outbound HTTP convenience token %q", rel, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
}

func TestProductionHTTPClientLiteralsDeclareBoundsAndRedirectPolicy(t *testing.T) {
	root := filepath.Join("..", "..")

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipProductionSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "examples/") || strings.HasPrefix(rel, "scripts/attack-simulation/") {
			return nil
		}

		fset := token.NewFileSet()
		file, err := goparser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok || !isHTTPClientComposite(lit.Type) {
				return true
			}
			fields := keyedCompositeFields(lit)
			for _, required := range []string{"Timeout", "Transport", "CheckRedirect"} {
				if !fields[required] {
					pos := fset.Position(lit.Pos())
					t.Fatalf("%s:%d http.Client literal missing %s", rel, pos.Line, required)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
}

func TestWebhookPrivateBypassIsNotExportedFromProductionCode(t *testing.T) {
	root := filepath.Join("..", "..")
	webhookSource := readOutboundPolicyFixture(t, filepath.Join(root, "internal/alerting/webhook.go"))
	if strings.Contains(webhookSource, "func AllowWebhookPrivateTargets(") {
		t.Fatal("webhook private-target bypass must remain package-local test plumbing")
	}
	if !strings.Contains(webhookSource, "func allowWebhookPrivateTargetsForTest(") {
		t.Fatal("expected package-local webhook private-target test helper")
	}
}

func TestProxyPrivateTargetGlobalBypassIsNotUsedByProductionCode(t *testing.T) {
	root := filepath.Join("..", "..")
	targetSource := readOutboundPolicyFixture(t, filepath.Join(root, "internal/proxy/target.go"))
	if strings.Contains(targetSource, "func AllowPrivateTargets(") {
		t.Fatal("legacy proxy private-target bypass helper must not be exported")
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipProductionSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if strings.Contains(text, "SetPrivateTargetsAllowed(") && rel != "internal/proxy/target.go" {
			t.Fatalf("%s calls global proxy private-target bypass; use instance-scoped TargetPolicy instead", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
}

func TestProductionDocsDistinguishPlannedAdvancedRuntimePackages(t *testing.T) {
	root := filepath.Join("..", "..")
	architecture := readOutboundPolicyFixture(t, filepath.Join(root, "ARCHITECTURE.md"))
	docsArchitecture := readOutboundPolicyFixture(t, filepath.Join(root, "docs/ARCHITECTURE.md"))
	detectionEngine := readOutboundPolicyFixture(t, filepath.Join(root, "docs/detection-engine.md"))
	designSpecification := readOutboundPolicyFixture(t, filepath.Join(root, "docs/design/SPECIFICATION.md"))
	marketComparison := readOutboundPolicyFixture(t, filepath.Join(root, "docs/market-comparison.md"))
	roadmap := readOutboundPolicyFixture(t, filepath.Join(root, "PRODUCTION_READINESS_ROADMAP.md"))
	threatModel := readOutboundPolicyFixture(t, filepath.Join(root, "docs/threat-model.md"))
	grpcADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0019-grpc-protocol-support.md"))
	mcpDocs := readOutboundPolicyFixture(t, filepath.Join(root, "docs/mcp-integration.md"))
	zeroDepsADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0001-zero-external-dependencies.md"))
	zeroTrustADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0024-zero-trust-network-access.md"))
	graphQLADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0012-graphql-protection.md"))
	earlyMLAnomalyADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0007-ml-anomaly-detection.md"))
	apiDiscoveryADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0017-api-discovery-schema-validation.md"))
	mlAnomalyADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0016-ml-anomaly-detection.md"))
	clientSideADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0021-client-side-protection.md"))
	dlpADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0020-advanced-dlp.md"))
	complianceADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0022-compliance-reporting.md"))
	cacheADR := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0026-response-caching-layer.md"))
	adrIndex := readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/README.md"))
	goMod := readOutboundPolicyFixture(t, filepath.Join(root, "go.mod"))

	plannedOnlyDirs := []string{
		"internal/cluster",
		"internal/clustersync",
		"internal/layers/grpc",
		"internal/layers/graphql",
		"internal/discovery",
		"internal/layers/discovery",
		"internal/ml",
		"internal/http3",
		"internal/layers/cache",
		"internal/layers/canary",
		"internal/layers/replay",
		"internal/layers/zerotrust",
	}
	for _, rel := range plannedOnlyDirs {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Fatalf("%s now exists; update production-readiness docs and remove planned-only guard", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("Stat(%s) error = %v", rel, err)
		}
		if strings.Contains(roadmap, "go test ./"+rel) {
			t.Fatalf("roadmap claims package-level test evidence for missing package %s", rel)
		}
	}

	for _, want := range []string{
		"no HTTP/3 runtime package/server is present",
		"no runtime package",
		"HTTP/3 is a config/build-tag compatibility surface",
	} {
		if !strings.Contains(architecture, want) {
			t.Fatalf("architecture docs missing planned-runtime qualifier %q", want)
		}
	}
	for _, want := range []string{
		"current registered runtime pipeline",
		"planned/config-compatibility layer orders",
		"HTTP/3/QUIC is not a production listener",
		"11 Detectors",
	} {
		if !strings.Contains(docsArchitecture, want) {
			t.Fatalf("docs architecture missing current-vs-planned qualifier %q", want)
		}
	}
	for _, want := range []string{
		"current registered runtime pipeline",
		"planned/runtime-absent layers",
		"11 attack detectors",
		"gRPC message inspection",
	} {
		if !strings.Contains(detectionEngine, want) {
			t.Fatalf("detection engine docs missing current-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"The full pipeline includes additional layers between these stages: Cluster (75), WebSocket Security (76), gRPC Security (78), Canary (95)",
		"GuardianWAF ships with 6 attack detectors",
	} {
		if strings.Contains(detectionEngine, stale) {
			t.Fatalf("detection engine docs still contain stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"Runtime Pipeline And Planned Orders",
		"planned/runtime-absent packages are not production pipeline evidence",
		"Current registered runtime layers include",
		"Design order, mixing current runtime layers and planned/runtime-absent layer slots",
		"GraphQL(285 planned)",
		"API Discovery(310 planned)",
		"ML Anomaly(473 planned)",
		"no `internal/layers/graphql/` runtime package in the current tree",
		"no `internal/discovery/` or `internal/layers/discovery/` runtime package in the current tree",
		"no `internal/ml/` runtime package in the current tree",
		"planned HTTP/3/QUIC runtime package",
		"package absent in current tree",
	} {
		if !strings.Contains(designSpecification, want) {
			t.Fatalf("design specification missing current-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"Currently **28 layers are registered**",
		"Full Layer Table (28 layers registered in serve mode)",
		"Full pipeline order: SIEM(1) → Cluster(75) → WebSocket(76) → gRPC(78) → Canary(95)",
		"| 285 | GraphQL | Query depth/complexity/introspection limits |",
		"| 310 | API Discovery | Passive API endpoint discovery, OpenAPI generation |",
		"| 473 | ML Anomaly | ONNX-based Isolation Forest anomaly detection |",
		"│   ├── http3/ (HTTP/3/QUIC support, build with -tags http3, stub otherwise)",
		"│   ├── siem/ (SIEM event forwarding — Splunk, ELK, ArcSight)",
		"│   ├── clustersync/ (Cross-node state synchronization via gRPC-lite over TCP)",
		"│   └── layers/zerotrust/ (Zero Trust middleware — in-development, not yet wired)",
	} {
		if strings.Contains(designSpecification, stale) {
			t.Fatalf("design specification still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"message-aware gRPC inspection is planned",
		"HTTP/3/QUIC has config/build-tag compatibility only",
		"planned HTTP/3/QUIC listener",
	} {
		if !strings.Contains(marketComparison, want) {
			t.Fatalf("market comparison missing current-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"- Modern protocol desteği (gRPC, HTTP/3)",
		"| 5 | gRPC Support |",
		"| 6 | HTTP/3 QUIC |",
	} {
		if strings.Contains(marketComparison, stale) {
			t.Fatalf("market comparison still contains stale protocol claim %q", stale)
		}
	}
	for _, want := range []string{
		"Their outbound policies are future implementation requirements",
		"no QUIC/HTTP/3 listener package exists to drain",
		"SIEM exporter and cluster sync shutdown remain future requirements",
	} {
		if !strings.Contains(roadmap, want) {
			t.Fatalf("roadmap missing planned-runtime qualifier %q", want)
		}
	}
	for _, want := range []string{
		"no `internal/layers/zerotrust/` runtime package",
		"Current `ZeroTrustConfig` struct",
		"planned implementation locations",
	} {
		if !strings.Contains(zeroTrustADR, want) {
			t.Fatalf("zero trust ADR missing current-tree qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"`internal/layers/zerotrust/` exists",
		"(exists — not in pipeline)",
	} {
		if strings.Contains(zeroTrustADR, stale) {
			t.Fatalf("zero trust ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Proposed",
		"does not currently ship an `internal/layers/graphql/` runtime package",
		"`internal/layers/graphql/` is a planned runtime package and does not exist in the current tree",
		"GraphQL-specific pipeline Order 285 is not registered in the current serve pipeline",
	} {
		if !strings.Contains(graphQLADR, want) {
			t.Fatalf("GraphQL ADR missing current-tree qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"**Status:** Implemented",
		"GuardianWAF's `internal/layers/graphql/` provides foundational GraphQL protection",
		"### Current Implementation (`internal/layers/graphql/`)",
	} {
		if strings.Contains(graphQLADR, stale) {
			t.Fatalf("GraphQL ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Proposed",
		"`internal/layers/cache/` is a planned runtime package and does not exist in the current tree",
		"cache behavior is not registered in the current main pipeline",
	} {
		if !strings.Contains(cacheADR, want) {
			t.Fatalf("cache ADR missing current-tree qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"**Status:** Implemented",
	} {
		if strings.Contains(cacheADR, stale) {
			t.Fatalf("cache ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"| [0017](./0017-api-discovery-schema-validation.md) | 310 | API Discovery & Schema Validation | API Validation implemented baseline; passive discovery planned — not registered in pipeline |",
		"| [0020](./0020-advanced-dlp.md) | 475 | Advanced DLP | Implemented baseline — advanced pattern engine planned |",
		"| [0016](./0016-ml-anomaly-detection.md) | 473 | ML Anomaly Detection | Proposed — not registered in pipeline |",
		"| [0018](./0018-enhanced-bot-management.md) | 500 | Enhanced Bot Management | Withdrawn — runtime bot baseline lives in `internal/layers/botdetect` |",
		"| [0021](./0021-client-side-protection.md) | 590 | Client-Side Protection (RASP-lite) | Implemented baseline — browser agent planned |",
		"| [0020](./0020-advanced-dlp.md) | Advanced DLP Pattern Engine | Implemented baseline — advanced pattern engine planned |",
		"| [0022](./0022-compliance-reporting.md) | Compliance & Reporting Framework | Implemented baseline — scheduled reports and retention enforcement planned |",
		"| [0026](./0026-response-caching-layer.md) | 140 | Response Cache | Proposed — not registered in pipeline |",
	} {
		if !strings.Contains(adrIndex, want) {
			t.Fatalf("ADR index missing current-vs-planned qualifier %q", want)
		}
	}
	for _, want := range []string{
		"**Current tree note:** API Validation exists at `internal/layers/apivalidation/`",
		"Passive API Discovery is planned",
		"there is no `internal/discovery/` or `internal/layers/discovery/` runtime package in the current tree",
		"Order 310 is not registered in the current serve pipeline",
	} {
		if !strings.Contains(apiDiscoveryADR, want) {
			t.Fatalf("API discovery ADR missing current-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"Discovery is being built at `internal/discovery/`",
		"| `internal/layers/apivalidation/validator.go` | JSON Schema validation against `RequestContext` (planned) |",
	} {
		if strings.Contains(apiDiscoveryADR, stale) {
			t.Fatalf("API discovery ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Proposed",
		"does not ship an `internal/ml/` package",
		"`internal/ml/` is a planned runtime package and does not exist in the current tree",
		"`engine.OrderAnomaly` and `WAF.MLAnomaly` configuration parsing are compatibility surfaces only",
	} {
		if !strings.Contains(mlAnomalyADR, want) {
			t.Fatalf("ML anomaly ADR missing current-tree qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"`internal/ml/onnx/` exists with `model.go`",
		"Pipeline layer (Order 475 — same slot as DLP; order subject to change)",
	} {
		if strings.Contains(mlAnomalyADR, stale) {
			t.Fatalf("ML anomaly ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"no `internal/ml/` runtime package",
		"**Planned layer position**: Order 473",
		"`internal/ml/` is planned and does not exist in the current tree",
	} {
		if !strings.Contains(earlyMLAnomalyADR, want) {
			t.Fatalf("early ML anomaly ADR missing current-tree qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"`internal/ml/anomaly/layer.go` exists",
		"**Layer position**: Order 475",
	} {
		if strings.Contains(earlyMLAnomalyADR, stale) {
			t.Fatalf("early ML anomaly ADR still contains stale runtime claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Implemented baseline; scheduled reports and retention enforcement planned",
		"current baseline provides built-in controls",
		"hash-chained audit entries with optional JSONL persistence",
		"Scheduled report execution, PDF rendering, retention enforcement",
		"`internal/compliance/` exists and implements the baseline engine",
	} {
		if !strings.Contains(complianceADR, want) {
			t.Fatalf("compliance ADR missing baseline-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"`internal/compliance/` does not exist yet",
		"all files below are planned",
	} {
		if strings.Contains(complianceADR, stale) {
			t.Fatalf("compliance ADR still contains stale implementation claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Implemented baseline; browser RASP-lite agent planned",
		"registered as Layer 590 in the serve pipeline",
		"collect bounded browser/CSP reports through the shared report handler",
		"dedicated browser agent files below",
		"are planned and do not exist yet",
	} {
		if !strings.Contains(clientSideADR, want) {
			t.Fatalf("client-side ADR missing baseline-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"**Status:** Proposed",
		"Current client-side protection (Layer 590) only injects a Content-Security-Policy header and a placeholder script stub. There is no real-time monitoring or reporting from the browser.",
	} {
		if strings.Contains(clientSideADR, stale) {
			t.Fatalf("client-side ADR still contains stale implementation claim %q", stale)
		}
	}
	for _, want := range []string{
		"**Status:** Implemented baseline; advanced pattern engine planned",
		"registered as Order 475 in the serve pipeline",
		"bounded request-body scanning",
		"runtime custom regex patterns",
		"full advanced policy engine described below remains planned",
	} {
		if !strings.Contains(dlpADR, want) {
			t.Fatalf("DLP ADR missing baseline-vs-planned qualifier %q", want)
		}
	}
	for _, stale := range []string{
		"**Status:** Proposed",
		"It operates only on response bodies and takes a binary block/pass action.",
		"**No request-body inspection**",
		"**No custom patterns**",
	} {
		if strings.Contains(dlpADR, stale) {
			t.Fatalf("DLP ADR still contains stale implementation claim %q", stale)
		}
	}
	if strings.Contains(goMod, "github.com/quic-go/quic-go") {
		t.Fatal("go.mod now declares quic-go; update HTTP/3 current-runtime documentation guards")
	}
	for _, want := range []string{
		"does not declare `quic-go` in `go.mod`",
		"does not include an `internal/http3/` runtime package",
		"Planned future runtime behind `-tags http3`",
		"no current `internal/http3/` package",
	} {
		if !strings.Contains(zeroDepsADR, want) {
			t.Fatalf("zero external deps ADR missing current HTTP/3 qualifier %q", want)
		}
	}
	for _, tt := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "threat model", doc: threatModel, want: "HTTP/3/QUIC is not currently a production listener"},
		{name: "gRPC ADR", doc: grpcADR, want: "HTTP/3/QUIC is not a production runtime in the current tree"},
		{name: "MCP docs", doc: mcpDocs, want: "they do not imply a production QUIC listener in this tree"},
	} {
		if !strings.Contains(tt.doc, tt.want) {
			t.Fatalf("%s missing current HTTP/3 qualifier %q", tt.name, tt.want)
		}
	}
	for _, tt := range []struct {
		name  string
		doc   string
		stale string
	}{
		{name: "threat model", doc: threatModel, stale: "optional HTTP/3 listener"},
		{name: "gRPC ADR", doc: grpcADR, stale: "currently supports HTTP/1.1, HTTP/2, HTTP/3, and WebSocket traffic"},
	} {
		if strings.Contains(tt.doc, tt.stale) {
			t.Fatalf("%s still contains stale HTTP/3 runtime claim %q", tt.name, tt.stale)
		}
	}

	plannedLayerADRs := map[string]string{
		"docs/adr/0019-grpc-protocol-support.md":  readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0019-grpc-protocol-support.md")),
		"docs/adr/0026-response-caching-layer.md": readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0026-response-caching-layer.md")),
		"docs/adr/0035-websocket-proxy.md":        readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0035-websocket-proxy.md")),
		"docs/adr/0036-canary-deployments.md":     readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0036-canary-deployments.md")),
		"docs/adr/0037-request-replay.md":         readOutboundPolicyFixture(t, filepath.Join(root, "docs/adr/0037-request-replay.md")),
	}
	for path, doc := range plannedLayerADRs {
		normalizedDoc := strings.Join(strings.Fields(doc), " ")
		if !strings.Contains(normalizedDoc, "planned runtime package and does not exist in the current tree") {
			t.Fatalf("%s missing planned-runtime package qualifier", path)
		}
		for _, stale := range []string{
			"package exists",
			"exists with",
			"exists — not",
		} {
			if strings.Contains(doc, stale) {
				t.Fatalf("%s still contains stale planned-layer runtime claim %q", path, stale)
			}
		}
	}
}

func TestShouldSkipProductionSourceDir(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{name: ".git", want: true},
		{name: ".temp_files", want: true},
		{name: ".coverage-pkgs", want: true},
		{name: "dist", want: true},
		{name: "node_modules", want: true},
		{name: "internal", want: false},
		{name: "scripts", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSkipProductionSourceDir(tt.name); got != tt.want {
				t.Fatalf("shouldSkipProductionSourceDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func shouldSkipProductionSourceDir(name string) bool {
	return strings.HasPrefix(name, ".") || name == "dist" || name == "node_modules"
}

func isHTTPClientComposite(expr ast.Expr) bool {
	switch typ := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := typ.X.(*ast.Ident)
		return ok && pkg.Name == "http" && typ.Sel.Name == "Client"
	case *ast.StarExpr:
		return isHTTPClientComposite(typ.X)
	default:
		return false
	}
}

func keyedCompositeFields(lit *ast.CompositeLit) map[string]bool {
	fields := make(map[string]bool)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if ok {
			fields[key.Name] = true
		}
	}
	return fields
}

func readOutboundPolicyFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return string(data)
}
