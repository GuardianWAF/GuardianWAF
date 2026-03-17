# BRANDING.md -- GuardianWAF Project Identity

> This document defines the public identity, messaging, and visual direction for GuardianWAF.
> It serves as the single source of truth for all branding decisions across README, website, social media, and community interactions.

---

## 1. Core Identity

### 1.1 Names

| Context            | Value                                |
|--------------------|--------------------------------------|
| Full name          | **GuardianWAF**                      |
| Binary name        | `guardianwaf`                        |
| Short name / alias | `gwaf`                               |
| Go module          | `github.com/guardianwaf/guardianwaf`    |
| Domain             | `guardianwaf.com`                    |
| Author             | Ersin Koc / ECOSTACK TECHNOLOGY OU   |
| License            | MIT (core) + Commercial (enterprise) |

### 1.2 Tagline

**Primary:**

> "Zero-dependency WAF. One binary. Total protection."

**Alternatives:**

1. "The WAF that doesn't need a PhD to deploy."
2. "One binary to protect them all."
3. "Production-grade WAF. Zero dependencies. Pure Go."
4. "Deploy a WAF in 10 seconds, not 10 hours."
5. "Your application's guardian. No assembly required."
6. "Security without complexity."

Use the primary tagline in README, landing page hero, and GitHub description. Use alternatives contextually -- (1) for informal channels, (2) for dramatic effect, (3) for developer audiences, (4) for DevOps audiences, (5) for general marketing, (6) as a minimal fallback.

### 1.3 Elevator Pitch (30 seconds)

GuardianWAF is a Web Application Firewall built entirely in Go with zero external dependencies. It ships as a single binary that runs in three modes -- standalone reverse proxy, embeddable Go library, or sidecar proxy -- so it fits into any architecture without pulling in a dependency tree. Its tokenizer-based detection engine with a scoring system catches real attacks while keeping false positives low, and a built-in dashboard gives you full visibility without bolting on extra infrastructure.

---

## 2. Description Variants

### 2.1 One-liner (< 120 chars)

```
Zero-dependency Web Application Firewall in Go. Single binary. Three deployment modes. Tokenizer-based detection.
```

_110 characters. Use for GitHub repository description, social media bios, and package registries._

### 2.2 Short Description (2-3 sentences)

GuardianWAF is a production-grade Web Application Firewall written in pure Go with zero external dependencies. It ships as a single binary supporting three deployment modes: standalone reverse proxy, embeddable library, and sidecar proxy. Its tokenizer-based scoring engine provides accurate threat detection with minimal false positives.

### 2.3 Medium Description (1 paragraph)

GuardianWAF is a modular, zero-dependency Web Application Firewall built entirely in Go. Instead of relying on regex-heavy rule files or machine learning black boxes, it uses a tokenizer-based detection engine with a configurable scoring system that breaks down HTTP requests into tokens, evaluates each token against attack patterns, and produces a cumulative threat score. The result is precise detection of SQL injection, XSS, path traversal, command injection, and other OWASP Top 10 threats -- with granular control over sensitivity thresholds. GuardianWAF compiles to a single binary and supports three deployment modes (standalone reverse proxy, embeddable Go library, sidecar proxy), ships with a built-in web dashboard, and targets sub-millisecond p99 latency overhead. Everything from the YAML parser to the ACME TLS client is implemented from scratch -- no external dependencies, no supply chain risk.

### 2.4 Full Description (3-4 paragraphs)

**What it is.** GuardianWAF is an open-source Web Application Firewall written in pure Go. It compiles to a single, self-contained binary with zero external dependencies -- no C bindings, no shared libraries, no runtime requirements. It protects web applications against SQL injection, cross-site scripting, path traversal, command injection, and the broader OWASP Top 10 attack categories. It includes a built-in web dashboard for real-time monitoring, threat visualization, and rule management.

**Why it exists.** Existing WAF solutions force you into trade-offs. ModSecurity requires complex rule sets and an NGINX/Apache host process. Cloud WAFs lock you into a vendor and a monthly bill. Most open-source alternatives pull in dozens of transitive dependencies, each one a potential supply chain risk. GuardianWAF was built to eliminate these trade-offs: a WAF that is genuinely simple to deploy, trivially auditable (one repo, zero deps), and powerful enough for production workloads.

**How it's different.** At the core of GuardianWAF is a tokenizer-based detection engine. Rather than matching raw regex patterns against request bodies -- an approach prone to both false positives and evasion -- GuardianWAF lexically analyzes HTTP requests, produces token streams, scores each token against known attack signatures, and computes a cumulative threat score. This scoring approach lets operators tune sensitivity per-route, per-method, or per-source, and it provides explainable decisions: every blocked request includes the score breakdown showing exactly which tokens triggered and why. Three deployment modes (standalone reverse proxy, embeddable Go library, sidecar proxy) mean GuardianWAF fits into your architecture rather than demanding you reshape your architecture around it.

**Who it's for.** GuardianWAF is built for developers who deploy their own applications and want meaningful security without operational complexity. It's for DevOps engineers who want a container-ready WAF that starts in milliseconds and consumes minimal resources. It's for security teams who want transparent, auditable detection logic instead of opaque ML models. And it's for anyone who believes that security tooling should be as easy to deploy as the applications it protects.

---

## 3. Key Messages

### 3.1 For Developers

**Pain points GuardianWAF solves:**

- Adding WAF protection to an application typically means introducing infrastructure complexity -- reverse proxies, rule files, third-party services, or heavyweight SDKs with deep dependency trees.
- Most WAF libraries for Go pull in transitive dependencies that bloat binaries, increase build times, and expand supply chain attack surface.
- Regex-based detection is hard to tune: too aggressive and you block legitimate users; too loose and real attacks slip through.

**Why developers should care:**

- **Zero dependencies.** `go get github.com/guardianwaf/guardianwaf` adds nothing to your `go.sum` except GuardianWAF itself. Your supply chain stays clean.
- **Single binary.** Cross-compile for any OS/arch. Drop it into a container, a VM, or bare metal. No runtime, no shared libs.
- **Embeddable.** Wrap your `http.Handler` in three lines of Go code and you have a WAF. No sidecar, no reverse proxy -- just middleware.
- **Explainable scoring.** Every decision includes a score breakdown. Debug false positives in minutes, not hours.

### 3.2 For DevOps / SRE

**Deployment story:**

- Three deployment modes: standalone reverse proxy (drop-in front of any backend), embeddable library (compiled into your Go app), sidecar proxy (Kubernetes-native, alongside any language).
- Single static binary. Alpine container image under 15 MB. Starts in under 100ms.
- YAML configuration with sane defaults. Override via environment variables for 12-factor compliance.
- Built-in ACME client for automatic TLS certificate provisioning -- no certbot, no extra processes.
- Health check endpoint, Prometheus-compatible metrics, structured JSON logging.

**Performance characteristics:**

- Target: < 1ms p99 latency overhead per request.
- Minimal memory footprint -- radix tree routing, pooled allocators, zero-allocation hot paths.
- Horizontal scaling: stateless by default, with optional shared state for rate limiting clusters.

### 3.3 For Security Engineers

**Detection approach:**

- Tokenizer-based analysis, not raw regex matching. HTTP requests are lexically decomposed into typed tokens (string literals, operators, keywords, encoded sequences). Each token is evaluated against attack pattern databases for SQL, XSS, path traversal, command injection, and more.
- Scoring engine assigns weighted threat scores per token. Cumulative score is compared against configurable thresholds per route/method/source. This provides a gradient of response (log, challenge, block) rather than binary allow/deny.
- This approach resists common evasion techniques (encoding tricks, comment injection, case manipulation) because tokenization normalizes input before scoring.

**False positive management:**

- Per-route threshold tuning. An API endpoint accepting rich text needs different sensitivity than a login form.
- Score breakdown in every log entry: see exactly which tokens triggered, their individual scores, and the final cumulative score. Tuning is data-driven, not guesswork.
- Learning mode: observe traffic and generate baseline thresholds before enforcing.
- Allowlists and parameter-level exceptions for known-safe patterns.

**MCP integration:**

- Built-in MCP (Model Context Protocol) server enables AI-powered security operations.
- LLM agents can query threat logs, analyze attack patterns, adjust thresholds, and generate reports via structured tool calls.
- Bridges the gap between traditional rule-based WAF and intelligent, adaptive security operations.

---

## 4. README Structure

The README should follow this exact structure. Each section includes content guidance.

```markdown
# GuardianWAF

> Zero-dependency WAF. One binary. Total protection.

<!-- Badges row: see Section 5 for full badge list -->

Short description (Section 2.2)

## Features

Bullet list with emoji prefixes. Group into categories:
- Detection & Protection (shield emoji)
- Deployment (rocket emoji)
- Operations (wrench emoji)
- Developer Experience (laptop emoji)
Keep it scannable -- one line per feature, no paragraphs.

## Quick Start

Three tabs or subsections, one per deployment mode:
1. Standalone reverse proxy (curl install + one command)
2. Embeddable library (go get + 5-line code snippet)
3. Sidecar proxy (docker run one-liner)
Each should be copy-pasteable and working in under 30 seconds.

## Why GuardianWAF?

Comparison table from Section 6 of this document.
Brief prose paragraph above the table explaining the philosophy.

## Architecture

Simplified ASCII or Mermaid diagram showing:
Request -> Listener -> Tokenizer -> Scoring Engine -> Decision -> Upstream
Show where modules plug in (rate limiter, geo filter, bot detector, etc.)

## Detection Engine

Concrete scoring example:
- Show a malicious request
- Show the token breakdown
- Show individual token scores
- Show threshold comparison and final decision
This makes the scoring engine tangible and understandable.

## Installation

All installation methods:
- go install
- Binary download (Linux/macOS/Windows)
- Docker
- Homebrew (future)
- Build from source

## Configuration

Minimal YAML example -- 10-15 lines that protect a backend.
Link to full configuration reference in docs.

## Dashboard

Screenshot placeholder image.
Brief description: real-time traffic, threat map, score distributions, rule management.

## Library Usage

Go code example: wrap an http.Handler with GuardianWAF middleware.
Show the minimal case (3-5 lines) and one advanced case (custom scoring threshold).

## MCP Integration

Brief explanation of MCP + GuardianWAF.
Example tool call showing an LLM agent querying threat data.

## Performance

Benchmark table: requests/sec, p50/p99 latency, memory usage.
Comparison with and without GuardianWAF in the request path.

## Documentation

Links to:
- Full documentation site (guardianwaf.com/docs)
- Configuration reference
- Rule writing guide
- API reference
- Deployment guides per mode

## Contributing

Link to CONTRIBUTING.md.
Brief welcome message emphasizing that the project values quality over velocity.

## License

MIT for core. Mention commercial license for enterprise features (future).

## Author

Ersin Koc / ECOSTACK TECHNOLOGY OU
Links to GitHub, website.
```

---

## 5. Badge List

All badges use [shields.io](https://shields.io) unless otherwise noted.

```markdown
[![Go Version](https://img.shields.io/github/go-mod/go-version/guardianwaf/guardianwafwaf?style=flat-square)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/guardianwaf/guardianwaf?style=flat-square)](https://goreportcard.com/report/github.com/guardianwaf/guardianwaf)
[![Test Coverage](https://img.shields.io/codecov/c/github/guardianwaf/guardianwafwaf?style=flat-square)](https://codecov.io/guardianwaf/guardianwafianwaf)
[![Release](https://img.shields.io/github/v/release/guardianwaf/guardianwafwaf?style=flat-square)](https://github.com/guardianwaf/guardianwaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/guardianwaf/guardianwafwaf?style=flat-square)](https://hub.docker.comguardianwaf/guardianwafianwaf)
[![GitHub Stars](https://img.shields.io/github/stars/guardianwaf/guardianwafwaf?style=flat-square)](https://github.com/guardianwaf/guardianwaf/stargazers)
[![Build Status](https://img.shields.io/github/actions/workflow/status/guardianwaf/guardianwafwaf/ci.yml?branch=main&style=flat-square)](https://github.com/guardianwaf/guardianwaf/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/guardianwaf/guardianwaf.svg)](https://pkg.go.dev/github.com/guardianwaf/guardianwaf)
[![Security Headers](https://img.shields.io/security-headers?url=https%3A%2F%2Fguardianwaf.com&style=flat-square)](https://securityheaders.com/?q=guardianwaf.com)
```

Use `flat-square` style for visual consistency. Order: Go version, license, report card, coverage, release, Docker, stars, CI, Go reference, security headers.

---

## 6. Comparison Table

| Feature                 | GuardianWAF          | SafeLine            | Coraza              | ModSecurity         | NAXSI               |
|-------------------------|----------------------|---------------------|---------------------|---------------------|----------------------|
| **Language**            | Go                   | Go + Lua            | Go                  | C                   | C                    |
| **External deps**       | Zero                 | Multiple            | Multiple            | Multiple            | NGINX module         |
| **Deployment modes**    | 3 (proxy, lib, sidecar) | Reverse proxy    | Library / proxy     | Module (NGINX/Apache) | NGINX module       |
| **Detection method**    | Tokenizer + scoring  | Semantic analysis   | CRS regex rules     | CRS regex rules     | Scoring + allowlists |
| **Web dashboard**       | Built-in             | Built-in            | No (third-party)    | No (third-party)    | No                   |
| **Single binary**       | Yes                  | No                  | No                  | No                  | No                   |
| **MCP / AI integration**| Built-in MCP server  | No                  | No                  | No                  | No                   |
| **Configuration**       | YAML + env vars      | Web UI              | SecRule directives   | SecRule directives   | NGINX directives     |
| **False positive mgmt** | Score tuning per-route | Auto learning     | Rule exclusions      | Rule exclusions      | Allowlists           |
| **Performance overhead**| < 1ms p99            | Low                 | Low                 | Moderate            | Low                  |
| **Memory usage**        | Minimal              | Moderate            | Low-moderate        | Moderate-high       | Low                  |
| **Learning curve**      | Low                  | Low-moderate        | Moderate            | High                | Moderate             |
| **License**             | MIT                  | Apache 2.0          | Apache 2.0          | Apache 2.0          | GPL v3               |

**Notes on the comparison:**

- This table is intended to be factual and fair. It highlights architectural differences, not quality judgments.
- "Multiple" dependencies means the project relies on third-party libraries or external services.
- Performance and memory claims should be backed by published benchmarks before including in public materials.
- When publishing, add a date and version note (e.g., "Comparison as of March 2026. Check each project for current status.").

---

## 7. Social Media Copy

### 7.1 Launch Tweet / X Post (< 280 chars)

**Variant A (technical):**
```
Introducing GuardianWAF -- a zero-dependency Web Application Firewall in pure Go.

Single binary. Three deployment modes. Tokenizer-based detection with scoring engine.

Open source (MIT).

github.com/guardianwaf/guardianwaf
```

**Variant B (problem/solution):**
```
Tired of WAFs that need 20 dependencies, 3 config files, and a PhD?

GuardianWAF: one Go binary, zero deps, sub-millisecond overhead. Protects your app in 10 seconds.

github.com/guardianwaf/guardianwaf
```

**Variant C (feature-forward):**
```
GuardianWAF -- open-source WAF in Go:

- Zero external dependencies
- Single binary, 3 deployment modes
- Tokenizer-based scoring engine
- Built-in dashboard
- MCP server for AI-powered security ops

MIT licensed.

github.com/guardianwaf/guardianwaf
```

### 7.2 LinkedIn Post

```
I'm excited to open-source GuardianWAF -- a production-grade Web Application Firewall written entirely in Go with zero external dependencies.

The problem: deploying a WAF in front of your application shouldn't require a complex infrastructure stack. Yet most WAF solutions demand multiple dependencies, elaborate configuration, or vendor lock-in. For teams that value supply chain security and operational simplicity, the existing options all require trade-offs they shouldn't have to make.

GuardianWAF takes a different approach. It compiles to a single binary with no external dependencies -- not even a YAML parser or TLS library. Everything is implemented from scratch in pure Go. It supports three deployment modes (standalone reverse proxy, embeddable Go library, and sidecar proxy) so it fits your architecture instead of dictating it. At its core is a tokenizer-based detection engine that breaks HTTP requests into typed tokens and produces explainable threat scores -- giving security teams the transparency they need to tune detection without guesswork.

The project is MIT licensed and available now on GitHub. I'd love feedback from developers, DevOps engineers, and security professionals who have opinions about how WAFs should work.

github.com/guardianwaf/guardianwaf

#golang #security #waf #opensource #cybersecurity
```

### 7.3 Hacker News Title + Comment

**Title:**
```
GuardianWAF: Zero-dependency WAF in Go with tokenizer-based scoring engine
```

**First comment:**
```
Author here. I built GuardianWAF because I kept running into the same problem: every WAF I evaluated either pulled in a tree of transitive dependencies, required a host process (NGINX/Apache), or was a cloud service with a monthly bill.

GuardianWAF is a single Go binary with zero external dependencies. The YAML parser, radix-tree router, ACME TLS client, and scoring engine are all implemented from scratch. This isn't NIH syndrome -- it's a deliberate choice to keep the supply chain auditable and the binary self-contained.

The core innovation is the detection engine. Instead of matching regex patterns against raw request bodies, GuardianWAF tokenizes HTTP requests into typed token streams (string literals, SQL keywords, operators, encoded sequences, etc.) and scores each token against attack pattern databases. The cumulative score determines the response (log, challenge, or block). This makes detection resistant to common evasion techniques and gives operators a transparent, tunable system -- every blocked request includes the full score breakdown.

Three deployment modes:
1. Standalone reverse proxy: drop it in front of any backend
2. Embeddable Go library: wrap your http.Handler in middleware
3. Sidecar proxy: run alongside any service in a pod

MIT licensed. Source at github.com/guardianwaf/guardianwaf. Feedback and criticism welcome.
```

### 7.4 Reddit r/golang Post

**Title:**
```
GuardianWAF: I built a zero-dependency WAF in pure Go -- single binary, three deployment modes, tokenizer-based detection
```

**Body:**
```
Hey r/golang,

I've been working on GuardianWAF, a Web Application Firewall written entirely in Go with zero external dependencies.

**What it does:** Protects web applications against SQL injection, XSS, path traversal, command injection, and other OWASP Top 10 threats.

**What makes it different:**

- **Zero deps.** The go.sum is empty. YAML parser, radix tree, ACME client, scoring engine -- all from scratch. I wanted a WAF where you could audit the entire supply chain by reading one repository.
- **Single binary.** Cross-compile, drop it anywhere. Alpine container image under 15 MB.
- **Three deployment modes.** Standalone reverse proxy, embeddable Go library (wrap your `http.Handler`), or sidecar proxy.
- **Tokenizer-based detection.** Instead of regex matching, requests are lexically tokenized and scored. Each token gets a weighted threat score, and the cumulative score determines the action. This makes detection both evasion-resistant and tunable.
- **Built-in dashboard.** Real-time traffic monitoring, threat visualization, score breakdowns.
- **MCP server.** For AI-powered security operations via Model Context Protocol.

**Performance target:** < 1ms p99 latency overhead.

It's MIT licensed: github.com/guardianwaf/guardianwaf

I'd especially appreciate feedback on:
- The API surface for the embeddable library mode
- The scoring engine design
- Configuration ergonomics

Thanks for taking a look.
```

### 7.5 Dev.to / Blog Announcement Title Ideas

1. **"Building a Zero-Dependency WAF in Go: Why I Wrote Everything from Scratch"**
2. **"Why Tokenizer-Based Detection Beats Regex for Web Application Firewalls"**
3. **"One Binary, Three Deployment Modes: Rethinking WAF Architecture"**
4. **"GuardianWAF: An Open-Source WAF That Fits in a 15 MB Container"**
5. **"How a Scoring Engine Makes WAF False Positives a Solvable Problem"**

---

## 8. Visual Identity

### 8.1 Logo Concept

The logo combines a **shield** silhouette with a **binary/digital motif**. The shield represents protection and trust. Inside the shield, a stylized pattern of ones and zeros, circuit traces, or a hexagonal mesh suggests the technical, code-native nature of the project. The shield outline is bold and geometric -- not ornate or medieval, but modern and minimal.

Alternative concept: a shield formed by converging angle brackets (`< >`) -- a nod to both Go syntax and the idea of code-as-armor. The negative space between the brackets creates the shield shape.

The Go gopher should **not** appear in the primary logo (trademark considerations), but a "GuardianWAF gopher" mascot (a gopher wearing a security helmet or holding a shield) can be used in community materials, stickers, and documentation illustrations where Go branding guidelines permit.

### 8.2 Color Palette

| Role                    | Color         | Hex       | Usage                                    |
|-------------------------|---------------|-----------|------------------------------------------|
| **Primary**             | Guardian Blue | `#1A56DB`  | Logo, headings, primary buttons, links   |
| **Primary Dark**        | Deep Navy     | `#0F2D5E`  | Dark mode primary, footer backgrounds    |
| **Secondary / Accent**  | Cyan Spark    | `#06B6D4`  | Highlights, hover states, code accents   |
| **Dark background**     | Slate 950     | `#0B1120`  | Dark theme page background               |
| **Light background**    | Slate 50      | `#F8FAFC`  | Light theme page background              |
| **Alert / Block**       | Threat Red    | `#DC2626`  | Blocked requests, critical alerts        |
| **Warning / Log**       | Amber         | `#D97706`  | Warnings, logged-but-not-blocked events  |
| **Success / Allow**     | Safe Green    | `#16A34A`  | Allowed requests, healthy status         |
| **Neutral / Muted**     | Slate 400     | `#94A3B8`  | Secondary text, borders, inactive states |

The palette is rooted in deep blue for trust and authority, with cyan as a technical accent. The alert colors follow universal conventions (red/amber/green) for instant recognition in dashboard and log contexts.

### 8.3 Typography

| Context              | Font                        | Fallback              | Notes                                          |
|----------------------|-----------------------------|-----------------------|-------------------------------------------------|
| **Logo / Headings**  | JetBrains Mono              | Fira Code, monospace  | Monospace conveys technical precision            |
| **Body text**        | Inter                       | system-ui, sans-serif | Clean, highly legible at all sizes               |
| **Code blocks**      | JetBrains Mono              | Fira Code, monospace  | Consistent with heading font for brand cohesion  |
| **Dashboard UI**     | Inter                       | system-ui, sans-serif | Optimized for data-dense interfaces              |

For web use, load Inter via Google Fonts or bundle it. JetBrains Mono is open-source (Apache 2.0) and available via Google Fonts. Avoid decorative or serif fonts -- the brand is technical, modern, and minimal.

---

## 9. SEO & Discovery

### 9.1 Keywords

1. web application firewall
2. waf
3. go waf
4. golang waf
5. zero dependency waf
6. single binary waf
7. reverse proxy waf
8. embeddable waf
9. waf middleware
10. sql injection protection
11. xss protection
12. owasp top 10
13. tokenizer waf
14. scoring engine waf
15. sidecar proxy security
16. go security middleware
17. open source waf
18. lightweight waf
19. application security
20. web security golang

### 9.2 GitHub Topics

Set these exact topics on the GitHub repository:

```
waf
web-application-firewall
golang
go
security
reverse-proxy
middleware
owasp
sql-injection
xss
zero-dependency
single-binary
scoring-engine
sidecar-proxy
mcp
```

### 9.3 Go Package Description

For `pkg.go.dev` (this is the first line of the package-level doc comment in `doc.go`):

```go
// Package guardianwaf is a zero-dependency Web Application Firewall with
// tokenizer-based detection, scoring engine, and three deployment modes
// (standalone reverse proxy, embeddable library, sidecar proxy).
```

---

## 10. Community Guidelines

### 10.1 Tone of Voice

GuardianWAF communicates with a voice that is:

- **Technical but approachable.** Use precise terminology when it matters, but always explain concepts for people encountering them for the first time. Avoid jargon for jargon's sake.
- **Confident but not arrogant.** State what GuardianWAF does well. Acknowledge what it does not do. Never claim superiority over other projects -- let the architecture and benchmarks speak.
- **Helpful by default.** Issues, discussions, and documentation should assume the reader is competent but may be unfamiliar with WAF internals. Guide, don't gatekeep.
- **Honest about trade-offs.** Zero dependencies means more code to maintain internally. Single binary means no plugin system (yet). Acknowledge these choices openly.
- **Developer-to-developer.** Write as a practitioner sharing a tool, not as a marketing team selling a product.

### 10.2 Key Phrases to Use

These phrases should appear consistently across documentation, README, talks, and social media:

- **"Zero dependencies"** -- the headline differentiator. Always specify "zero external dependencies" when being precise.
- **"Single binary"** -- emphasizes deployment simplicity.
- **"Tokenizer-based detection"** -- differentiates the detection approach from regex matching.
- **"Scoring engine"** -- highlights the gradient response system vs. binary allow/deny.
- **"Three deployment modes"** -- shows flexibility. Always enumerate: standalone reverse proxy, embeddable library, sidecar proxy.
- **"Explainable decisions"** -- every block includes a score breakdown.
- **"Supply chain security"** -- zero deps means zero transitive risk.
- **"Sub-millisecond overhead"** -- the performance promise (use "target" until benchmarks are published).
- **"Pure Go"** -- no CGO, no C bindings, cross-compilation works out of the box.

### 10.3 Phrases to Avoid

- **"Enterprise-only"** or **"premium required"** -- the core WAF is fully open source. Never imply that essential security features are paywalled.
- **"Complex setup required"** -- contradicts the core value proposition.
- **"Requires Docker"** -- Docker is one option, not a requirement. GuardianWAF runs anywhere a Go binary runs.
- **"Better than [specific project]"** -- do not make direct negative comparisons to ModSecurity, Coraza, SafeLine, NAXSI, or any other project. Comparison tables should be factual and respectful.
- **"Military-grade"** or **"unhackable"** -- overclaims erode trust in the security community.
- **"AI-powered WAF"** -- the MCP integration enables AI workflows, but the core detection is deterministic tokenizer+scoring. Don't misrepresent the architecture.
- **"Blazingly fast"** -- overused. Use specific numbers instead.
- **"Simple"** without context -- say what is simple (deployment, configuration, tuning) rather than making a vague claim.

---

_This document is versioned alongside the codebase. Update it when the project's identity, messaging, or visual direction changes._
