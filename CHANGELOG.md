# Changelog

All notable changes to GuardianWAF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-04

### Added

#### Alerting & Notifications
- **Email Alerting**: Full SMTP support with TLS encryption
  - Configurable email templates with variable substitution
  - Per-target event filtering (block, challenge, log, all)
  - Minimum score thresholds and cooldown periods
  - Dashboard UI for email configuration
- **PagerDuty Integration**: Events API v2 format support
  - Severity mapping (critical/warning/info)
  - Deduplication keys
  - Custom payload with event details
- **Webhook Management**:
  - Slack, Discord, PagerDuty, and generic webhook types
  - Runtime add/remove via Dashboard API
  - Test alert functionality
- **MCP Alerting Tools**: 6 new MCP tools for programmatic management
  - `guardianwaf_get_alerting_status`
  - `guardianwaf_add_webhook`
  - `guardianwaf_remove_webhook`
  - `guardianwaf_add_email_target`
  - `guardianwaf_remove_email_target`
  - `guardianwaf_test_alert`

#### Security Enhancements
- **JWT ASN.1 DER Parsing**: Standalone library-free implementation
  - RSA public key parsing from PKCS#1/SubjectPublicKeyInfo
  - ECDSA curve detection (P-256, P-384, P-521)
  - Ed25519 support
  - RS256/ES256/HS256/EdDSA signature verification
  - JWKS support with key rotation

#### Events Management
- **Events Export API**: `/api/v1/events/export`
  - JSON format export
  - CSV format with proper escaping
  - Filter support (action, client_ip, path, min_score, since, until)
  - Configurable limit (up to 50,000 events)
- **Dashboard Alerting Page**: React-based management UI
  - Webhook and email configuration tabs
  - Add/remove/test targets
  - Real-time alerting statistics

#### Testing & Quality
- **E2E Test Coverage**: Added alerting and block page content tests
- **Email Alerting Tests**: 11 new test cases
- **Alerting Management Tests**: 15 MCP and webhook tests
- **Test Coverage**: Maintained ~95% overall coverage

### Changed

- MCP tool count: 15 → 21 (6 new alerting tools)
- Dashboard sidebar: Added Alerting menu item
- API endpoints: Added `/api/v1/alerting/*` routes
- Docker images: Moved from Docker Hub to GitHub Container Registry (GHCR)

### Fixed

- JWT parsing with complex ASN.1 structures
- SMTP TLS connection handling
- CSV export escaping for special characters

## [0.2.0] - 2026-03-20

### Added
- AI-powered threat analysis with 400+ providers from models.dev
- Docker auto-discovery with label-based routing
- MCP server with SSE transport support
- Routing topology graph in dashboard
- Real-time backend health monitoring

### Changed
- Improved dashboard UI/UX
- Enhanced detection engine performance

## [0.1.0] - 2026-03-17

### Added
- Initial release
- 13-layer security pipeline
- SQLi, XSS, LFI, CMDi, SSRF, XXE detection
- Bot detection with JA3/JA4 fingerprinting
- Rate limiting with token bucket
- IP ACL with radix tree CIDR matching
- Docker auto-discovery
- AI-powered threat analysis
- Real-time dashboard with SSE
- MCP server integration
- ACME/Let's Encrypt support
- WebSocket proxy support
- Multi-domain virtual hosting
- Circuit breaker pattern
- Custom rules engine

---

## Legend

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements
