# Infrastructure Security Findings -- GuardianWAF

**Scan Date:** 2026-04-16
**Scope:** INFRASTRUCTURE SECURITY (HUNT phase)
**Repository:** D:\CODEBOX\PROJECTS\GuardianWAF

---

## 1. Dockerfile Security

### Finding 1 -- Non-Root User Configuration (PASS)

**File:** `Dockerfile` (root), `examples/sidecar/Dockerfile`

Both Dockerfiles create and switch to a non-root user: `adduser -D -H -s /sbin/nologin guardianwaf` followed by `USER guardianwaf`. The root Dockerfile additionally creates the guardianwaf user with ownership of /var/lib/guardianwaf and sets WORKDIR before the USER directive.

**Verdict:** PASS -- Containers run as non-root. No privilege escalation via user context.

---

### Finding 2 -- Minimal Base Image (PASS)

**File:** `Dockerfile` (root) -- `FROM alpine:3.21.3`

Alpine Linux 3.21.3 is a specific pinned minimal release. Multi-stage build is used, so the Go builder image does not appear in the final runtime image.

**Verdict:** PASS -- Minimal base image, pinned version, no builder image leakage.

---

### Finding 3 -- No Secrets in Dockerfile Layers (PASS)

**File:** `Dockerfile` (root)

Build arguments (VERSION, COMMIT, DATE, IMAGE_VERSION) are passed as --build-arg during docker buildx build and consumed only as Go linker flags (-ldflags) during binary compilation. They are not persisted as environment variables or files in the final image. The Dockerfile has no ENV, ARG, or RUN statements that embed credentials.

**Verdict:** PASS -- No embedded secrets in image layers.

---

### Finding 4 -- Config File Permissions (ADVISORY)

**File:** `Dockerfile` (root)

The root Dockerfile creates /etc/guardianwaf implicitly via volume mount at runtime. Config files are mounted :ro (read-only) in all compose files, and production Kubernetes manifests explicitly set readOnly: true on the config mount. There is no explicit umask or permission chmod applied to /etc/guardianwaf inside the Dockerfile.

**Verdict:** ADVISORY -- Config file permissions handled at mount/manifest level, not baked into image. Acceptable given defense-in-depth of :ro mounts.

---

## 2. docker-compose.yml Security

### Finding 5 -- Exposed Ports (INFO)

**Files:** `docker-compose.yml`, `docker-compose.prod.yml`, `examples/sidecar/docker-compose.yml`

docker-compose.yml: ports 18080:8088 and 19443:9443 (dev access only).
docker-compose.prod.yml: No explicit ports block -- uses internal networks only.
examples/sidecar/docker-compose.yml: ports 8080:8080 and 9443:9443.

No sensitive services (e.g., Docker socket API port 2375/2376) are accidentally forwarded.

**Verdict:** INFO -- Port exposure is intentional and scoped to development.

---

### Finding 6 -- Network Isolation (PASS)

**Files:** `docker-compose.yml`, `examples/sidecar/docker-compose.yml`

Both define an isolated bridge network. Backend services use expose: instead of ports:, preventing direct host access. GuardianWAF acts as the sole ingress point.

**Verdict:** PASS -- Bridge network isolation prevents lateral movement.

---

### Finding 7 -- Volume Mounts (PASS with Advisory)

**File:** `docker-compose.yml` -- Config file mounted :ro, named volume for data.

docker-compose.prod.yml explicitly comments out the Docker socket mount and documents: "DO NOT use socket mount in production -- it is a privilege escalation vector."

**Verdict:** PASS (with Advisory) -- Production socket mount is commented. Uncommenting it re-enables a privilege escalation vector.

---

### Finding 8 -- Environment Variable Security (INFO)

**File:** `docker-compose.yml`

No secrets are passed via environment: in the development compose file. Sensitive fields (dashboard password, AI API key) are commented out with documentation to use GWAF_DASHBOARD_PASSWORD and GWAF_AI_API_KEY env vars instead.

**Verdict:** INFO -- No hardcoded secrets. Production env vars are documented for external injection.

---
## 3. CI/CD Security

### Finding 9 -- Secret Handling in Workflows (PASS)

**File:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`

- secrets.GITHUB_TOKEN and secrets.CODECOV_TOKEN are used but never logged or passed to untrusted steps.
- No secrets appear as plain-text in workflow YAML files.
- Build arguments are derived from GitHub context, not user-controlled secrets.
- SBOM generation runs without passing secrets.
- GITHUB_TOKEN has minimal contents:write and packages:write permissions scoped to the release job only.
- website.yml uses id-token:write only for GitHub Pages OIDC deployment.

**Verdict:** PASS -- Secrets properly scoped, no leakage expected.

---

### Finding 10 -- Supply Chain Security (PASS)

**File:** `.github/workflows/release.yml`, `.pre-commit-config.yaml`

- Multi-arch image build (linux/amd64,linux/arm64) via Docker Buildx with GHA cache -- build cache not shared publicly.
- GoReleaser runs before Docker build, providing a reproducible binary signing path.
- SBOM (SPDX JSON) generated via anchore/sbom-action and attached to GitHub Release.
- No latest tag pushed from feature branches.
- golangci-lint v1.64.8 and editorconfig-checker v2.7.2 are pinned to specific revisions.

**Verdict:** PASS -- Supply chain hardened with pinned versions, SBOM, and linter gates.

---

## 4. Infrastructure as Code

### Finding 11 -- Kubernetes Manifests: Security Context (PASS)

**Files:** `examples/kubernetes/deployment.yaml`, `contrib/k8s/deployment.yaml`

Both include strong securityContext:
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop: ["ALL"]
```
This matches the Kubernetes Pod Security Standards restricted profile.

**Verdict:** PASS -- Kubernetes deployments follow Pod Security Standards.

---

### Finding 12 -- Kubernetes Manifests: Resource Limits (PASS)

**Files:** `examples/kubernetes/deployment.yaml`, `contrib/k8s/deployment.yaml`, `examples/sidecar/docker-compose.yml`

All manifests set CPU and memory limits (256Mi memory, 500m CPU maximum). Sidecar compose sets deploy.resources.limits (128M memory, 0.5 CPU).

**Verdict:** PASS -- Resource limits prevent container resource exhaustion attacks.

---

### Finding 13 -- Kubernetes: Ingress TLS and Dashboard Auth (ADVISORY)

**Files:** `examples/kubernetes/ingress.yaml`, `contrib/k8s/ingress.yaml`

Both ingress manifests require TLS via cert-manager (cert-manager.io/cluster-issuer). The dashboard ingress uses nginx.ingress.kubernetes.io/auth-type: basic -- but the guardianwaf-dashboard-auth secret is not included in the repository and must be provisioned out-of-band.

**Verdict:** ADVISORY -- TLS enforced via cert-manager. Basic Auth secret must be created manually (not in repo). A misconfigured cluster could expose the dashboard without auth if annotations are removed.

---

### Finding 14 -- Helm Charts (N/A)

No Helm charts found in the repository. Kubernetes manifests are raw YAML.

**Verdict:** N/A -- No Helm charts to audit.

---

## 5. Unix Socket / Docker Daemon Security

### Finding 15 -- Docker Socket Mount Disabled in Production (PASS)

**File:** `internal/docker/client.go`, `docker-compose.prod.yml`

Two Docker client modes provided: (1) CLI-based client (NewClient / NewTLSClient) -- works on Unix sockets, Windows named pipes, and remote daemons via Docker contexts or TLS. (2) Direct HTTP socket client (NewHTTPClient) -- low-latency polling via Unix socket HTTP, Linux/macOS only.

docker-compose.prod.yml explicitly comments out the socket mount and documents: "DO NOT use socket mount in production -- it is a privilege escalation vector."

**Verdict:** PASS -- Socket mount is production-disabled by design. TLS-based Docker client is the documented alternative.

---

### Finding 16 -- Command Injection Prevention (PASS)

**File:** `internal/docker/client.go`

The isSafeContainerRef() function validates container IDs and names before passing them to docker inspect. It allows only alphanumeric characters plus dash, underscore, and dot. Container IDs from docker ps --format json are validated before being appended to docker inspect calls. Shell metacharacters are explicitly rejected.

**Verdict:** PASS -- CLI command injection mitigated via allowlist input validation.

---

### Finding 17 -- Windows Named Pipe Support (PASS)

**File:** `internal/docker/client.go`

On Windows, the hostFlag is not set for the CLI client, so dockerCmd omits the --host flag and relies on the default Docker context (which handles Windows named pipes transparently). The NewHTTPClient (direct socket HTTP) is explicitly guarded to Linux/macOS only.

**Verdict:** PASS -- Windows named pipe access handled through Docker CLI layer, not direct socket access.

---

## Summary

| # | Category | Finding | Severity | Status |
|---|---|---|---|---|
| 1 | Dockerfile | Non-root user | -- | PASS |
| 2 | Dockerfile | Minimal pinned base image | -- | PASS |
| 3 | Dockerfile | No secrets in layers | -- | PASS |
| 4 | Dockerfile | Config file permissions | Advisory | PASS (Advisory) |
| 5 | docker-compose | Exposed ports | Info | PASS |
| 6 | docker-compose | Network isolation | -- | PASS |
| 7 | docker-compose | Volume mounts | Advisory | PASS (Advisory) |
| 8 | docker-compose | Env var security | Info | PASS |
| 9 | CI/CD | Secret handling | -- | PASS |
| 10 | CI/CD | Supply chain hardening | -- | PASS |
| 11 | K8s | Security context (PSS restricted) | -- | PASS |
| 12 | K8s | Resource limits | -- | PASS |
| 13 | K8s | Ingress TLS / dashboard auth | Advisory | PASS (Advisory) |
| 14 | Helm | No Helm charts | -- | N/A |
| 15 | Docker Socket | Socket mount disabled in prod | -- | PASS |
| 16 | Docker CLI | Command injection prevention | -- | PASS |
| 17 | Docker Windows | Named pipe support | -- | PASS |

**Overall: HARDENED.** No critical or high-severity issues found. The codebase demonstrates strong infrastructure security hygiene: non-root containers, minimal images, network isolation, TLS-based Docker connectivity in production, Kubernetes Pod Security Standards, and supply chain hardening with SBOMs and pinned dependencies.

**Advisories to monitor:**
1. Uncommenting the Docker socket mount in docker-compose.prod.yml re-enables a privilege escalation vector.
2. Dashboard Basic Auth secret (guardianwaf-dashboard-auth) must be provisioned out-of-band for K8s deployments.
3. Config file permission hardening is delegated to mount flags rather than baked into the image.

---
*Generated by HUNT Phase -- INFRASTRUCTURE SECURITY scan*
