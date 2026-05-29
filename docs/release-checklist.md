# Release Checklist

Pre-release verification steps for GuardianWAF.

## Pre-Release

- [ ] All CI checks pass (build-dashboard, test, lint)
- [ ] Frontend tests pass (`cd internal/dashboard/ui && npm test`)
- [ ] Frontend lint clean (`cd internal/dashboard/ui && npm run lint`)
- [ ] Go tests pass with race detector (`make test`)
- [ ] Go vet clean (`make vet`)
- [ ] golangci-lint clean (`make lint`)
- [ ] No uncommitted changes (`git status` clean)
- [ ] Version bumped in relevant files (if applicable)
- [ ] CHANGELOG or release notes drafted

## Build Verification

- [ ] Full build succeeds (`make build`)
- [ ] Docker build succeeds (`make docker-build`)
- [ ] Smoke tests pass (`make smoke`)
- [ ] Binary runs without errors (`./guardianwaf serve --help`)
- [ ] Dashboard loads at `https://localhost:9443/`
- [ ] Dashboard hot-reload works (`make ui-dev`)

## Integration Checks

- [ ] Docker Compose test passes (`make docker-test`)
- [ ] Multi-tenant isolation verified
- [ ] SSE event streaming works in dashboard
- [ ] API endpoints respond correctly (`/api/v1/stats`, `/api/v1/events`)
- [ ] Liveness endpoint responds (`/livez`)
- [ ] Readiness endpoint responds (`/readyz`)
- [ ] Metrics endpoint responds (`/metrics`)
- [ ] Config validation works (`./guardianwaf validate -config config.yaml`)

## Release Process

1. Tag the release: `git tag -a v1.x.x -m "Release v1.x.x"`
2. Push the tag: `git push origin v1.x.x`
3. GitHub Actions release workflow runs automatically:
   - GoReleaser builds binaries for all platforms
   - SBOM generated via anchore/sbom-action
   - Docker images built and pushed to GHCR (amd64 + arm64)
4. Verify GitHub Release page has all assets
5. Verify Docker image available: `docker pull ghcr.io/guardianwaf/guardianwaf:v1.x.x`

## Post-Release

- [ ] Release notes published on GitHub
- [ ] Documentation updated (getting-started, configuration, deployment-modes)
- [ ] CLAUDE.md updated if architecture changed
- [ ] CONTRIBUTING.md updated if workflow changed
- [ ] Announcement sent (if major release)
