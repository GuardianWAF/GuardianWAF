# Contributing to GuardianWAF

## Development Setup
1. Clone the repository
2. Ensure Go 1.25+ is installed
3. Run `make test` to verify everything works

## Guidelines
- Zero external dependencies — everything from Go stdlib
- All new features must include tests
- Run `make test` and `make vet` before submitting
- Follow existing code patterns and naming conventions

## Pull Request Process
1. Fork and create a feature branch
2. Write tests for new functionality
3. Ensure `go test ./...` passes
4. Ensure `go vet ./...` is clean
5. Submit a PR with clear description

## Code Style
- Use `gofumpt` for formatting
- Use `any` instead of `interface{}`
- Use built-in `min`/`max` functions
- Use `range N` for simple loops (Go 1.25+)
