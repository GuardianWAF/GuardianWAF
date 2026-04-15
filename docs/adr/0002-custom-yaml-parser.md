# ADR 0002: Custom YAML Parser

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF requires a configuration format that supports:

- **Hierarchical structure** — nested maps and sequences for virtual hosts, routes, WAF rules, alerting, etc.
- **Variable substitution** — `${VAR_NAME}` and `${VAR_NAME:-default}` syntax for environment-driven configuration
- **Includes** — `!include path/to/file.yaml` to split large configs into modular files
- **Deep merging** — per-domain WAF config overrides that merge on top of global defaults
- **Comments** — for operator documentation within config files
- **Hot-reload** — detect which keys changed between two loaded configs without full reparse

Standard YAML libraries like `gopkg.in/yaml.v3` use `reflect` + struct tags to unmarshal directly into Go structs. This creates coupling between the file format and the in-memory representation: changing a field name requires updating both the struct tag and the YAML key. It also makes hot-reload difficult — the library returns a populated struct, not the parsed node tree, so diffing requires a second parse.

## Decision

Implement a custom YAML parser (`internal/config/yaml.go`) that builds a generic **node tree** from the YAML source, then explicitly maps nodes to structs via type-switch methods. This decouples parsing from representation.

### Node Tree Architecture

```go
// NodeKind represents the type of a YAML node.
type NodeKind int

const (
    ScalarNode   NodeKind = iota // string, int, float, bool, null
    MapNode                      // key: value pairs (ordered keys)
    SequenceNode                 // [item1, item2, ...]
)

// Node is the core type of the YAML parser.
type Node struct {
    Kind     NodeKind
    Value    string           // raw scalar (for ScalarNode)
    MapKeys  []string         // ordered keys (for MapNode)
    MapItems map[string]*Node // key→value pairs (for MapNode)
    Items    []*Node          // items (for SequenceNode)
    IsNull   bool             // true when value is null or ~
    Line     int              // source line number (1-based, for error reporting)
}
```

The parser uses `text/scanner` from the Go standard library — a zero-dependency token scanner that reports source positions (line/column) for every token. This enables precise error messages pointing to the exact line causing a parse failure.

### Supported YAML Subset

| Feature | Supported | Notes |
|---------|-----------|-------|
| Maps (`key: value`) | Yes | Ordered keys via `MapKeys` slice |
| Sequences (`-[ item ]`) | Yes | |
| Flow collections (`[1, 2]`, `{a: b}`) | Yes | |
| Block scalars (`|` multiline, `>` folded) | Yes | |
| Comments (`# ...`) | Yes | Stripped during scanning |
| Anchors (`&`) and aliases (`*`) | No | Not needed for GuardianWAF configs |
| Multi-document (`---`) | No | Single document per file |
| Tags (`!!str`, `!!int`) | No | Typed scalars not used |

### Variable Substitution

Environment variables are resolved during node tree construction, not during struct mapping:

```yaml
# ${VAR:-default} syntax — uses "default" if VAR is unset
database:
  host: ${DB_HOST:-localhost}
  port: ${DB_PORT:-5432}
  # If DB_PASSWORD is unset, the key is absent (no default) — triggers validation error
  password: ${DB_PASSWORD}
```

The `${VAR:-default}` pattern uses `-` as the default value delimiter (not `:-` which is valid YAML anchor syntax). The parser recognizes the `${` prefix and performs substitution before the scanner processes the token.

### Hot-Reload Diffs

Because config is stored as a node tree before being mapped to structs, hot-reload can compute a precise diff:

```go
// Compare two node trees and return changed keys as dotted paths.
// "virtual_hosts.0.waf.block_threshold" = changed key.
func Diff(old, new *Node) []string
```

This enables granular reload: if only `waf.rate_limit` changed, only that component needs to be reinitialized — not the entire WAF.

### Configuration Loading

```go
// Load reads a YAML file and returns the root Node.
func Load(path string) (*Node, error)

// LoadWithEnv reads a YAML file, substitutes env vars, and returns the root Node.
func LoadWithEnv(path string) (*Node, error)

// Include resolves !include directives recursively.
func (n *Node) ResolveIncludes(baseDir string) error
```

## Consequences

### Positive

- **Zero external dependency** — `text/scanner` is in the Go stdlib; no `gopkg.in/yaml.v3` needed
- **Decoupled format** — YAML schema can evolve without touching Go structs; add new keys freely
- **Precise error messages** — every node carries its source line number; parse errors point to the exact location
- **Hot-reload diffing** — `Diff()` returns dotted key paths of changed values, enabling granular component restart
- **Variable substitution** — `${VAR}` syntax is operator-friendly; no separate env var documentation
- **Ordered maps** — `MapKeys` preserves YAML map ordering (important for rule evaluation order)

### Negative

- **~800 lines of custom parser code** that must be maintained and kept compatible with the YAML spec
- **Custom parser edge cases** — some valid YAML patterns (anchors, tags, multi-document) are not supported; operator documentation must warn against these
- **No community bug fixes** — spec interpretation bugs must be found and fixed internally
- **Validation deferred** — struct mapping happens after parse; type errors (wrong field type) are caught late in the pipeline

### Comparison with `gopkg.in/yaml.v3`

| Feature | yaml.v3 | Custom Parser |
|---------|---------|---------------|
| Dependency | External | None (stdlib only) |
| Unmarshal target | Struct via tags | Explicit node→struct mapping |
| Error line numbers | Approximate | Exact (per-node Line field) |
| Variable substitution | External lib or manual | Built-in `${VAR}` |
| Hot-reload diffing | Not provided | `Diff(old, new)` method |
| Anchor/alias support | Yes | No |
| Multi-document support | Yes | No |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/config/yaml.go` | Scanner, Node types, Load, LoadWithEnv, Diff, ResolveIncludes |
| `internal/config/config.go` | Typed config structs (Config, WAFConfig, VirtualHostConfig, etc.) |
| `internal/config/validate.go` | Post-load validation (required fields, value ranges) |
| `internal/config/defaults.go` | Default values merged before env overlay |
| `internal/config/serialize.go` | Struct→YAML serialization (for config write-back) |

## References

- [YAML 1.2 Specification](https://yaml.org/spec/1.2.2/)
- [Go text/scanner package](https://pkg.go.dev/go/token#Scanner)
- [ADR 0001: Zero External Go Dependencies](./0001-zero-external-dependencies.md)
