package config

import (
	"strings"
	"testing"
)

func TestYAMLParser(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		check  func(t *testing.T, n *Node)
		errMsg string // if non-empty, expect an error containing this string
	}{
		// === Scalar types ===
		{
			name:  "simple string value",
			input: "name: hello",
			check: func(t *testing.T, n *Node) {
				assertKind(t, n, MapNode)
				assertEqual(t, n.Get("name").String(), "hello")
			},
		},
		{
			name:  "integer value",
			input: "port: 8080",
			check: func(t *testing.T, n *Node) {
				v, err := n.Get("port").Int()
				if err != nil {
					t.Fatal(err)
				}
				if v != 8080 {
					t.Fatalf("expected 8080, got %d", v)
				}
			},
		},
		{
			name:  "negative integer",
			input: "offset: -42",
			check: func(t *testing.T, n *Node) {
				v, err := n.Get("offset").Int()
				if err != nil {
					t.Fatal(err)
				}
				if v != -42 {
					t.Fatalf("expected -42, got %d", v)
				}
			},
		},
		{
			name:  "float value",
			input: "score: 3.14",
			check: func(t *testing.T, n *Node) {
				v, err := n.Get("score").Float64()
				if err != nil {
					t.Fatal(err)
				}
				if v != 3.14 {
					t.Fatalf("expected 3.14, got %f", v)
				}
			},
		},
		{
			name:  "boolean true variants",
			input: "a: true\nb: yes\nc: on",
			check: func(t *testing.T, n *Node) {
				for _, key := range []string{"a", "b", "c"} {
					v, err := n.Get(key).Bool()
					if err != nil {
						t.Fatalf("key %s: %v", key, err)
					}
					if !v {
						t.Fatalf("expected true for key %s", key)
					}
				}
			},
		},
		{
			name:  "boolean false variants",
			input: "a: false\nb: no\nc: off",
			check: func(t *testing.T, n *Node) {
				for _, key := range []string{"a", "b", "c"} {
					v, err := n.Get(key).Bool()
					if err != nil {
						t.Fatalf("key %s: %v", key, err)
					}
					if v {
						t.Fatalf("expected false for key %s", key)
					}
				}
			},
		},
		{
			name:  "null values",
			input: "a: null\nb: ~\nc: Null\nd: NULL\ne:",
			check: func(t *testing.T, n *Node) {
				for _, key := range []string{"a", "b", "c", "d", "e"} {
					child := n.Get(key)
					if child == nil {
						t.Fatalf("key %s not found", key)
					}
					if !child.IsNull {
						t.Fatalf("expected null for key %s", key)
					}
				}
			},
		},

		// === Quoted strings ===
		{
			name:  "double-quoted string with escapes",
			input: `message: "hello\nworld\t!"`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("message").String(), "hello\nworld\t!")
			},
		},
		{
			name:  "single-quoted string",
			input: "message: 'it''s alive'",
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("message").String(), "it's alive")
			},
		},
		{
			name:  "double-quoted with backslash escapes",
			input: `path: "C:\\Users\\test"`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("path").String(), "C:\\Users\\test")
			},
		},
		{
			name:  "double-quoted with embedded quote",
			input: `msg: "say \"hi\""`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("msg").String(), `say "hi"`)
			},
		},

		// === Comments ===
		{
			name: "standalone comment lines",
			input: `# This is a comment
name: test
# Another comment
port: 80`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("name").String(), "test")
				v, _ := n.Get("port").Int()
				if v != 80 {
					t.Fatalf("expected 80, got %d", v)
				}
			},
		},
		{
			name:  "inline comment",
			input: "name: hello # this is a comment",
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("name").String(), "hello")
			},
		},

		// === Nested maps ===
		{
			name: "nested maps 3 levels",
			input: `server:
  tls:
    enabled: true
    port: 443`,
			check: func(t *testing.T, n *Node) {
				tls := n.GetPath("server", "tls")
				if tls == nil {
					t.Fatal("path server.tls not found")
				}
				v, _ := tls.Get("enabled").Bool()
				if !v {
					t.Fatal("expected true")
				}
				p, _ := tls.Get("port").Int()
				if p != 443 {
					t.Fatalf("expected 443, got %d", p)
				}
			},
		},
		{
			name: "deeply nested 5+ levels",
			input: `level1:
  level2:
    level3:
      level4:
        level5:
          level6:
            value: deep`,
			check: func(t *testing.T, n *Node) {
				v := n.GetPath("level1", "level2", "level3", "level4", "level5", "level6", "value")
				if v == nil {
					t.Fatal("deep path not found")
				}
				assertEqual(t, v.String(), "deep")
			},
		},

		// === Block sequences ===
		{
			name: "simple block sequence",
			input: `items:
  - apple
  - banana
  - cherry`,
			check: func(t *testing.T, n *Node) {
				items := n.Get("items").Slice()
				if len(items) != 3 {
					t.Fatalf("expected 3 items, got %d", len(items))
				}
				assertEqual(t, items[0].String(), "apple")
				assertEqual(t, items[1].String(), "banana")
				assertEqual(t, items[2].String(), "cherry")
			},
		},
		{
			name: "sequence of maps",
			input: `servers:
  - host: alpha
    port: 8080
  - host: beta
    port: 9090`,
			check: func(t *testing.T, n *Node) {
				servers := n.Get("servers").Slice()
				if len(servers) != 2 {
					t.Fatalf("expected 2 servers, got %d", len(servers))
				}
				assertEqual(t, servers[0].Get("host").String(), "alpha")
				p, _ := servers[0].Get("port").Int()
				if p != 8080 {
					t.Fatalf("expected 8080, got %d", p)
				}
				assertEqual(t, servers[1].Get("host").String(), "beta")
				p2, _ := servers[1].Get("port").Int()
				if p2 != 9090 {
					t.Fatalf("expected 9090, got %d", p2)
				}
			},
		},

		// === Flow sequences ===
		{
			name:  "flow sequence",
			input: "methods: [GET, POST, PUT, DELETE]",
			check: func(t *testing.T, n *Node) {
				items := n.Get("methods").Slice()
				if len(items) != 4 {
					t.Fatalf("expected 4 items, got %d", len(items))
				}
				assertEqual(t, items[0].String(), "GET")
				assertEqual(t, items[1].String(), "POST")
				assertEqual(t, items[2].String(), "PUT")
				assertEqual(t, items[3].String(), "DELETE")
			},
		},

		// === Flow maps ===
		{
			name:  "flow map",
			input: "limits: {requests: 100, window: 10, burst: 20}",
			check: func(t *testing.T, n *Node) {
				lim := n.Get("limits")
				assertKind(t, lim, MapNode)
				v, _ := lim.Get("requests").Int()
				if v != 100 {
					t.Fatalf("expected 100, got %d", v)
				}
				w, _ := lim.Get("window").Int()
				if w != 10 {
					t.Fatalf("expected 10, got %d", w)
				}
				b, _ := lim.Get("burst").Int()
				if b != 20 {
					t.Fatalf("expected 20, got %d", b)
				}
			},
		},

		// === Literal block scalar ===
		{
			name: "literal block scalar",
			input: `description: |
  This is line 1.
  This is line 2.
  This is line 3.`,
			check: func(t *testing.T, n *Node) {
				expected := "This is line 1.\nThis is line 2.\nThis is line 3.\n"
				assertEqual(t, n.Get("description").String(), expected)
			},
		},
		{
			name: "literal block strip",
			input: `text: |-
  hello
  world`,
			check: func(t *testing.T, n *Node) {
				expected := "hello\nworld"
				assertEqual(t, n.Get("text").String(), expected)
			},
		},

		// === Folded block scalar ===
		{
			name: "folded block scalar",
			input: `description: >
  This is a long
  paragraph that should
  be folded.`,
			check: func(t *testing.T, n *Node) {
				v := n.Get("description").String()
				if !strings.Contains(v, "This is a long paragraph") {
					t.Fatalf("expected folded text, got: %q", v)
				}
			},
		},
		{
			name: "folded block strip",
			input: `text: >-
  folded
  text`,
			check: func(t *testing.T, n *Node) {
				expected := "folded text"
				assertEqual(t, n.Get("text").String(), expected)
			},
		},

		// === Empty values ===
		{
			name: "empty value is null",
			input: `key1:
key2: value2`,
			check: func(t *testing.T, n *Node) {
				if !n.Get("key1").IsNull {
					t.Fatal("expected key1 to be null")
				}
				assertEqual(t, n.Get("key2").String(), "value2")
			},
		},

		// === Mixed nesting ===
		{
			name: "maps with sequences and sequences with maps",
			input: `database:
  hosts:
    - host: primary
      port: 5432
    - host: replica
      port: 5433
  options:
    - read_only
    - timeout_30s`,
			check: func(t *testing.T, n *Node) {
				db := n.Get("database")
				hosts := db.Get("hosts").Slice()
				if len(hosts) != 2 {
					t.Fatalf("expected 2 hosts, got %d", len(hosts))
				}
				assertEqual(t, hosts[0].Get("host").String(), "primary")
				p, _ := hosts[0].Get("port").Int()
				if p != 5432 {
					t.Fatalf("expected 5432, got %d", p)
				}

				opts := db.Get("options").Slice()
				if len(opts) != 2 {
					t.Fatalf("expected 2 options, got %d", len(opts))
				}
				assertEqual(t, opts[0].String(), "read_only")
				assertEqual(t, opts[1].String(), "timeout_30s")
			},
		},

		// === UTF-8 content ===
		{
			name:  "UTF-8 content",
			input: "greeting: Merhaba Dünya\nauthor: 日本語テスト",
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("greeting").String(), "Merhaba Dünya")
				assertEqual(t, n.Get("author").String(), "日本語テスト")
			},
		},

		// === Windows line endings ===
		{
			name:  "windows line endings",
			input: "name: test\r\nport: 80\r\n",
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("name").String(), "test")
				v, _ := n.Get("port").Int()
				if v != 80 {
					t.Fatalf("expected 80, got %d", v)
				}
			},
		},

		// === Empty document ===
		{
			name:  "empty document",
			input: "",
			check: func(t *testing.T, n *Node) {
				assertKind(t, n, MapNode)
			},
		},
		{
			name:  "document with only comments",
			input: "# just a comment\n# another comment\n",
			check: func(t *testing.T, n *Node) {
				assertKind(t, n, MapNode)
			},
		},

		// === GetPath returning nil for missing path ===
		{
			name:  "GetPath returns nil for missing",
			input: "a: 1",
			check: func(t *testing.T, n *Node) {
				if n.GetPath("a", "b", "c") != nil {
					t.Fatal("expected nil for non-existent path")
				}
				if n.GetPath("nonexistent") != nil {
					t.Fatal("expected nil for missing key")
				}
			},
		},

		// === Nil node safety ===
		{
			name:  "nil node methods",
			input: "key: value",
			check: func(t *testing.T, n *Node) {
				var nilNode *Node
				if nilNode.String() != "" {
					t.Fatal("expected empty string from nil node")
				}
				if _, err := nilNode.Int(); err == nil {
					t.Fatal("expected error from nil node Int()")
				}
				if _, err := nilNode.Float64(); err == nil {
					t.Fatal("expected error from nil node Float64()")
				}
				if _, err := nilNode.Bool(); err == nil {
					t.Fatal("expected error from nil node Bool()")
				}
				if nilNode.Slice() != nil {
					t.Fatal("expected nil from nil node Slice()")
				}
				if nilNode.Map() != nil {
					t.Fatal("expected nil from nil node Map()")
				}
				if nilNode.Get("key") != nil {
					t.Fatal("expected nil from nil node Get()")
				}
			},
		},

		// === Full GuardianWAF config snippet ===
		{
			name: "GuardianWAF realistic config",
			input: `# GuardianWAF Configuration
server:
  listen: 0.0.0.0
  port: 8080
  tls:
    enabled: true
    cert_file: /etc/ssl/cert.pem
    key_file: /etc/ssl/key.pem

engine:
  mode: reverse_proxy
  threshold: 10
  paranoia_level: 2
  allowed_methods: [GET, POST, PUT, DELETE, PATCH]
  max_body_size: 1048576

detection:
  sqli:
    enabled: true
    score_multiplier: 1.0
  xss:
    enabled: true
    score_multiplier: 1.5
  lfi:
    enabled: true
    score_multiplier: 1.0

rate_limit:
  rules:
    - scope: ip
      requests: 100
      window: 10
      burst: 20
    - scope: path
      requests: 50
      window: 5
      burst: 10

proxy:
  backends:
    - url: http://backend1:8080
      weight: 3
    - url: http://backend2:8080
      weight: 1
  health_check_interval: 30

logging:
  level: info
  format: json
  output: /var/log/guardianwaf/access.log`,
			check: func(t *testing.T, n *Node) {
				// Server
				assertEqual(t, n.GetPath("server", "listen").String(), "0.0.0.0")
				port, _ := n.GetPath("server", "port").Int()
				if port != 8080 {
					t.Fatalf("expected 8080, got %d", port)
				}
				tlsEnabled, _ := n.GetPath("server", "tls", "enabled").Bool()
				if !tlsEnabled {
					t.Fatal("expected tls enabled")
				}

				// Engine
				threshold, _ := n.GetPath("engine", "threshold").Int()
				if threshold != 10 {
					t.Fatalf("expected threshold 10, got %d", threshold)
				}
				methods := n.GetPath("engine", "allowed_methods").Slice()
				if len(methods) != 5 {
					t.Fatalf("expected 5 methods, got %d", len(methods))
				}
				assertEqual(t, methods[0].String(), "GET")

				// Detection
				sqlMul, _ := n.GetPath("detection", "sqli", "score_multiplier").Float64()
				if sqlMul != 1.0 {
					t.Fatalf("expected 1.0, got %f", sqlMul)
				}
				xssMul, _ := n.GetPath("detection", "xss", "score_multiplier").Float64()
				if xssMul != 1.5 {
					t.Fatalf("expected 1.5, got %f", xssMul)
				}

				// Rate limit rules
				rules := n.GetPath("rate_limit", "rules").Slice()
				if len(rules) != 2 {
					t.Fatalf("expected 2 rules, got %d", len(rules))
				}
				assertEqual(t, rules[0].Get("scope").String(), "ip")
				req, _ := rules[0].Get("requests").Int()
				if req != 100 {
					t.Fatalf("expected 100, got %d", req)
				}

				// Proxy backends
				backends := n.GetPath("proxy", "backends").Slice()
				if len(backends) != 2 {
					t.Fatalf("expected 2 backends, got %d", len(backends))
				}
				assertEqual(t, backends[0].Get("url").String(), "http://backend1:8080")
				w, _ := backends[0].Get("weight").Int()
				if w != 3 {
					t.Fatalf("expected weight 3, got %d", w)
				}

				// Logging
				assertEqual(t, n.GetPath("logging", "level").String(), "info")
				assertEqual(t, n.GetPath("logging", "format").String(), "json")
			},
		},

		// === Multiple data types in one document ===
		{
			name: "multiple scalar types together",
			input: `string_val: hello
int_val: 42
neg_int: -7
float_val: 2.718
bool_true: true
bool_false: false
null_val: null
tilde_null: ~`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("string_val").String(), "hello")
				iv, _ := n.Get("int_val").Int()
				if iv != 42 {
					t.Fatalf("expected 42, got %d", iv)
				}
				nv, _ := n.Get("neg_int").Int()
				if nv != -7 {
					t.Fatalf("expected -7, got %d", nv)
				}
				fv, _ := n.Get("float_val").Float64()
				if fv != 2.718 {
					t.Fatalf("expected 2.718, got %f", fv)
				}
				bv, _ := n.Get("bool_true").Bool()
				if !bv {
					t.Fatal("expected true")
				}
				bf, _ := n.Get("bool_false").Bool()
				if bf {
					t.Fatal("expected false")
				}
				if !n.Get("null_val").IsNull {
					t.Fatal("expected null")
				}
				if !n.Get("tilde_null").IsNull {
					t.Fatal("expected null for ~")
				}
			},
		},

		// === Top-level sequence ===
		{
			name: "top-level block sequence",
			input: `- item1
- item2
- item3`,
			check: func(t *testing.T, n *Node) {
				assertKind(t, n, SequenceNode)
				items := n.Slice()
				if len(items) != 3 {
					t.Fatalf("expected 3 items, got %d", len(items))
				}
				assertEqual(t, items[0].String(), "item1")
			},
		},

		// === Colons in values ===
		{
			name:  "colon in value URL",
			input: "url: http://example.com:8080/path",
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("url").String(), "http://example.com:8080/path")
			},
		},

		// === Quoted key ===
		{
			name:  "double-quoted key",
			input: `"special key": value`,
			check: func(t *testing.T, n *Node) {
				assertEqual(t, n.Get("special key").String(), "value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := Parse([]byte(tt.input))
			if tt.errMsg != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got: %v", tt.errMsg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, node)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		errMsg string
	}{
		{
			name:   "invalid UTF-8",
			input:  string([]byte{0xff, 0xfe, 0xfd}),
			errMsg: "not valid UTF-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errMsg)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestParseErrorStruct(t *testing.T) {
	pe := &ParseError{Line: 5, Column: 10, Message: "unexpected token"}
	expected := "yaml: line 5, column 10: unexpected token"
	if pe.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, pe.Error())
	}

	pe2 := &ParseError{Line: 3, Message: "bad indent"}
	expected2 := "yaml: line 3: bad indent"
	if pe2.Error() != expected2 {
		t.Fatalf("expected %q, got %q", expected2, pe2.Error())
	}
}

func TestNodeKindString(t *testing.T) {
	if ScalarNode.String() != "Scalar" {
		t.Fatalf("expected Scalar, got %s", ScalarNode.String())
	}
	if MapNode.String() != "Map" {
		t.Fatalf("expected Map, got %s", MapNode.String())
	}
	if SequenceNode.String() != "Sequence" {
		t.Fatalf("expected Sequence, got %s", SequenceNode.String())
	}
}

func TestFlowSequenceNested(t *testing.T) {
	input := "matrix: [[1, 2], [3, 4]]"
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	matrix := node.Get("matrix").Slice()
	if len(matrix) != 2 {
		t.Fatalf("expected 2 items, got %d", len(matrix))
	}
	row1 := matrix[0].Slice()
	if len(row1) != 2 {
		t.Fatalf("expected 2 items in row1, got %d", len(row1))
	}
	v, _ := row1[0].Int()
	if v != 1 {
		t.Fatalf("expected 1, got %d", v)
	}
}

func TestEmptyFlowSequence(t *testing.T) {
	input := "items: []"
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	items := node.Get("items").Slice()
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}
}

func TestEmptyFlowMap(t *testing.T) {
	input := "data: {}"
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	m := node.Get("data").Map()
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(m))
	}
}

func TestSequenceWithFlowSequenceItems(t *testing.T) {
	input := `rules:
  - [GET, POST]
  - [PUT, DELETE]`
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	rules := node.Get("rules").Slice()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	first := rules[0].Slice()
	if len(first) != 2 {
		t.Fatalf("expected 2 items in first rule, got %d", len(first))
	}
	assertEqual(t, first[0].String(), "GET")
}

func TestMapOrdering(t *testing.T) {
	input := `z_key: 1
a_key: 2
m_key: 3`
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != MapNode {
		t.Fatal("expected MapNode")
	}
	// Verify insertion order is preserved
	expected := []string{"z_key", "a_key", "m_key"}
	if len(node.MapKeys) != len(expected) {
		t.Fatalf("expected %d keys, got %d", len(expected), len(node.MapKeys))
	}
	for i, k := range expected {
		if node.MapKeys[i] != k {
			t.Fatalf("expected key[%d]=%q, got %q", i, k, node.MapKeys[i])
		}
	}
}

func TestInlineCommentInQuotedString(t *testing.T) {
	input := `value: "has # inside"` // # inside quotes is not a comment
	node, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, node.Get("value").String(), "has # inside")
}

// helper functions

func assertKind(t *testing.T, n *Node, kind NodeKind) {
	t.Helper()
	if n == nil {
		t.Fatalf("node is nil, expected kind %s", kind)
	}
	if n.Kind != kind {
		t.Fatalf("expected kind %s, got %s", kind, n.Kind)
	}
}

func assertEqual(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
