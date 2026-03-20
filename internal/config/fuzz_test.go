package config

import "testing"

func FuzzYAMLParser(f *testing.F) {
	f.Add([]byte("mode: enforce\nlisten: \":8088\""))
	f.Add([]byte(""))
	f.Add([]byte("key: value"))
	f.Add([]byte("list:\n  - item1\n  - item2"))
	f.Add([]byte("nested:\n  key: value\n  sub:\n    deep: true"))
	f.Add([]byte("# comment only"))
	f.Add([]byte("flow_seq: [a, b, c]"))
	f.Add([]byte("flow_map: {key1: val1, key2: val2}"))
	f.Add([]byte("literal: |\n  line1\n  line2"))
	f.Add([]byte("folded: >\n  line1\n  line2"))
	f.Add([]byte("null_val: ~"))
	f.Add([]byte("null_val: null"))
	f.Add([]byte("bool_val: true"))
	f.Add([]byte("bool_val: false"))
	f.Add([]byte("int_val: 42"))
	f.Add([]byte("float_val: 3.14"))
	f.Add([]byte("quoted: \"hello world\""))
	f.Add([]byte("single_quoted: 'it''s a test'"))
	f.Add([]byte("colon_in_value: \"http://example.com\""))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse should not panic
		node, err := Parse(data)
		if err != nil {
			return // parse errors are expected for random input
		}
		if node == nil {
			return
		}

		// If parsing succeeded, PopulateFromNode should not panic
		cfg := DefaultConfig()
		_ = PopulateFromNode(cfg, node)
	})
}

func FuzzYAMLParserWithValidation(f *testing.F) {
	minimal := []byte("mode: enforce\nlisten: \":8088\"")
	f.Add(minimal)

	full := []byte(`mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
    detectors:
      sqli:
        enabled: true
        multiplier: 1.0
logging:
  level: info
  format: json
events:
  storage: memory
  max_events: 1000`)
	f.Add(full)

	f.Fuzz(func(t *testing.T, data []byte) {
		node, err := Parse(data)
		if err != nil {
			return
		}

		cfg := DefaultConfig()
		err = PopulateFromNode(cfg, node)
		if err != nil {
			return
		}

		// Validate should not panic
		_ = Validate(cfg)
	})
}
