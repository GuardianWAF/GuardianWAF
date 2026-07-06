package config

import "testing"

func TestDeepCopy_SimpleGeneratedTypes(t *testing.T) {
	t.Run("DetectorConfig", func(t *testing.T) {
		in := &DetectorConfig{Enabled: true, Multiplier: 2.5}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if *out != *in {
			t.Fatalf("copied value mismatch: got %+v want %+v", *out, *in)
		}
	})

	t.Run("ValidationError", func(t *testing.T) {
		in := &ValidationError{Errors: []FieldError{{Field: "mode", Message: "invalid"}}}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if len(out.Errors) != 1 || out.Errors[0] != in.Errors[0] {
			t.Fatalf("copied value mismatch: got %+v want %+v", out.Errors, in.Errors)
		}
	})

	t.Run("FieldError", func(t *testing.T) {
		in := &FieldError{Field: "waf.mode", Message: "bad value"}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if *out != *in {
			t.Fatalf("copied value mismatch: got %+v want %+v", *out, *in)
		}
	})

	t.Run("Node", func(t *testing.T) {
		in := &Node{Kind: ScalarNode, Value: "value", IsNull: false, Line: 7}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if out.Kind != in.Kind || out.Value != in.Value || out.IsNull != in.IsNull || out.Line != in.Line {
			t.Fatalf("copied value mismatch: got %+v want %+v", *out, *in)
		}
	})

	t.Run("ParseError", func(t *testing.T) {
		in := &ParseError{Line: 3, Column: 9, Message: "unexpected token"}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if *out != *in {
			t.Fatalf("copied value mismatch: got %+v want %+v", *out, *in)
		}
	})

	t.Run("parser", func(t *testing.T) {
		in := &parser{lines: []string{"a: 1", "b: 2"}, pos: 1, maxNest: 10}
		out := in.DeepCopy()
		if out == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if out == in {
			t.Fatal("DeepCopy returned same pointer")
		}
		if out.pos != in.pos || out.maxNest != in.maxNest || len(out.lines) != len(in.lines) {
			t.Fatalf("copied value mismatch: got %+v want %+v", *out, *in)
		}
		for i := range in.lines {
			if out.lines[i] != in.lines[i] {
				t.Fatalf("copied line mismatch at %d: got %q want %q", i, out.lines[i], in.lines[i])
			}
		}
	})
}

func TestDeepCopy_SimpleGeneratedTypes_Nil(t *testing.T) {
	var detector *DetectorConfig
	if detector.DeepCopy() != nil {
		t.Fatal("nil DetectorConfig DeepCopy should return nil")
	}

	var validationErr *ValidationError
	if validationErr.DeepCopy() != nil {
		t.Fatal("nil ValidationError DeepCopy should return nil")
	}

	var fieldErr *FieldError
	if fieldErr.DeepCopy() != nil {
		t.Fatal("nil FieldError DeepCopy should return nil")
	}

	var node *Node
	if node.DeepCopy() != nil {
		t.Fatal("nil Node DeepCopy should return nil")
	}

	var parseErr *ParseError
	if parseErr.DeepCopy() != nil {
		t.Fatal("nil ParseError DeepCopy should return nil")
	}

	var p *parser
	if p.DeepCopy() != nil {
		t.Fatal("nil parser DeepCopy should return nil")
	}
}
