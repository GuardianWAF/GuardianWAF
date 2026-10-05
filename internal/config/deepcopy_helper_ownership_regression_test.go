package config

import "testing"

func TestDeepCopyHelperOwnership(t *testing.T) {
	for range 3 {
		in := &Node{Kind: MapNode, Line: 7, MapKeys: []string{"a"}, MapItems: map[string]*Node{"a": {Kind: SequenceNode, Items: []*Node{{Value: "original"}, nil}}, "nil": nil}, Items: []*Node{{Value: "original"}, nil}}
		err := &ValidationError{Errors: []FieldError{{Field: "mode", Message: "original"}}}
		p := &parser{lines: []string{"original"}, pos: 2, maxNest: 10}
		nc, ec, pc := in.DeepCopy(), err.DeepCopy(), p.DeepCopy()
		gate, done := make(chan struct{}), make(chan struct{})
		go func() {
			<-gate
			in.MapKeys[0] = "changed"
			in.MapItems["a"].Items[0].Value = "changed"
			in.Items[0].Value = "changed"
			err.Errors[0].Message = "changed"
			p.lines[0] = "changed"
			close(done)
		}()
		close(gate)
		<-done
		if nc.MapKeys[0] != "a" || nc.MapItems["a"].Items[0].Value != "original" || nc.Items[0].Value != "original" || ec.Errors[0].Message != "original" || pc.lines[0] != "original" {
			t.Fatal("producer mutation changed copy")
		}
		nc.MapItems["new"] = &Node{Value: "copy-only"}
		nc.Items[0].Value = "copy-only"
		ec.Errors[0].Message = "copy-only"
		pc.lines[0] = "copy-only"
		if in.MapItems["new"] != nil || in.Items[0].Value != "changed" || err.Errors[0].Message != "changed" || p.lines[0] != "changed" {
			t.Fatal("copy mutation changed producer")
		}
		if nc.Line != 7 || pc.pos != 2 || pc.maxNest != 10 || nc.MapItems["nil"] != nil || nc.Items[1] != nil || nc.MapItems["a"].Items[1] != nil {
			t.Fatal("scalar or nil child changed")
		}
	}
	empty := (&Node{MapKeys: []string{}, MapItems: map[string]*Node{}, Items: []*Node{}}).DeepCopy()
	if empty.MapKeys == nil || empty.MapItems == nil || empty.Items == nil {
		t.Fatal("empty collections became nil")
	}
	zero := (&Node{}).DeepCopy()
	if zero.MapKeys != nil || zero.MapItems != nil || zero.Items != nil || (&parser{}).DeepCopy().lines != nil || (&ValidationError{}).DeepCopy().Errors != nil {
		t.Fatal("nil collections became empty")
	}
	if (*Node)(nil).DeepCopy() != nil || (*parser)(nil).DeepCopy() != nil || (*ValidationError)(nil).DeepCopy() != nil {
		t.Fatal("nil receiver")
	}
}
