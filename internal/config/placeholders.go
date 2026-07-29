package config

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

func capturePlaceholderBindings(raw []byte, node *Node) map[string]PlaceholderBinding {
	if node == nil || len(raw) == 0 {
		return nil
	}
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
	lines := strings.Split(string(normalized), "\n")
	bindings := make(map[string]PlaceholderBinding)
	collectBindingsFromNode(node, "", lines, bindings)
	if len(bindings) == 0 {
		return nil
	}
	return bindings
}

func collectBindingsFromNode(node *Node, path string, lines []string, bindings map[string]PlaceholderBinding) {
	if node == nil {
		return
	}
	switch node.Kind {
	case MapNode:
		for _, key := range node.MapKeys {
			child := node.MapItems[key]
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			collectBindingsFromNode(child, childPath, lines, bindings)
		}
	case SequenceNode:
		for i, child := range node.Items {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				childPath = fmt.Sprintf("[%d]", i)
			}
			collectBindingsFromNode(child, childPath, lines, bindings)
		}
	case ScalarNode:
		if path == "" || node.Line <= 0 || node.Line > len(lines) {
			return
		}
		for _, original := range placeholderCandidates(lines[node.Line-1]) {
			resolved := expandEnvVars(original)
			if resolved == node.Value {
				bindings[path] = PlaceholderBinding{Original: original, Resolved: resolved}
				return
			}
		}
	}
}

func placeholderCandidates(line string) []string {
	seen := make(map[string]struct{})
	for _, match := range findEnvPlaceholderExprs(line) {
		seen[match] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(seen))
	for match := range seen {
		ordered = append(ordered, match)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	return ordered
}

func findEnvPlaceholderExprs(s string) []string {
	var matches []string
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			i++
			continue
		}
		if i+1 >= len(s) || s[i+1] != '{' {
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			continue
		}
		expr := s[i+2 : i+2+end]
		varName := expr
		if idx := strings.Index(expr, ":-"); idx >= 0 {
			varName = expr[:idx]
		}
		if !isPlaceholderEnvVarName(varName) {
			continue
		}
		matches = append(matches, s[i:i+2+end+1])
		i += 2 + end
	}
	return matches
}

func isPlaceholderEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func restorePlaceholder(path, value string, bindings map[string]PlaceholderBinding) string {
	if bindings == nil || value == "" {
		return value
	}
	binding, ok := bindings[path]
	if !ok {
		return value
	}
	if value != binding.Resolved {
		return value
	}
	return binding.Original
}

func marshalYAMLWithPlaceholderPreservation(cfg *Config) string {
	if cfg == nil {
		return MarshalYAML(cfg)
	}
	clone := cfg.DeepCopy()
	bindings := clone.placeholderBindings()
	if len(bindings) == 0 {
		return MarshalYAML(clone)
	}
	restorePlaceholdersRecursive(reflect.ValueOf(clone).Elem(), reflect.TypeOf(clone).Elem(), "", bindings)
	clone.SetPlaceholderBindings(nil)
	return MarshalYAML(clone)
}

func restorePlaceholdersRecursive(v reflect.Value, t reflect.Type, path string, bindings map[string]PlaceholderBinding) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		fv := v.Field(i)
		fieldPath := tag
		if path != "" {
			fieldPath = path + "." + tag
		}
		restoreValuePlaceholders(fv, fieldPath, bindings)
	}
}

func restoreValuePlaceholders(v reflect.Value, path string, bindings map[string]PlaceholderBinding) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(restorePlaceholder(path, v.String(), bindings))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			restoreValuePlaceholders(v.Elem(), path, bindings)
		}
	case reflect.Struct:
		restorePlaceholdersRecursive(v, v.Type(), path, bindings)
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			restoreValuePlaceholders(v.Index(i), itemPath, bindings)
		}
	case reflect.Map:
		for _, mk := range v.MapKeys() {
			mv := v.MapIndex(mk)
			if mv.Kind() == reflect.Interface && !mv.IsNil() {
				mv = mv.Elem()
			}
			itemPath := path + "." + fmt.Sprintf("%v", mk.Interface())
			if mv.Kind() == reflect.String {
				restored := restorePlaceholder(itemPath, mv.String(), bindings)
				if restored != mv.String() {
					v.SetMapIndex(mk, reflect.ValueOf(restored).Convert(v.Type().Elem()))
				}
				continue
			}
			if mv.CanAddr() {
				restoreValuePlaceholders(mv, itemPath, bindings)
			}
		}
	}
}
