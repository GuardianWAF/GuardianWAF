package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"
)

// SaveFile serializes the config to YAML and writes it to the given path.
func SaveFile(path string, cfg *Config) error {
	data := MarshalYAML(cfg)
	return os.WriteFile(path, []byte(data), 0o600)
}

// MarshalYAML serializes a Config struct to a YAML string using yaml struct tags.
func MarshalYAML(cfg *Config) string {
	var b strings.Builder
	b.WriteString("# GuardianWAF Configuration\n# Auto-saved by GuardianWAF dashboard\n\n")
	marshalStruct(&b, reflect.ValueOf(cfg).Elem(), reflect.TypeOf(cfg).Elem(), 0)
	return b.String()
}

func marshalStruct(b *strings.Builder, v reflect.Value, t reflect.Type, indent int) {
	prefix := strings.Repeat("  ", indent)

	for i := range t.NumField() {
		field := t.Field(i)
		fv := v.Field(i)

		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}

		// Skip zero-value optional fields at top level to keep output clean
		if isZeroValue(fv) && indent > 0 {
			continue
		}

		marshalField(b, prefix, tag, fv, indent)
	}
}

func marshalField(b *strings.Builder, prefix, key string, fv reflect.Value, indent int) {
	switch fv.Kind() {
	case reflect.String:
		s := fv.String()
		if s == "" {
			return
		}
		if needsQuoting(s) {
			fmt.Fprintf(b, "%s%s: %q\n", prefix, key, s)
		} else {
			fmt.Fprintf(b, "%s%s: %s\n", prefix, key, s)
		}

	case reflect.Int, reflect.Int64:
		// Check if it's a time.Duration
		if fv.Type() == reflect.TypeOf(time.Duration(0)) {
			d := time.Duration(fv.Int())
			if d == 0 {
				return
			}
			fmt.Fprintf(b, "%s%s: %s\n", prefix, key, formatDuration(d))
		} else {
			fmt.Fprintf(b, "%s%s: %d\n", prefix, key, fv.Int())
		}

	case reflect.Float64:
		f := fv.Float()
		if f == float64(int64(f)) {
			fmt.Fprintf(b, "%s%s: %d\n", prefix, key, int64(f))
		} else {
			fmt.Fprintf(b, "%s%s: %g\n", prefix, key, f)
		}

	case reflect.Bool:
		fmt.Fprintf(b, "%s%s: %t\n", prefix, key, fv.Bool())

	case reflect.Slice:
		marshalSlice(b, prefix, key, fv, indent)

	case reflect.Map:
		if fv.Len() == 0 {
			return
		}
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		marshalMap(b, fv, indent+1)

	case reflect.Struct:
		if isZeroValue(fv) {
			return
		}
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		marshalStruct(b, fv, fv.Type(), indent+1)

	case reflect.Ptr:
		if fv.IsNil() {
			return
		}
		marshalField(b, prefix, key, fv.Elem(), indent)

	case reflect.Interface:
		if fv.IsNil() {
			return
		}
		// For any values, marshal the concrete value
		marshalField(b, prefix, key, fv.Elem(), indent)
	}
}

func marshalSlice(b *strings.Builder, prefix, key string, fv reflect.Value, indent int) {
	if fv.Len() == 0 {
		return
	}

	elemKind := fv.Type().Elem().Kind()
	childPrefix := strings.Repeat("  ", indent+1)

	switch elemKind {
	case reflect.String:
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		for i := range fv.Len() {
			s := fv.Index(i).String()
			if needsQuoting(s) {
				fmt.Fprintf(b, "%s- %q\n", childPrefix, s)
			} else {
				fmt.Fprintf(b, "%s- %s\n", childPrefix, s)
			}
		}

	case reflect.Struct:
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		for i := range fv.Len() {
			elem := fv.Index(i)
			et := elem.Type()
			// Write first field with "- " prefix, rest with "  " prefix
			first := true
			for j := range et.NumField() {
				field := et.Field(j)
				tag := field.Tag.Get("yaml")
				if tag == "" || tag == "-" {
					continue
				}
				fieldVal := elem.Field(j)
				if isZeroValue(fieldVal) {
					continue
				}
				if first {
					fmt.Fprintf(b, "%s- ", childPrefix)
					marshalInlineField(b, tag, fieldVal, indent+2)
					first = false
				} else {
					fmt.Fprintf(b, "%s  ", childPrefix)
					marshalInlineField(b, tag, fieldVal, indent+2)
				}
			}
		}

	default:
		fmt.Fprintf(b, "%s%s:\n", prefix, key)
		for i := range fv.Len() {
			fmt.Fprintf(b, "%s- %v\n", childPrefix, fv.Index(i).Interface())
		}
	}
}

func marshalInlineField(b *strings.Builder, key string, fv reflect.Value, indent int) {
	switch fv.Kind() {
	case reflect.String:
		s := fv.String()
		if needsQuoting(s) {
			fmt.Fprintf(b, "%s: %q\n", key, s)
		} else {
			fmt.Fprintf(b, "%s: %s\n", key, s)
		}
	case reflect.Int, reflect.Int64:
		if fv.Type() == reflect.TypeOf(time.Duration(0)) {
			fmt.Fprintf(b, "%s: %s\n", key, formatDuration(time.Duration(fv.Int())))
		} else {
			fmt.Fprintf(b, "%s: %d\n", key, fv.Int())
		}
	case reflect.Float64:
		f := fv.Float()
		if f == float64(int64(f)) {
			fmt.Fprintf(b, "%s: %d\n", key, int64(f))
		} else {
			fmt.Fprintf(b, "%s: %g\n", key, f)
		}
	case reflect.Bool:
		fmt.Fprintf(b, "%s: %t\n", key, fv.Bool())
	case reflect.Slice:
		if fv.Len() == 0 {
			return
		}
		elemKind := fv.Type().Elem().Kind()
		if elemKind == reflect.String {
			// flow style [a, b, c]
			var items []string
			for i := range fv.Len() {
				items = append(items, fv.Index(i).String())
			}
			fmt.Fprintf(b, "%s: [%s]\n", key, strings.Join(items, ", "))
		} else if elemKind == reflect.Struct {
			// Bug 2 fix: struct slices inside sequence items — block style
			fmt.Fprintf(b, "%s:\n", key)
			childPrefix := strings.Repeat("  ", indent+1)
			for i := range fv.Len() {
				elem := fv.Index(i)
				et := elem.Type()
				first := true
				for j := range et.NumField() {
					field := et.Field(j)
					ftag := field.Tag.Get("yaml")
					if ftag == "" || ftag == "-" {
						continue
					}
					fieldVal := elem.Field(j)
					if isZeroValue(fieldVal) {
						continue
					}
					if first {
						fmt.Fprintf(b, "%s- ", childPrefix)
						marshalInlineField(b, ftag, fieldVal, indent+1)
						first = false
					} else {
						fmt.Fprintf(b, "%s  ", childPrefix)
						marshalInlineField(b, ftag, fieldVal, indent+1)
					}
				}
			}
		}
	case reflect.Struct:
		fmt.Fprintf(b, "%s:\n", key)
		marshalStruct(b, fv, fv.Type(), indent+1)
	case reflect.Ptr:
		// Bug 3 fix: handle pointer fields (e.g. *WAFConfig in VirtualHostConfig)
		if !fv.IsNil() {
			marshalInlineField(b, key, fv.Elem(), indent)
		}
	case reflect.Interface:
		if !fv.IsNil() {
			marshalInlineField(b, key, fv.Elem(), indent)
		}
	}
}

func marshalMap(b *strings.Builder, fv reflect.Value, indent int) {
	prefix := strings.Repeat("  ", indent)
	for _, mk := range fv.MapKeys() {
		key := fmt.Sprintf("%v", mk.Interface())
		mv := fv.MapIndex(mk)

		if mv.Kind() == reflect.Interface {
			mv = mv.Elem()
		}

		if mv.Kind() == reflect.Struct {
			fmt.Fprintf(b, "%s%s:\n", prefix, key)
			marshalStruct(b, mv, mv.Type(), indent+1)
		} else {
			marshalField(b, prefix, key, mv, indent)
		}
	}
}

func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int64:
		return v.Int() == 0
	case reflect.Float64:
		return v.Float() == 0
	case reflect.Slice:
		return v.Len() == 0
	case reflect.Map:
		return v.Len() == 0
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			if !isZeroValue(v.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Ptr:
		return v.IsNil()
	case reflect.Interface:
		return v.IsNil()
	}
	return false
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	// Quote if contains special YAML characters
	for _, c := range s {
		if c == ':' || c == '#' || c == '[' || c == ']' || c == '{' || c == '}' || c == ',' || c == '\n' || c == '"' || c == '\'' {
			return true
		}
	}
	// Quote if looks like a number, bool, or null
	lower := strings.ToLower(s)
	if lower == "true" || lower == "false" || lower == "null" || lower == "~" {
		return true
	}
	// Quote if starts with special chars
	if s[0] == '*' || s[0] == '&' || s[0] == '!' || s[0] == '|' || s[0] == '>' || s[0] == '%' || s[0] == '@' {
		return true
	}
	return false
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d >= time.Second && d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return d.String()
}
