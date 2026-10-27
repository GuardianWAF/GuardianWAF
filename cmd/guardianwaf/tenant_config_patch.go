package main

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

type tenantUpdateError struct{ err error }

func (e *tenantUpdateError) Error() string       { return "invalid tenant update: " + e.err.Error() }
func (e *tenantUpdateError) Unwrap() error       { return e.err }
func (e *tenantUpdateError) HTTPStatusCode() int { return 400 }

// applyTenantWAFPatch uses the same field names and value parser as YAML
// configuration. Decoding directly with encoding/json would silently discard
// snake_case fields because config structs carry yaml tags, not json tags.
func applyTenantWAFPatch(cfg *config.Config, patch any) error {
	node, err := tenantPatchNode(patch, reflect.TypeFor[config.WAFConfig](), "waf", 0)
	if err != nil {
		return err
	}
	root := &config.Node{Kind: config.MapNode, MapKeys: []string{"waf"}, MapItems: map[string]*config.Node{"waf": node}}
	if err := config.PopulateFromNode(cfg, root); err != nil {
		return err
	}
	return config.Validate(cfg)
}

func tenantPatchNode(value any, typ reflect.Type, path string, depth int) (*config.Node, error) {
	if value == nil || depth > 64 {
		return nil, fmt.Errorf("%s: null or excessively nested value", path)
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeFor[time.Duration]() {
		if _, ok := value.(string); !ok {
			return nil, fmt.Errorf("%s: duration must be a string", path)
		}
	}
	switch v := value.(type) {
	case map[string]any:
		if typ.Kind() != reflect.Struct && typ.Kind() != reflect.Map && typ.Kind() != reflect.Interface {
			return nil, fmt.Errorf("%s: object is not allowed", path)
		}
		fields := make(map[string]reflect.Type)
		if typ.Kind() == reflect.Struct {
			for i := range typ.NumField() {
				field := typ.Field(i)
				name := strings.Split(field.Tag.Get("yaml"), ",")[0]
				if name != "" && name != "-" && field.IsExported() {
					fields[name] = field.Type
				}
			}
		}
		node := &config.Node{Kind: config.MapNode, MapItems: make(map[string]*config.Node, len(v))}
		for key, item := range v {
			childType := reflect.TypeFor[any]()
			if typ.Kind() == reflect.Struct {
				var ok bool
				childType, ok = fields[key]
				if !ok {
					return nil, fmt.Errorf("%s.%s: unknown field", path, key)
				}
			} else if typ.Kind() == reflect.Map {
				childType = typ.Elem()
			}
			child, err := tenantPatchNode(item, childType, path+"."+key, depth+1)
			if err != nil {
				return nil, err
			}
			node.MapKeys = append(node.MapKeys, key)
			node.MapItems[key] = child
		}
		sort.Strings(node.MapKeys)
		return node, nil
	case []any:
		if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Interface {
			return nil, fmt.Errorf("%s: array is not allowed", path)
		}
		node := &config.Node{Kind: config.SequenceNode}
		for i, item := range v {
			childType := reflect.TypeFor[any]()
			if typ.Kind() == reflect.Slice {
				childType = typ.Elem()
			}
			child, err := tenantPatchNode(item, childType, fmt.Sprintf("%s[%d]", path, i), depth+1)
			if err != nil {
				return nil, err
			}
			node.Items = append(node.Items, child)
		}
		return node, nil
	case bool:
		if typ.Kind() != reflect.Bool && typ.Kind() != reflect.Interface {
			return nil, fmt.Errorf("%s: boolean is not allowed", path)
		}
		return &config.Node{Kind: config.ScalarNode, Value: strconv.FormatBool(v)}, nil
	case float64:
		if typ.Kind() != reflect.Interface && (typ.Kind() < reflect.Int || typ.Kind() > reflect.Float64) {
			return nil, fmt.Errorf("%s: number is not allowed", path)
		}
		return &config.Node{Kind: config.ScalarNode, Value: strconv.FormatFloat(v, 'f', -1, 64)}, nil
	case string:
		if typ.Kind() != reflect.String && typ.Kind() != reflect.Interface && typ != reflect.TypeFor[time.Duration]() {
			return nil, fmt.Errorf("%s: string is not allowed", path)
		}
		return &config.Node{Kind: config.ScalarNode, Value: v}, nil
	default:
		return nil, fmt.Errorf("%s: unsupported value type", path)
	}
}
