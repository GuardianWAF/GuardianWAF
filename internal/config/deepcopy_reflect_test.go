package config

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// TestDeepCopy_FullIndependence densely fills a Config (every slice, map, and
// pointer made non-nil) via reflection, deep-copies it, then walks both trees
// asserting that NO mutable reference (slice backing array, map, or pointer) is
// shared between the original and the copy.
//
// This is the safety net for the generated DeepCopy: the generator
// (gen_deepcopy.py) is not in the repo, so a regeneration or a new config field
// could silently reintroduce a shallow-copy/shared-reference bug (a hot-reload
// snapshot mutating the live config). This test catches that class for the whole
// config tree, not just the three fields fixed by hand.
func TestDeepCopy_FullIndependence(t *testing.T) {
	orig := &Config{}
	fillValue(reflect.ValueOf(orig).Elem(), 0)

	cp := orig.DeepCopy()

	var shared []string
	checkShared(reflect.ValueOf(orig).Elem(), reflect.ValueOf(cp).Elem(), "Config", &shared)
	if len(shared) > 0 {
		t.Fatalf("DeepCopy shares %d mutable reference(s) with the original (shallow-copy bug):\n  %v", len(shared), shared)
	}
}

var timeType = reflect.TypeOf(time.Time{})

// fillValue recursively populates v so that every slice/map/pointer is non-nil
// (length 1 / one entry / allocated), enabling checkShared to inspect the whole
// tree. time.Time is left zero (unexported fields, and it carries no mutable
// references we copy).
func fillValue(v reflect.Value, depth int) {
	if depth > 12 || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		fillValue(v.Elem(), depth+1)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillValue(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillValue(key, depth+1)
		val := reflect.New(v.Type().Elem()).Elem()
		fillValue(val, depth+1)
		m.SetMapIndex(key, val)
		v.Set(m)
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			fillValue(v.Field(i), depth+1)
		}
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	}
}

// checkShared walks orig and cp in parallel, recording any path where a
// slice/map/pointer in the copy aliases the same underlying memory as the
// original.
func checkShared(orig, cp reflect.Value, path string, shared *[]string) {
	if orig.Kind() != cp.Kind() {
		return
	}
	switch orig.Kind() {
	case reflect.Ptr:
		if orig.IsNil() || cp.IsNil() {
			return
		}
		if orig.Pointer() == cp.Pointer() {
			*shared = append(*shared, fmt.Sprintf("%s (shared *%s)", path, orig.Type().Elem().Name()))
			return
		}
		checkShared(orig.Elem(), cp.Elem(), path, shared)
	case reflect.Slice:
		if orig.IsNil() || cp.IsNil() || orig.Len() == 0 || cp.Len() == 0 {
			return
		}
		if orig.Pointer() == cp.Pointer() {
			*shared = append(*shared, fmt.Sprintf("%s (shared []%s backing array)", path, orig.Type().Elem().Name()))
			return
		}
		n := orig.Len()
		if cp.Len() < n {
			n = cp.Len()
		}
		for i := 0; i < n; i++ {
			checkShared(orig.Index(i), cp.Index(i), fmt.Sprintf("%s[%d]", path, i), shared)
		}
	case reflect.Map:
		if orig.IsNil() || cp.IsNil() {
			return
		}
		if orig.Pointer() == cp.Pointer() {
			*shared = append(*shared, fmt.Sprintf("%s (shared map)", path))
			return
		}
		for _, k := range orig.MapKeys() {
			ov := orig.MapIndex(k)
			cv := cp.MapIndex(k)
			if cv.IsValid() {
				checkShared(ov, cv, fmt.Sprintf("%s[%v]", path, k), shared)
			}
		}
	case reflect.Struct:
		if orig.Type() == timeType {
			return
		}
		for i := 0; i < orig.NumField(); i++ {
			checkShared(orig.Field(i), cp.Field(i), path+"."+orig.Type().Field(i).Name, shared)
		}
	}
}
