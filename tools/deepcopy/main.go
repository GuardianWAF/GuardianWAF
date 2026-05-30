//go:build ignore

// DeepcopyGen generates DeepCopy methods for all struct types in config.go.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

func main() {
	src := os.Args[1]

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	var generated []string
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			method := generateDeepCopy(typeSpec.Name.Name, structType)
			if method != "" {
				generated = append(generated, method)
			}
		}
	}

	for _, g := range generated {
		fmt.Println(g)
	}
}

func generateDeepCopy(typeName string, st *ast.StructType) string {
	var fields []fieldInfo
	for _, field := range st.Fields.List {
		if field.Names == nil {
			continue
		}
		for _, name := range field.Names {
			if !name.IsExported() {
				continue
			}
			fields = append(fields, fieldInfo{name: name.Name, typ: field.Type})
		}
	}

	if len(fields) == 0 {
		return ""
	}

	var bodyLines []string
	bodyLines = append(bodyLines, fmt.Sprintf("func (in *%s) DeepCopy() %s {", typeName, typeName))
	bodyLines = append(bodyLines, "\tif in == nil {")
	bodyLines = append(bodyLines, "\t\treturn nil")
	bodyLines = append(bodyLines, "\t}")
	bodyLines = append(bodyLines, "\tout := *in // shallow copy of scalar fields")

	for _, f := range fields {
		t := f.typ
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		switch tt := t.(type) {
		case *ast.ArrayType:
			elemType := typeString(tt.Elt)
			bodyLines = append(bodyLines, fmt.Sprintf("\tif in.%s != nil {", f.name))
			bodyLines = append(bodyLines, fmt.Sprintf("\t\tout.%s = make([]%s, len(in.%s))", f.name, elemType, f.name))
			bodyLines = append(bodyLines, fmt.Sprintf("\t\tcopy(out.%s, in.%s)", f.name, f.name))
			bodyLines = append(bodyLines, "\t}")
		case *ast.MapType:
			keyType := typeString(tt.Key)
			valType := typeString(tt.Value)
			bodyLines = append(bodyLines, fmt.Sprintf("\tif in.%s != nil {", f.name))
			bodyLines = append(bodyLines, fmt.Sprintf("\t\tout.%s = make(map[%s]%s, len(in.%s))", f.name, keyType, valType, f.name))
			bodyLines = append(bodyLines, fmt.Sprintf("\t\tfor k, v := range in.%s {", f.name))
			bodyLines = append(bodyLines, fmt.Sprintf("\t\t\tout.%s[k] = v", f.name))
			bodyLines = append(bodyLines, "\t\t}")
			bodyLines = append(bodyLines, "\t}")
		default:
			bodyLines = append(bodyLines, fmt.Sprintf("\tout.%s = in.%s", f.name, f.name))
		}
	}

	bodyLines = append(bodyLines, "\treturn &out")
	bodyLines = append(bodyLines, "}")

	return strings.Join(bodyLines, "\n")
}

type fieldInfo struct {
	name string
	typ  ast.Expr
}

func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeString(t.X) + "*"
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	case *ast.MapType:
		return "map[" + typeString(t.Key) + "]" + typeString(t.Value)
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	default:
		return "interface{}"
	}
}
