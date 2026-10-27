package sanitizer

import (
	"bytes"
	"mime/multipart"
	"slices"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func hasBodyNullByteFinding(ctx *engine.RequestContext) bool {
	for _, f := range ValidateRequest(ctx, Config{BlockNullBytes: true}) {
		if f.Description == "Null byte detected in body" {
			return true
		}
	}
	return false
}

func multipartBody(t *testing.T, filename string, file []byte, fields map[string]string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := w.CreateFormFile("upload", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(file)
	_ = w.Close()
	return buf.String(), w.FormDataContentType()
}

var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10")

// Regression: with block_null_bytes on (the default) every body containing a
// NUL scored 60 and was blocked, so any binary upload — images, PDFs,
// archives, protobuf — was rejected.
func TestBinaryBodiesDoNotTripNullByteCheck(t *testing.T) {
	body, ct := multipartBody(t, "me.png", pngBytes, map[string]string{"title": "hello"})
	if hasBodyNullByteFinding(&engine.RequestContext{BodyString: body, ContentType: ct}) {
		t.Error("multipart image upload flagged as null-byte injection")
	}
	for _, ct := range []string{"image/png", "application/octet-stream", "application/pdf", "application/grpc+proto", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"} {
		if hasBodyNullByteFinding(&engine.RequestContext{BodyString: string(pngBytes), ContentType: ct}) {
			t.Errorf("%s body flagged as null-byte injection", ct)
		}
	}
}

func TestTextBodiesStillTripNullByteCheck(t *testing.T) {
	for name, ctx := range map[string]*engine.RequestContext{
		"form":           {BodyString: "file=shell.php%00.jpg", ContentType: "application/x-www-form-urlencoded"},
		"json":           {BodyString: "{\"a\":\"x\x00y\"}", ContentType: "application/json"},
		"vnd json":       {BodyString: "{\"a\":\"x\x00y\"}", ContentType: "application/vnd.api+json"},
		"no type":        {BodyString: "a\x00b"},
		"malformed type": {BodyString: "a\x00b", ContentType: "image/png; ;;"},
	} {
		if !hasBodyNullByteFinding(ctx) {
			t.Errorf("%s: null byte not flagged", name)
		}
	}
	body, ct := multipartBody(t, "shell.php%00.jpg", pngBytes, nil)
	if !hasBodyNullByteFinding(&engine.RequestContext{BodyString: body, ContentType: ct}) {
		t.Error("null byte in an upload filename not flagged")
	}
	body, ct = multipartBody(t, "a.png", pngBytes, map[string]string{"comment": "x\x00y"})
	if !hasBodyNullByteFinding(&engine.RequestContext{BodyString: body, ContentType: ct}) {
		t.Error("null byte in a multipart text field not flagged")
	}
	if !hasBodyNullByteFinding(&engine.RequestContext{BodyString: "--x\r\nbroken\x00", ContentType: "multipart/form-data; boundary=x"}) {
		t.Error("unparsable multipart body with NUL not flagged")
	}
}

func TestMultipartFieldsExtraction(t *testing.T) {
	body, ct := multipartBody(t, "../../etc/passwd", []byte("plain text upload"), map[string]string{"comment": "admin' --"})
	boundary, ok := multipartBoundary(ct)
	if !ok {
		t.Fatal("boundary not found")
	}
	fields := multipartFields(body, boundary)
	for _, want := range []string{"comment", "admin' --", "upload", "../../etc/passwd", "plain text upload"} {
		if !slices.Contains(fields, want) {
			t.Errorf("fields %q missing %q", fields, want)
		}
	}
	body, ct = multipartBody(t, "me.png", pngBytes, nil)
	boundary, _ = multipartBoundary(ct)
	for _, f := range multipartFields(body, boundary) {
		if f == string(pngBytes) {
			t.Error("binary upload content extracted as a text field")
		}
	}
	if multipartFields("not multipart", "x") != nil {
		t.Error("garbage parsed as multipart")
	}
}
