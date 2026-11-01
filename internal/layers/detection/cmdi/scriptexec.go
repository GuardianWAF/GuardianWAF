package cmdi

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var (
	// YAML tags that instantiate objects: PyYAML (!!python/object/new:os.system),
	// SnakeYAML (!!javax.script.ScriptEngineManager, !!java.net.URLClassLoader)
	// and Ruby (!ruby/object).
	yamlObjectTag = regexp.MustCompile(`!!?(?:python/(?:object|name|module)|javax?\.[a-z]|ruby/(?:object|hash|struct))`)
	// Java native serialization: the magic bytes as hex or as base64 ("rO0AB").
	javaSerialized = regexp.MustCompile(`(?:^|[^a-z0-9])(?:aced0005|ro0ab[a-z0-9+/])`)
	// PHP serialized object: O:8:"stdClass":1:{...}
	phpSerialized = regexp.MustCompile(`\bo:\d{1,3}:"[a-z_\\][a-z0-9_\\]*":\d+:\{`)
	// PHP webshell calls on request data: eval($_GET['x']), system($_POST[0]).
	phpRequestExec = regexp.MustCompile(`\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:get|post|request|cookie|server)\b`)
	// ASP/VBScript execution of request data: eval request("x"), execute(request(...)).
	aspRequestExec = regexp.MustCompile(`\b(?:eval|execute)\s*\(?\s*request\s*[.(]`)
	// VBScript string concatenation joiner: "Ex"&"e"&"cute(".
	vbConcat = regexp.MustCompile(`"\s*&\s*"`)
)

// checkScriptExec finds server-side code and deserialization payloads: the
// remote-code-execution forms that need no shell command.
func checkScriptExec(input, lower, location string) []engine.Finding {
	var findings []engine.Finding
	add := func(score int, sev engine.Severity, desc, matched string) {
		findings = append(findings, makeFinding(score, sev, desc, matched, location, 0.85))
	}
	if strings.Contains(lower, "!") && (strings.Contains(lower, "python/") || strings.Contains(lower, "java") || strings.Contains(lower, "ruby/")) {
		if m := yamlObjectTag.FindString(lower); m != "" {
			add(90, engine.SeverityCritical, "YAML object tag (deserialization RCE)", m)
		}
	}
	if strings.Contains(lower, "aced0005") || strings.Contains(lower, "ro0ab") {
		if m := javaSerialized.FindString(lower); m != "" {
			add(75, engine.SeverityHigh, "Java serialized object", strings.TrimSpace(m))
		}
	}
	if strings.Contains(lower, ":{") && strings.Contains(lower, "o:") {
		if m := phpSerialized.FindString(lower); m != "" {
			add(70, engine.SeverityHigh, "PHP serialized object", m)
		}
	}
	if strings.Contains(lower, "$_") {
		if m := phpRequestExec.FindString(lower); m != "" {
			add(90, engine.SeverityCritical, "PHP code execution on request data", m)
		}
	}
	if strings.Contains(lower, "request") && (strings.Contains(lower, "eval") || strings.Contains(lower, "execute")) {
		if m := aspRequestExec.FindString(lower); m != "" {
			add(90, engine.SeverityCritical, "ASP code execution on request data", m)
		}
	}
	// VBScript builds function names from string pieces to dodge filters:
	// join them and look for execution primitives.
	if strings.Contains(lower, `"&`) || strings.Contains(lower, `" &`) {
		joined := vbConcat.ReplaceAllString(lower, "")
		compact := strings.ReplaceAll(joined, " ", "")
		if strings.Contains(compact, "execute(") || strings.Contains(compact, "eval(") {
			if strings.Contains(compact, "server.scripttimeout") || strings.Contains(compact, "onerrorresumenext") ||
				strings.Contains(compact, "createobject(") || strings.Contains(compact, "wscript.shell") ||
				strings.Contains(compact, "request.form") || strings.Contains(compact, "request(") {
				add(85, engine.SeverityCritical, "VBScript execution assembled from string pieces", extractContext(lower, "execute"))
			}
		}
	}
	return findings
}

// normalizeIFS rewrites the shell's field-separator variable to a space.
// "cat$IFS$9/etc/passwd", "cat${IFS}/etc/passwd" and "cat$IFS/etc/passwd" are
// all "cat /etc/passwd" to the shell and hide the command boundary from a word
// splitter.
func normalizeIFS(lower string) string {
	if !strings.Contains(lower, "$") {
		return lower
	}
	for _, v := range []string{"${ifs}", "$ifs$9", "$ifs$1", "$ifs"} {
		lower = strings.ReplaceAll(lower, v, " ")
	}
	return lower
}
