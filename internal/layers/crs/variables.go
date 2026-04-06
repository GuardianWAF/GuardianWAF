package crs

import (
	"net/http"
	"strconv"
	"strings"
)

// VariableResolver resolves SecRule variables from transaction data.
type VariableResolver struct {
	transaction *Transaction
}

// NewVariableResolver creates a new variable resolver.
func NewVariableResolver(tx *Transaction) *VariableResolver {
	return &VariableResolver{
		transaction: tx,
	}
}

// Resolve resolves a RuleVariable to its value(s).
func (vr *VariableResolver) Resolve(rv RuleVariable) ([]string, error) {
	varName := rv.Name
	if varName == "" && rv.Collection != "" {
		varName = rv.Collection
	}

	switch varName {
	// Request line variables
	case "REQUEST_LINE":
		return []string{vr.transaction.Method + " " + vr.transaction.URI + " " + vr.transaction.Protocol}, nil
	case "REQUEST_METHOD":
		return []string{vr.transaction.Method}, nil
	case "REQUEST_URI":
		return []string{vr.transaction.URI}, nil
	case "REQUEST_URI_RAW":
		return []string{vr.transaction.URI}, nil
	case "REQUEST_PROTOCOL":
		return []string{vr.transaction.Protocol}, nil
	case "REQUEST_FILENAME":
		return []string{vr.transaction.Path}, nil

	// Query string variables
	case "QUERY_STRING":
		return []string{vr.transaction.Query}, nil
	case "ARGS":
		return vr.resolveArgs(rv.Key, rv.KeyRegex, rv.Count)
	case "ARGS_NAMES":
		return vr.getArgNames(), nil
	case "ARGS_GET":
		// GET arguments only (same as ARGS for now)
		return vr.resolveArgs(rv.Key, rv.KeyRegex, rv.Count)
	case "ARGS_POST":
		// POST arguments only
		return vr.resolveArgs(rv.Key, rv.KeyRegex, rv.Count)

	// Header variables
	case "REQUEST_HEADERS":
		return vr.resolveHeaders(rv.Key, rv.KeyRegex, vr.transaction.RequestHeaders, rv.Count)
	case "REQUEST_HEADERS_NAMES":
		return vr.getHeaderNames(vr.transaction.RequestHeaders), nil

	// Body variables
	case "REQUEST_BODY":
		return []string{string(vr.transaction.RequestBody)}, nil
	case "REQUEST_BODY_LENGTH":
		return []string{strconv.Itoa(len(vr.transaction.RequestBody))}, nil

	// Cookie variables
	case "REQUEST_COOKIES":
		return vr.resolveCookies(rv.Key, rv.KeyRegex, rv.Count)
	case "REQUEST_COOKIES_NAMES":
		return vr.getCookieNames(), nil

	// Response variables
	case "RESPONSE_STATUS":
		return []string{strconv.Itoa(vr.transaction.StatusCode)}, nil
	case "RESPONSE_HEADERS":
		return vr.resolveHeaders(rv.Key, rv.KeyRegex, vr.transaction.ResponseHeaders, rv.Count)
	case "RESPONSE_BODY":
		return []string{string(vr.transaction.ResponseBody)}, nil

	// Server variables
	case "SERVER_NAME":
		return []string{vr.transaction.GetVar("SERVER_NAME")}, nil
	case "SERVER_ADDR":
		return []string{vr.transaction.ServerIP}, nil
	case "SERVER_PORT":
		return []string{strconv.Itoa(vr.transaction.ServerPort)}, nil
	case "REMOTE_ADDR":
		return []string{vr.transaction.ClientIP}, nil
	case "REMOTE_PORT":
		return []string{strconv.Itoa(vr.transaction.ClientPort)}, nil

	// Time variables
	case "TIME":
		return []string{vr.transaction.Timestamp.Format("H:i:s")}, nil
	case "TIME_EPOCH":
		return []string{strconv.FormatInt(vr.transaction.Timestamp.Unix(), 10)}, nil
	case "TIME_YEAR":
		return []string{vr.transaction.Timestamp.Format("Y")}, nil
	case "TIME_MON":
		return []string{vr.transaction.Timestamp.Format("m")}, nil
	case "TIME_DAY":
		return []string{vr.transaction.Timestamp.Format("d")}, nil
	case "TIME_HOUR":
		return []string{vr.transaction.Timestamp.Format("H")}, nil
	case "TIME_MIN":
		return []string{vr.transaction.Timestamp.Format("i")}, nil
	case "TIME_SEC":
		return []string{vr.transaction.Timestamp.Format("s")}, nil

	// Transaction variables
	case "TX":
		if rv.Key != "" {
			val := vr.transaction.GetVar(rv.Key)
			if val != "" {
				return []string{val}, nil
			}
			return []string{}, nil
		}
		return vr.getAllTXVars(), nil

	// Special variables
	case "ARGS_COMBINED_SIZE":
		size := 0
		for _, vals := range vr.transaction.RequestArgs {
			for _, val := range vals {
				size += len(val)
			}
		}
		return []string{strconv.Itoa(size)}, nil
	case "FULL_REQUEST":
		// Build full request string
		var sb strings.Builder
		sb.WriteString(vr.transaction.Method + " " + vr.transaction.URI + " " + vr.transaction.Protocol + "\r\n")
		for key, vals := range vr.transaction.RequestHeaders {
			for _, val := range vals {
				sb.WriteString(key + ": " + val + "\r\n")
			}
		}
		sb.WriteString("\r\n")
		sb.WriteString(string(vr.transaction.RequestBody))
		return []string{sb.String()}, nil
	case "FULL_REQUEST_LENGTH":
		return []string{strconv.Itoa(len(vr.transaction.RequestBody) + 1024)}, nil // Approximate

	default:
		// Unknown variable - check TX collection
		if val := vr.transaction.GetVar(varName); val != "" {
			return []string{val}, nil
		}
		return []string{}, nil
	}
}

// resolveArgs resolves ARGS variable.
func (vr *VariableResolver) resolveArgs(key string, keyRegex bool, count bool) ([]string, error) {
	if count {
		return []string{strconv.Itoa(len(vr.transaction.RequestArgs))}, nil
	}

	if key == "" {
		// Return all argument values
		var values []string
		for _, vals := range vr.transaction.RequestArgs {
			values = append(values, vals...)
		}
		return values, nil
	}

	// Specific key lookup
	if keyRegex {
		// Regex key matching
		var values []string
		for argKey, vals := range vr.transaction.RequestArgs {
			// Simple wildcard matching for now
			if matched, _ := matchWildcard(argKey, key); matched {
				values = append(values, vals...)
			}
		}
		return values, nil
	}

	// Exact key match
	if vals, ok := vr.transaction.RequestArgs[key]; ok {
		return vals, nil
	}

	return []string{}, nil
}

// resolveHeaders resolves header variables.
func (vr *VariableResolver) resolveHeaders(key string, keyRegex bool, headers map[string][]string, count bool) ([]string, error) {
	if count {
		count := 0
		for _, vals := range headers {
			count += len(vals)
		}
		return []string{strconv.Itoa(count)}, nil
	}

	if key == "" {
		// Return all header values
		var values []string
		for _, vals := range headers {
			values = append(values, vals...)
		}
		return values, nil
	}

	// Case-insensitive header lookup
	headerKey := http.CanonicalHeaderKey(key)

	if keyRegex {
		// Regex key matching
		var values []string
		for hKey, vals := range headers {
			if matched, _ := matchWildcard(hKey, key); matched {
				values = append(values, vals...)
			}
		}
		return values, nil
	}

	// Exact key match
	if vals, ok := headers[headerKey]; ok {
		return vals, nil
	}

	return []string{}, nil
}

// resolveCookies resolves cookie variables.
func (vr *VariableResolver) resolveCookies(key string, keyRegex bool, count bool) ([]string, error) {
	if count {
		return []string{strconv.Itoa(len(vr.transaction.RequestCookies))}, nil
	}

	if key == "" {
		// Return all cookie values
		var values []string
		for _, val := range vr.transaction.RequestCookies {
			values = append(values, val)
		}
		return values, nil
	}

	if keyRegex {
		// Regex key matching
		var values []string
		for cookieKey, val := range vr.transaction.RequestCookies {
			if matched, _ := matchWildcard(cookieKey, key); matched {
				values = append(values, val)
			}
		}
		return values, nil
	}

	// Exact key match
	if val, ok := vr.transaction.RequestCookies[key]; ok {
		return []string{val}, nil
	}

	return []string{}, nil
}

// getArgNames returns all argument names.
func (vr *VariableResolver) getArgNames() []string {
	names := []string{}
	for key := range vr.transaction.RequestArgs {
		names = append(names, key)
	}
	return names
}

// getHeaderNames returns all header names.
func (vr *VariableResolver) getHeaderNames(headers map[string][]string) []string {
	names := []string{}
	for key := range headers {
		names = append(names, key)
	}
	return names
}

// getCookieNames returns all cookie names.
func (vr *VariableResolver) getCookieNames() []string {
	names := []string{}
	for key := range vr.transaction.RequestCookies {
		names = append(names, key)
	}
	return names
}

// getAllTXVars returns all transaction variables.
func (vr *VariableResolver) getAllTXVars() []string {
	values := []string{}
	for _, val := range vr.transaction.Variables {
		values = append(values, val)
	}
	return values
}

// matchWildcard performs simple wildcard matching.
// pattern: "foo*" or "*bar" or "*baz*"
func matchWildcard(s, pattern string) (bool, error) {
	if pattern == "" {
		return s == "", nil
	}

	if pattern == "*" {
		return true, nil
	}

	// Handle simple wildcards
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *pattern*
		mid := pattern[1:len(pattern)-1]
		return strings.Contains(s, mid), nil
	}

	if strings.HasPrefix(pattern, "*") {
		// *suffix
		suffix := pattern[1:]
		return strings.HasSuffix(s, suffix), nil
	}

	if strings.HasSuffix(pattern, "*") {
		// prefix*
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(s, prefix), nil
	}

	// Exact match
	return s == pattern, nil
}
