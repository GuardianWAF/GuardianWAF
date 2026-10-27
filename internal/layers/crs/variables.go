package crs

import (
	"net/http"
	"regexp"
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
		return []string{vr.transaction.RequestBodyString()}, nil
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
		return []string{vr.transaction.ResponseBodyString()}, nil

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
	//
	// time.Time.Format uses Go's reference layout ("Mon Jan 2 15:04:05 MST
	// 2006") — it has no PHP-style placeholders, so "H", "i", "s", "Y", "m",
	// "d" are emitted literally ("H:i:s", "Y", ...). The layouts below are the
	// Go equivalents of the ModSecurity TIME* variables: TIME "HH:MM:SS",
	// TIME_YEAR "YYYY", TIME_MON/TIME_DAY/TIME_HOUR/TIME_MIN/TIME_SEC
	// zero-padded two digits.
	case "TIME":
		return []string{vr.transaction.Timestamp.Format("15:04:05")}, nil
	case "TIME_EPOCH":
		return []string{strconv.FormatInt(vr.transaction.Timestamp.Unix(), 10)}, nil
	case "TIME_YEAR":
		return []string{vr.transaction.Timestamp.Format("2006")}, nil
	case "TIME_MON":
		return []string{vr.transaction.Timestamp.Format("01")}, nil
	case "TIME_DAY":
		return []string{vr.transaction.Timestamp.Format("02")}, nil
	case "TIME_HOUR":
		return []string{vr.transaction.Timestamp.Format("15")}, nil
	case "TIME_MIN":
		return []string{vr.transaction.Timestamp.Format("04")}, nil
	case "TIME_SEC":
		return []string{vr.transaction.Timestamp.Format("05")}, nil

	// Transaction variables
	//
	// Count and regex selection mirror the other keyed collections
	// (resolveArgs/resolveCookies): &TX:key counts that variable (1/0 — an
	// empty value counts as absent, mirroring the value form below),
	// &TX:/re/ counts variables with matching names, &TX counts the
	// collection, and TX:/re/ selects the values of matching names. The
	// pre-fix branch ignored Count and KeyRegex entirely, so &TX:key leaked
	// the key's VALUE (anomaly_score "5" instead of "1") and TX:/re/ looked
	// the pattern up as a literal key name (always empty — every
	// regex-selected TX rule went inert).
	case "TX":
		if rv.Key != "" {
			if rv.KeyRegex {
				re, err := getKeySelectorRegex(rv.Key)
				if err != nil {
					if rv.Count {
						return []string{"0"}, nil
					}
					return []string{}, nil
				}
				var values []string
				for txKey, val := range vr.transaction.Variables {
					if re.MatchString(txKey) && val != "" {
						values = append(values, val)
					}
				}
				if rv.Count {
					return []string{strconv.Itoa(len(values))}, nil
				}
				return values, nil
			}
			val := vr.transaction.GetVar(rv.Key)
			if rv.Count {
				if val != "" {
					return []string{"1"}, nil
				}
				return []string{"0"}, nil
			}
			if val != "" {
				return []string{val}, nil
			}
			return []string{}, nil
		}
		if rv.Count {
			total := 0
			for _, val := range vr.transaction.Variables {
				if val != "" {
					total++
				}
			}
			return []string{strconv.Itoa(total)}, nil
		}
		return vr.getAllTXVars(), nil

	// Special variables
	case "ARGS_COMBINED_SIZE":
		// SecLang contract (ModSecurity v3 transaction.cc, addArgs):
		// m_ARGScombinedSizeDouble += key.length() + value.length() —
		// per occurrence, so a repeated parameter counts its name each
		// time. The values-only sum undercounted every rule threshold
		// evaluated against this variable.
		size := 0
		for argKey, vals := range vr.transaction.RequestArgs {
			for _, val := range vals {
				size += len(argKey) + len(val)
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
		sb.WriteString(vr.transaction.RequestBodyString())
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
		// ModSecurity &ARGS counts every name=value pair (total), while
		// &ARGS:key counts only that key's values and &ARGS:/re/ counts the
		// values across matching keys — keyed counts are the parameter-
		// pollution detection idiom (&ARGS:password "@eq 2") and must not
		// fall back to the whole-collection total.
		if keyRegex {
			re, err := getKeySelectorRegex(key)
			if err != nil {
				return []string{"0"}, nil
			}
			total := 0
			for argKey, vals := range vr.transaction.RequestArgs {
				if re.MatchString(argKey) {
					total += len(vals)
				}
			}
			return []string{strconv.Itoa(total)}, nil
		}
		if key != "" {
			return []string{strconv.Itoa(len(vr.transaction.RequestArgs[key]))}, nil
		}
		total := 0
		for _, vals := range vr.transaction.RequestArgs {
			total += len(vals)
		}
		return []string{strconv.Itoa(total)}, nil
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
		// Regex key matching: /pattern/ selectors parse to KeyRegex with the
		// pattern as Key. Matched through the bounded regex cache; an invalid
		// pattern selects nothing (fail-soft, like operator errors).
		re, err := getKeySelectorRegex(key)
		if err != nil {
			return []string{}, nil
		}
		var values []string
		for argKey, vals := range vr.transaction.RequestArgs {
			if re.MatchString(argKey) {
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
		// Keyed counts mirror resolveArgs: &REQUEST_HEADERS:key counts that
		// header's values (canonical-key lookup) and &REQUEST_HEADERS:/re/
		// counts values across matching headers; only the keyless form is
		// the whole-collection total.
		if keyRegex {
			re, err := getKeySelectorRegex(key)
			if err != nil {
				return []string{"0"}, nil
			}
			total := 0
			for hKey, vals := range headers {
				if re.MatchString(hKey) {
					total += len(vals)
				}
			}
			return []string{strconv.Itoa(total)}, nil
		}
		if key != "" {
			return []string{strconv.Itoa(len(headers[http.CanonicalHeaderKey(key)]))}, nil
		}
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
		// Regex key matching (see resolveArgs): bounded cache, fail-soft on
		// an invalid pattern.
		re, err := getKeySelectorRegex(key)
		if err != nil {
			return []string{}, nil
		}
		var values []string
		for hKey, vals := range headers {
			if re.MatchString(hKey) {
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

// cookieValues also supports manually populated public Transactions, whose
// RequestCookies field retains its single-value-per-name API.
func (vr *VariableResolver) cookieValues() map[string][]string {
	if vr.transaction.requestCookieValues != nil {
		return vr.transaction.requestCookieValues
	}
	cookies := make(map[string][]string, len(vr.transaction.RequestCookies))
	for name, value := range vr.transaction.RequestCookies {
		cookies[name] = []string{value}
	}
	return cookies
}

// resolveCookies resolves cookie variables.
func (vr *VariableResolver) resolveCookies(key string, keyRegex bool, count bool) ([]string, error) {
	cookies := vr.cookieValues()
	if count {
		// Keyed counts mirror resolveArgs: &REQUEST_COOKIES:key counts that
		// cookie's values, including repeated names captured by the engine;
		// only the keyless form is the whole-collection total.
		if keyRegex {
			re, err := getKeySelectorRegex(key)
			if err != nil {
				return []string{"0"}, nil
			}
			total := 0
			for cookieKey, values := range cookies {
				if re.MatchString(cookieKey) {
					total += len(values)
				}
			}
			return []string{strconv.Itoa(total)}, nil
		}
		if key != "" {
			return []string{strconv.Itoa(len(cookies[key]))}, nil
		}
		total := 0
		for _, values := range cookies {
			total += len(values)
		}
		return []string{strconv.Itoa(total)}, nil
	}

	if key == "" {
		// Return all cookie values
		var values []string
		for _, vals := range cookies {
			values = append(values, vals...)
		}
		return values, nil
	}

	if keyRegex {
		// Regex key matching (see resolveArgs): bounded cache, fail-soft on
		// an invalid pattern.
		re, err := getKeySelectorRegex(key)
		if err != nil {
			return []string{}, nil
		}
		var values []string
		for cookieKey, vals := range cookies {
			if re.MatchString(cookieKey) {
				values = append(values, vals...)
			}
		}
		return values, nil
	}

	// Exact key match
	if vals, ok := cookies[key]; ok {
		return vals, nil
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
	for key := range vr.cookieValues() {
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
		mid := pattern[1 : len(pattern)-1]
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

// getKeySelectorRegex compiles a COLLECTION:/re/ key selector. SecLang matches
// regex key selectors case-insensitively (ModSecurity v2 compiles them
// PCRE_CASELESS; libmodsecurity v3 builds VariableRegex with ignoreCase).
// Case-sensitive matching left every lowercase header selector
// (REQUEST_HEADERS:/^x-api-/) inert, because Go canonicalizes header names to
// "X-Api-..." (F186).
func getKeySelectorRegex(key string) (*regexp.Regexp, error) {
	return getCachedRegex("(?i)" + key)
}

// resolveExcluding resolves an included rule variable minus the fields named
// by exclusion targets (!COLLECTION:key or !COLLECTION:/re/) of the SAME
// collection. Exclusion is by field identity, never by value: a different
// field carrying a byte-identical value is still inspected (F187).
func (vr *VariableResolver) resolveExcluding(rv RuleVariable, excludes []RuleVariable) []string {
	name := ruleVariableName(rv)
	var same []RuleVariable
	for _, ex := range excludes {
		if ruleVariableName(ex) == name {
			same = append(same, ex)
		}
	}
	if len(same) == 0 || rv.Count {
		values, _ := vr.Resolve(rv)
		return values
	}
	entries, fold, keyed := vr.keyedEntries(name)
	if !keyed {
		// Non-keyed variable: a keyless exclusion removes it entirely.
		for _, ex := range same {
			if ex.Key == "" {
				return nil
			}
		}
		values, _ := vr.Resolve(rv)
		return values
	}
	var values []string
	for key, vals := range entries {
		if !keySelectorMatches(rv, key, fold) {
			continue
		}
		excluded := false
		for _, ex := range same {
			if keySelectorMatches(ex, key, fold) {
				excluded = true
				break
			}
		}
		if !excluded {
			values = append(values, vals...)
		}
	}
	return values
}

// ruleVariableName returns the collection/variable a RuleVariable targets.
func ruleVariableName(rv RuleVariable) string {
	if rv.Name == "" && rv.Collection != "" {
		return rv.Collection
	}
	return rv.Name
}

// keyedEntries returns the key->values view of a keyed collection, mirroring
// what Resolve inspects, plus whether its exact keys compare
// case-insensitively (header names, TX variables).
func (vr *VariableResolver) keyedEntries(name string) (map[string][]string, bool, bool) {
	switch name {
	case "ARGS", "ARGS_GET", "ARGS_POST":
		return vr.transaction.RequestArgs, false, true
	case "REQUEST_HEADERS":
		return vr.transaction.RequestHeaders, true, true
	case "RESPONSE_HEADERS":
		return vr.transaction.ResponseHeaders, true, true
	case "REQUEST_COOKIES":
		return vr.cookieValues(), false, true
	case "TX":
		entries := make(map[string][]string, len(vr.transaction.Variables))
		for k, v := range vr.transaction.Variables {
			if v != "" {
				entries[k] = []string{v}
			}
		}
		return entries, true, true
	}
	return nil, false, false
}

// keySelectorMatches reports whether a field key is selected by rv's key
// selector (no key selects every field).
func keySelectorMatches(rv RuleVariable, key string, fold bool) bool {
	switch {
	case rv.Key == "":
		return true
	case rv.KeyRegex:
		re, err := getKeySelectorRegex(rv.Key)
		return err == nil && re.MatchString(key)
	case fold:
		return strings.EqualFold(rv.Key, key)
	default:
		return rv.Key == key
	}
}
