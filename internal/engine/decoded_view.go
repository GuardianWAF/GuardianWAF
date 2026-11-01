package engine

// DecodedView is request text the per-parameter views miss, recovered by the
// sanitizer: what a base64 value decodes to, or a whole query string or form
// body read across its parameters.
type DecodedView struct {
	// Source is the finding location the view reports under, for example
	// "base64:query", "base64:body" or "query-string".
	Source     string
	Raw        string // the text as is
	Normalized string // Raw after the sanitizer's normalization
}
