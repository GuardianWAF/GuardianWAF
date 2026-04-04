// Package features extracts features from HTTP requests for ML anomaly detection.
package features

import (
	"math"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Extractor extracts features from HTTP requests.
type Extractor struct {
	// Feature configuration
	maxPathSegments   int
	maxQueryParams    int
	maxHeaderCount    int
	maxBodySampleSize int
}

// NewExtractor creates a new feature extractor.
func NewExtractor() *Extractor {
	return &Extractor{
		maxPathSegments:   10,
		maxQueryParams:    50,
		maxHeaderCount:    30,
		maxBodySampleSize: 1024,
	}
}

// FeatureVector contains extracted features.
// These are the inputs to the ML model.
type FeatureVector struct {
	// Path features (indices 0-2)
	PathEntropy      float64 // Entropy of path
	PathSegmentCount float64 // Number of path segments
	PathDepth        float64 // Path depth (../ count)

	// Query features (indices 3-5)
	QueryEntropy   float64 // Entropy of query string
	QueryParamCount float64 // Number of query parameters
	QueryMaxLength float64 // Max parameter value length

	// Header features (indices 6-8)
	HeaderCount      float64 // Number of headers
	HeaderEntropy    float64 // Entropy of header values
	ContentLength    float64 // Content-Length header value

	// Body features (indices 9-10)
	BodyEntropy   float64 // Entropy of body (if present)
	BodySize      float64 // Body size in bytes

	// Method feature (index 11)
	MethodScore float64 // Method risk score

	// Timing features (indices 12-13)
	TimeOfDay  float64 // Hour of day (0-23 normalized)
	DayOfWeek  float64 // Day of week (0-6 normalized)

	// Derived features (will be used in v2)
	// UserAgentLength  float64
	// CookieCount      float64
	// SpecialCharRatio float64
}

// ToSlice converts feature vector to float slice for model input.
func (fv *FeatureVector) ToSlice() []float64 {
	return []float64{
		fv.PathEntropy,
		fv.PathSegmentCount,
		fv.PathDepth,
		fv.QueryEntropy,
		fv.QueryParamCount,
		fv.QueryMaxLength,
		fv.HeaderCount,
		fv.HeaderEntropy,
		fv.ContentLength,
		fv.BodyEntropy,
		fv.BodySize,
		fv.MethodScore,
		fv.TimeOfDay,
		fv.DayOfWeek,
	}
}

// Extract extracts features from an HTTP request.
func (e *Extractor) Extract(req *http.Request) *FeatureVector {
	fv := &FeatureVector{}

	// Extract path features
	fv.PathEntropy = calculateEntropy(req.URL.Path)
	fv.PathSegmentCount = float64(countPathSegments(req.URL.Path))
	fv.PathDepth = float64(countPathDepth(req.URL.Path))

	// Extract query features
	queryStr := req.URL.RawQuery
	fv.QueryEntropy = calculateEntropy(queryStr)
	fv.QueryParamCount = float64(len(req.URL.Query()))
	fv.QueryMaxLength = float64(getMaxQueryParamLength(req.URL.Query()))

	// Extract header features
	headerStr := headersToString(req.Header)
	fv.HeaderCount = float64(len(req.Header))
	fv.HeaderEntropy = calculateEntropy(headerStr)
	fv.ContentLength = float64(req.ContentLength)

	// Method score (higher = more risky)
	fv.MethodScore = getMethodRiskScore(req.Method)

	// Note: Body features require reading body (not done here)
	// Will be added in full implementation

	return fv
}

// ExtractWithBody extracts features including body analysis.
func (e *Extractor) ExtractWithBody(req *http.Request, body []byte) *FeatureVector {
	fv := e.Extract(req)

	// Body features
	if len(body) > 0 {
		bodySample := body
		if len(body) > e.maxBodySampleSize {
			bodySample = body[:e.maxBodySampleSize]
		}
		fv.BodyEntropy = calculateEntropy(string(bodySample))
		fv.BodySize = float64(len(body))
	}

	return fv
}

// calculateEntropy calculates Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(utf8.RuneCountInString(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	// Normalize to 0-1 range (max entropy for ASCII is log2(128) ≈ 7)
	maxEntropy := 7.0
	return math.Min(1.0, entropy/maxEntropy)
}

// countPathSegments counts the number of segments in a path.
func countPathSegments(path string) int {
	path = strings.Trim(path, "/")
	if path == "" {
		return 0
	}
	return strings.Count(path, "/") + 1
}

// countPathDepth counts navigation depth (../ patterns).
func countPathDepth(path string) int {
	return strings.Count(path, "../") + strings.Count(path, "..\\")
}

// getMaxQueryParamLength returns the maximum parameter value length.
func getMaxQueryParamLength(query map[string][]string) int {
	maxLen := 0
	for _, values := range query {
		for _, v := range values {
			if len(v) > maxLen {
				maxLen = len(v)
			}
		}
	}
	return maxLen
}

// headersToString concatenates all header values.
func headersToString(headers http.Header) string {
	var sb strings.Builder
	for name, values := range headers {
		sb.WriteString(name)
		sb.WriteString(":")
		for _, v := range values {
			sb.WriteString(v)
		}
	}
	return sb.String()
}

// getMethodRiskScore returns a risk score for HTTP methods.
func getMethodRiskScore(method string) float64 {
	switch method {
	case "GET":
		return 0.1
	case "HEAD", "OPTIONS":
		return 0.0
	case "POST":
		return 0.3
	case "PUT":
		return 0.5
	case "DELETE":
		return 0.7
	case "PATCH":
		return 0.4
	default:
		return 0.9 // Unknown methods are suspicious
	}
}

// Normalizer normalizes feature values.
type Normalizer struct {
	// Min/max values for normalization
	minValues []float64
	maxValues []float64
}

// NewNormalizer creates a new feature normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		minValues: make([]float64, 14),
		maxValues: make([]float64, 14),
	}
}

// Normalize scales features to 0-1 range.
func (n *Normalizer) Normalize(features []float64) []float64 {
	normalized := make([]float64, len(features))
	for i, v := range features {
		min := n.minValues[i]
		max := n.maxValues[i]
		if max > min {
			normalized[i] = (v - min) / (max - min)
		} else {
			normalized[i] = v
		}
	}
	return normalized
}
