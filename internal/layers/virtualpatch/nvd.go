package virtualpatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NVDClient is a client for the National Vulnerability Database API.
type NVDClient struct {
	mu         sync.RWMutex
	baseURL    string
	apiKey     string
	httpClient *http.Client
	// allowPrivate is used by tests that exercise the client with httptest
	// loopback servers. Production code must leave this false.
	allowPrivate bool
}

// NewNVDClient creates a new NVD API client.
func NewNVDClient(apiKey string) *NVDClient {
	c := &NVDClient{
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		apiKey:  apiKey,
	}
	c.httpClient = c.newHTTPClient()
	return c
}

func (c *NVDClient) newHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	transport = transport.Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if c.privateAllowed() {
			return dialer.DialContext(ctx, network, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("NVD SSRF dial: DNS lookup failed for %q: %w", host, err)
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			target := ip.String()
			if port != "" {
				target = net.JoinHostPort(target, port)
			}
			return dialer.DialContext(ctx, network, target)
		}
		return nil, fmt.Errorf("NVD SSRF dial: no valid public IPs for %q", host)
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if c.privateAllowed() {
				return nil
			}
			if err := validateURLNotPrivate(req.URL.String()); err != nil {
				return fmt.Errorf("redirect URL rejected: %w", err)
			}
			return nil
		},
	}
}

func (c *NVDClient) privateAllowed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.allowPrivate
}

// SetBaseURL sets a custom base URL for the NVD API.
// Returns an error if the URL targets a private/loopback address (SSRF protection).
func (c *NVDClient) SetBaseURL(baseURL string) error {
	if err := validateURLNotPrivate(baseURL); err != nil {
		return fmt.Errorf("base URL rejected: %w", err)
	}
	if strings.HasPrefix(baseURL, "http://") {
		log.Printf("[virtualpatch] WARNING: NVD base URL is not HTTPS: %s", baseURL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = baseURL
	return nil
}

// validateURLNotPrivate checks that a URL does not resolve to a private,
// loopback, or link-local IP address (SSRF prevention).
func validateURLNotPrivate(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("must not target localhost or internal hosts")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("must not target private/loopback/link-local addresses")
		}
		return nil
	}
	// Hostname — resolve DNS and check all resulting IPs (prevents DNS rebinding)
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil // DNS failure — will fail at connection time
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("hostname resolves to private/loopback address %s", ip)
		}
	}
	return nil
}

// NVDResponse represents the NVD API response.
type NVDResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Vulnerabilities []NVDCVEItem `json:"vulnerabilities"`
}

// NVDCVEItem represents a CVE item in the NVD response.
type NVDCVEItem struct {
	CVE NVDCVE `json:"cve"`
}

// NVDCVE represents CVE data.
type NVDCVE struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []NVDDescription `json:"descriptions"`
	Metrics          NVDMetrics       `json:"metrics"`
	Configurations   []NVDConfig      `json:"configurations"`
	References       []NVDReference   `json:"references"`
	Weaknesses       []NVDWeakness    `json:"weaknesses"`
}

// NVDDescription represents a CVE description.
type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDMetrics represents CVE metrics.
type NVDMetrics struct {
	CVSSMetricV31 []NVDCVSSMetricV31 `json:"cvssMetricV31"`
	CVSSMetricV30 []NVDCVSSMetricV30 `json:"cvssMetricV30"`
	CVSSMetricV2  []NVDCVSSMetricV2  `json:"cvssMetricV2"`
}

// NVDCVSSMetricV31 represents CVSS v3.1 metrics.
type NVDCVSSMetricV31 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData NVDCVSSData `json:"cvssData"`
}

// NVDCVSSMetricV30 represents CVSS v3.0 metrics.
type NVDCVSSMetricV30 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData NVDCVSSData `json:"cvssData"`
}

// NVDCVSSMetricV2 represents CVSS v2 metrics.
type NVDCVSSMetricV2 struct {
	Source   string        `json:"source"`
	Type     string        `json:"type"`
	CVSSData NVDCVSSDataV2 `json:"cvssData"`
}

// NVDCVSSData represents CVSS v3 data.
type NVDCVSSData struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

// NVDCVSSDataV2 represents CVSS v2 data.
type NVDCVSSDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

// NVDConfig represents CPE configurations.
type NVDConfig struct {
	Nodes []NVDNode `json:"nodes"`
}

// NVDNode represents a configuration node.
type NVDNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

// CPEMatch represents CPE match criteria.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// NVDReference represents a CVE reference.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// NVDWeakness represents CWE weaknesses.
type NVDWeakness struct {
	Source      string           `json:"source"`
	Type        string           `json:"type"`
	Description []NVDDescription `json:"description"`
}

// SearchOptions represents search options for the NVD API.
type SearchOptions struct {
	Keyword        string
	ResultsPerPage int
	StartIndex     int
	PubStartDate   time.Time
	PubEndDate     time.Time
	ModStartDate   time.Time
	ModEndDate     time.Time
	Severity       string
	CWEID          string
}

// Search searches for CVEs in the NVD.
func (c *NVDClient) Search(opts SearchOptions) (*NVDResponse, error) {
	c.mu.RLock()
	baseURL := c.baseURL
	apiKey := c.apiKey
	client := c.httpClient
	c.mu.RUnlock()

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}

	q := u.Query()

	if opts.Keyword != "" {
		q.Set("keywordSearch", opts.Keyword)
	}

	if opts.ResultsPerPage > 0 {
		q.Set("resultsPerPage", fmt.Sprintf("%d", opts.ResultsPerPage))
	}

	if opts.StartIndex > 0 {
		q.Set("startIndex", fmt.Sprintf("%d", opts.StartIndex))
	}

	if !opts.PubStartDate.IsZero() {
		q.Set("pubStartDate", opts.PubStartDate.Format(time.RFC3339))
	}

	if !opts.PubEndDate.IsZero() {
		q.Set("pubEndDate", opts.PubEndDate.Format(time.RFC3339))
	}

	if opts.Severity != "" {
		q.Set("cvssV3Severity", opts.Severity)
	}

	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain; error ignored
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result NVDResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 50<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain; error ignored

	return &result, nil
}

// GetCVE retrieves a specific CVE by ID.
func (c *NVDClient) GetCVE(cveID string) (*CVEEntry, error) {
	c.mu.RLock()
	baseURL := c.baseURL
	apiKey := c.apiKey
	client := c.httpClient
	c.mu.RUnlock()

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}

	q := u.Query()
	q.Set("cveId", cveID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain; error ignored
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result NVDResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 50<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain; error ignored

	if len(result.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	return convertToCVEEntry(result.Vulnerabilities[0].CVE), nil
}

// convertToCVEEntry converts NVD CVE to our CVEEntry format.
func convertToCVEEntry(nvdCVE NVDCVE) *CVEEntry {
	entry := &CVEEntry{
		CVEID:         nvdCVE.ID,
		PublishedDate: parseNVDDatetime(nvdCVE.Published),
		ModifiedDate:  parseNVDDatetime(nvdCVE.LastModified),
		VulnStatus:    nvdCVE.VulnStatus,
		Source:        "nvd",
		Active:        true,
	}

	// Extract description (prefer English)
	for _, desc := range nvdCVE.Descriptions {
		if desc.Lang == "en" {
			entry.Description = desc.Value
			break
		}
	}

	// Extract CVSS score and severity
	if len(nvdCVE.Metrics.CVSSMetricV31) > 0 {
		entry.CVSSScore = nvdCVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		entry.Severity = nvdCVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
	} else if len(nvdCVE.Metrics.CVSSMetricV30) > 0 {
		entry.CVSSScore = nvdCVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		entry.Severity = nvdCVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
	} else if len(nvdCVE.Metrics.CVSSMetricV2) > 0 {
		entry.CVSSScore = nvdCVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		// Convert CVSS v2 score to severity
		entry.Severity = cvssV2ToSeverity(entry.CVSSScore)
	}

	// Extract CWEs
	for _, weakness := range nvdCVE.Weaknesses {
		for _, desc := range weakness.Description {
			if desc.Lang == "en" && len(desc.Value) > 4 && desc.Value[:4] == "CWE-" {
				entry.CWEs = append(entry.CWEs, desc.Value)
			}
		}
	}

	// Extract affected products from configurations
	for _, config := range nvdCVE.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if match.Vulnerable {
					entry.AffectedProducts = append(entry.AffectedProducts, Product{
						CPE: match.Criteria,
					})
				}
			}
		}
	}

	return entry
}

// parseNVDDatetime parses NVD datetime format.
func parseNVDDatetime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// cvssV2ToSeverity converts CVSS v2 score to severity string.
func cvssV2ToSeverity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
