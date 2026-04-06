package virtualpatch

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// NVDClient is a client for the National Vulnerability Database API.
type NVDClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewNVDClient creates a new NVD API client.
func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetBaseURL sets a custom base URL for the NVD API.
func (c *NVDClient) SetBaseURL(baseURL string) {
	c.baseURL = baseURL
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
	Source   string       `json:"source"`
	Type     string       `json:"type"`
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
	Operator string   `json:"operator"`
	Negate   bool     `json:"negate"`
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
	URL  string `json:"url"`
	Source string `json:"source"`
	Tags []string `json:"tags,omitempty"`
}

// NVDWeakness represents CWE weaknesses.
type NVDWeakness struct {
	Source      string   `json:"source"`
	Type        string   `json:"type"`
	Description []NVDDescription `json:"description"`
}

// SearchOptions represents search options for the NVD API.
type SearchOptions struct {
	Keyword         string
	ResultsPerPage  int
	StartIndex      int
	PubStartDate    time.Time
	PubEndDate      time.Time
	ModStartDate    time.Time
	ModEndDate      time.Time
	Severity        string
	CWEID           string
}

// Search searches for CVEs in the NVD.
func (c *NVDClient) Search(opts SearchOptions) (*NVDResponse, error) {
	u, err := url.Parse(c.baseURL)
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

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// GetCVE retrieves a specific CVE by ID.
func (c *NVDClient) GetCVE(cveID string) (*CVEEntry, error) {
	u, err := url.Parse(c.baseURL)
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

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

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
