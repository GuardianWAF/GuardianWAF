package discovery

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// Analyzer analyzes captured traffic to discover APIs.
type Analyzer struct {
	config AnalysisConfig

	lastRun    time.Time
	runCount   int
}

// AnalysisResult contains analysis results.
type AnalysisResult struct {
	Inventory *Inventory
	Clusters  []Cluster
}

// NewAnalyzer creates a new traffic analyzer.
func NewAnalyzer(config AnalysisConfig) *Analyzer {
	return &Analyzer{
		config: config,
	}
}

// Analyze analyzes captured requests.
func (a *Analyzer) Analyze(requests []CapturedRequest) *AnalysisResult {
	a.lastRun = time.Now()
	a.runCount++

	// Run clustering
	clusteringEngine := NewClusteringEngine(
		a.config.MinClusterSize,
		a.config.SimilarityThreshold,
	)
	clusters := clusteringEngine.Cluster(requests)

	// Build inventory from clusters
	inventory := a.buildInventory(clusters)

	return &AnalysisResult{
		Inventory: inventory,
		Clusters:  clusters,
	}
}

// DetectChanges detects changes between old and new inventory.
func (a *Analyzer) DetectChanges(old, new *Inventory) []Change {
	var changes []Change

	if old == nil || new == nil {
		return changes
	}

	// Find new endpoints
	for id, newEP := range new.Endpoints {
		if _, exists := old.Endpoints[id]; !exists {
			changes = append(changes, Change{
				ID:          generateChangeID(),
				Type:        ChangeTypeNew,
				Severity:    SeverityMedium,
				EndpointID:  id,
				Pattern:     newEP.Pattern,
				Description: fmt.Sprintf("New endpoint discovered: %s %s", newEP.Methods, newEP.Pattern),
				Timestamp:   time.Now(),
			})
		}
	}

	// Find removed endpoints
	for id, oldEP := range old.Endpoints {
		if _, exists := new.Endpoints[id]; !exists {
			changes = append(changes, Change{
				ID:          generateChangeID(),
				Type:        ChangeTypeRemoved,
				Severity:    SeverityHigh,
				EndpointID:  id,
				Pattern:     oldEP.Pattern,
				Description: fmt.Sprintf("Endpoint removed: %s", oldEP.Pattern),
				Timestamp:   time.Now(),
			})
		}
	}

	// Find modified endpoints
	for id, newEP := range new.Endpoints {
		if oldEP, exists := old.Endpoints[id]; exists {
			// Check for method changes
			if !slicesEqual(oldEP.Methods, newEP.Methods) {
				changes = append(changes, Change{
					ID:          generateChangeID(),
					Type:        ChangeTypeModified,
					Severity:    SeverityLow,
					EndpointID:  id,
					Pattern:     newEP.Pattern,
					Description: fmt.Sprintf("Methods changed for %s: %v -> %v", newEP.Pattern, oldEP.Methods, newEP.Methods),
					Timestamp:   time.Now(),
				})
			}

			// Check for parameter changes
			if len(oldEP.Parameters) != len(newEP.Parameters) {
				changes = append(changes, Change{
					ID:          generateChangeID(),
					Type:        ChangeTypeModified,
					Severity:    SeverityMedium,
					EndpointID:  id,
					Pattern:     newEP.Pattern,
					Description: fmt.Sprintf("Parameter count changed for %s: %d -> %d", newEP.Pattern, len(oldEP.Parameters), len(newEP.Parameters)),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return changes
}

// LastRun returns the last analysis time.
func (a *Analyzer) LastRun() time.Time {
	return a.lastRun
}

// buildInventory builds API inventory from clusters.
func (a *Analyzer) buildInventory(clusters []Cluster) *Inventory {
	inventory := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: make(map[string]*Endpoint),
		Statistics: Statistics{
			TotalEndpoints:   len(clusters),
			DynamicEndpoints: countDynamicEndpoints(clusters),
		},
	}

	for _, cluster := range clusters {
		endpoint := a.clusterToEndpoint(cluster)
		inventory.Endpoints[endpoint.ID] = endpoint
	}

	return inventory
}

// clusterToEndpoint converts a cluster to an endpoint.
func (a *Analyzer) clusterToEndpoint(cluster Cluster) *Endpoint {
	// Generate endpoint ID from pattern
	id := generateEndpointID(cluster.Pattern)

	// Extract methods
	methods := make([]string, 0, len(cluster.Methods))
	for method := range cluster.Methods {
		methods = append(methods, method)
	}

	// Convert status codes
	statusCodes := make(map[string]int)
	for code, count := range cluster.StatusCodes {
		statusCodes[fmt.Sprintf("%d", code)] = count
	}

	return &Endpoint{
		ID:          id,
		Pattern:     cluster.Pattern,
		PathRegex:   cluster.PathRegex.String(),
		Methods:     methods,
		Parameters:  cluster.Parameters,
		Examples:    cluster.Examples,
		Count:       cluster.Count,
		FirstSeen:   time.Unix(cluster.FirstSeen, 0),
		LastSeen:    time.Unix(cluster.LastSeen, 0),
		StatusCodes: statusCodes,
		Tags:        a.inferTags(cluster),
	}
}

// inferTags infers endpoint tags from cluster data.
func (a *Analyzer) inferTags(cluster Cluster) []string {
	var tags []string

	// Check if requires authentication
	for _, param := range cluster.Parameters {
		if param.In == "header" && (param.Name == "authorization" || param.Name == "x-api-key") {
			tags = append(tags, "auth-required")
			break
		}
	}

	// Check if sensitive
	if containsSensitivePattern(cluster.Pattern) {
		tags = append(tags, "sensitive")
	}

	// Check if public
	if len(tags) == 0 {
		tags = append(tags, "public")
	}

	return tags
}

// generateEndpointID generates a unique endpoint ID.
func generateEndpointID(pattern string) string {
	h := sha256.New()
	h.Write([]byte(pattern))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

// generateChangeID generates a unique change ID.
func generateChangeID() string {
	return fmt.Sprintf("change-%d", time.Now().UnixNano())
}

// Helper functions

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		if m[v] == 0 {
			return false
		}
		m[v]--
	}
	return true
}

func countDynamicEndpoints(clusters []Cluster) int {
	count := 0
	for _, c := range clusters {
		if len(c.Parameters) > 0 {
			count++
		}
	}
	return count
}

func containsSensitivePattern(pattern string) bool {
	sensitivePatterns := []string{
		"password", "secret", "token", "auth", "login", "admin",
		"payment", "credit", "card", "ssn", "personal",
	}

	lowerPattern := pattern
	for _, p := range sensitivePatterns {
		if findSubstring(lowerPattern, p) >= 0 {
			return true
		}
	}
	return false
}
