// Package tenant provides multi-tenancy support with namespace isolation.
package tenant

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Store provides persistent storage for tenant data.
type Store struct {
	mu       sync.RWMutex
	basePath string
	index    map[string]string // tenantID -> filename
}

// safeTenantID validates that a tenant ID contains only safe characters.
func safeTenantID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// NewStore creates a new tenant store.
func NewStore(basePath string) *Store {
	if basePath == "" {
		basePath = "data/tenants"
	}
	return &Store{
		basePath: basePath,
		index:    make(map[string]string),
	}
}

// Init initializes the store directory and loads the index.
func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create directory if not exists
	if err := os.MkdirAll(s.basePath, 0o700); err != nil {
		return fmt.Errorf("creating tenant directory: %w", err)
	}

	// Load index
	indexPath := filepath.Join(s.basePath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err == nil {
		if unmarshalErr := json.Unmarshal(data, &s.index); unmarshalErr != nil {
			fmt.Printf("[tenant-store] warning: failed to parse %s: %v\n", indexPath, unmarshalErr)
		}
	}

	return nil
}

// SaveTenant persists a tenant to disk.
func (s *Store) SaveTenant(tenant *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prepare tenant data (without runtime stats)
	data := &tenantData{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Description: tenant.Description,
		CreatedAt:   tenant.CreatedAt,
		UpdatedAt:   time.Now(),
		Active:      tenant.Active,
		APIKeyHash:  tenant.APIKeyHash,
		Domains:     tenant.Domains,
		Quota:       tenant.Quota,
		Config:      tenant.Config,
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling tenant: %w", err)
	}

	// Write to file
	filename := fmt.Sprintf("%s.json", tenant.ID)
	filepath := filepath.Join(s.basePath, filename)
	if err := os.WriteFile(filepath, jsonData, 0600); err != nil {
		return fmt.Errorf("writing tenant file: %w", err)
	}

	// Update index
	s.index[tenant.ID] = filename
	return s.saveIndex()
}

// LoadTenant loads a tenant from disk.
func (s *Store) LoadTenant(tenantID string) (*Tenant, error) {
	if !safeTenantID(tenantID) {
		return nil, fmt.Errorf("invalid tenant ID")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	filename, exists := s.index[tenantID]
	if !exists {
		filename = fmt.Sprintf("%s.json", tenantID)
	}

	filepath := filepath.Join(s.basePath, filename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading tenant file: %w", err)
	}

	var td tenantData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, fmt.Errorf("unmarshaling tenant: %w", err)
	}

	// Handle config
	cfg := td.Config
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	return &Tenant{
		ID:          td.ID,
		Name:        td.Name,
		Description: td.Description,
		CreatedAt:   td.CreatedAt,
		UpdatedAt:   td.UpdatedAt,
		Active:      td.Active,
		APIKeyHash:  td.APIKeyHash,
		Domains:     td.Domains,
		Quota:       td.Quota,
		Config:      cfg,
	}, nil
}

// LoadAllTenants loads all tenants from disk.
func (s *Store) LoadAllTenants() ([]*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Rebuild index from filesystem
	s.index = make(map[string]string)
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("reading tenant directory: %w", err)
	}

	var tenants []*Tenant
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Name() == "index.json" {
			continue
		}

		filepath := filepath.Join(s.basePath, entry.Name())
		data, err := os.ReadFile(filepath)
		if err != nil {
			continue // Skip unreadable files
		}

		var td tenantData
		if err := json.Unmarshal(data, &td); err != nil {
			continue // Skip invalid files
		}

		s.index[td.ID] = entry.Name()
		// Handle config
		cfg := td.Config
		if cfg == nil {
			cfg = config.DefaultConfig()
		}

		tenants = append(tenants, &Tenant{
			ID:          td.ID,
			Name:        td.Name,
			Description: td.Description,
			CreatedAt:   td.CreatedAt,
			UpdatedAt:   td.UpdatedAt,
			Active:      td.Active,
			APIKeyHash:  td.APIKeyHash,
			Domains:     td.Domains,
			Quota:       td.Quota,
			Config:      cfg,
		})
	}

	// Save rebuilt index
	_ = s.saveIndex()

	return tenants, nil
}

// DeleteTenant removes a tenant from disk.
func (s *Store) DeleteTenant(tenantID string) error {
	if !safeTenantID(tenantID) {
		return fmt.Errorf("invalid tenant ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filename, exists := s.index[tenantID]
	if !exists {
		filename = fmt.Sprintf("%s.json", tenantID)
	}

	filepath := filepath.Join(s.basePath, filename)
	if err := os.Remove(filepath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing tenant file: %w", err)
	}

	delete(s.index, tenantID)
	return s.saveIndex()
}

// saveIndex persists the index file.
func (s *Store) saveIndex() error {
	indexPath := filepath.Join(s.basePath, "index.json")
	data, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(indexPath, data, 0600)
}

// tenantData is the serialized representation of a tenant.
type tenantData struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Active      bool             `json:"active"`
	APIKeyHash  string           `json:"api_key_hash"`
	Domains     []string         `json:"domains"`
	Quota       ResourceQuota    `json:"quota"`
	Config      *config.Config   `json:"config,omitempty"`
}
