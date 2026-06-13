// Package tenant provides multi-tenancy support with namespace isolation.
package tenant

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

var storeLog = slog.Default().With(slog.String("component", "tenant/store"))

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

func cleanTenantStorePath(basePath string) (string, error) {
	if strings.ContainsRune(basePath, 0) {
		return "", fmt.Errorf("tenant store path contains NUL byte")
	}
	if basePath == "" {
		basePath = "data/tenants"
	}
	return filepath.Clean(basePath), nil
}

func tenantFilename(tenantID string) (string, error) {
	if !safeTenantID(tenantID) {
		return "", fmt.Errorf("invalid tenant ID")
	}
	return tenantID + ".json", nil
}

func validTenantDataFilename(name string) bool {
	if name == "index.json" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return false
	}
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	return safeTenantID(strings.TrimSuffix(name, ".json"))
}

func tenantFilePath(basePath, filename string) (string, error) {
	if !validTenantDataFilename(filename) {
		return "", fmt.Errorf("invalid tenant filename %q", filename)
	}
	basePath, err := cleanTenantStorePath(basePath)
	if err != nil {
		return "", err
	}
	path := filepath.Join(basePath, filename)
	if !pathWithinDir(basePath, path) {
		return "", fmt.Errorf("tenant file %q escapes store directory", filename)
	}
	return path, nil
}

func pathWithinDir(dir, path string) bool {
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// NewStore creates a new tenant store.
func NewStore(basePath string) *Store {
	cleanPath, err := cleanTenantStorePath(basePath)
	if err != nil {
		cleanPath = "data/tenants"
	}
	return &Store{
		basePath: cleanPath,
		index:    make(map[string]string),
	}
}

// Init initializes the store directory and loads the index.
func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	basePath, err := cleanTenantStorePath(s.basePath)
	if err != nil {
		return fmt.Errorf("validating tenant directory: %w", err)
	}
	s.basePath = basePath

	// Create directory if not exists
	if err := os.MkdirAll(s.basePath, 0o700); err != nil {
		return fmt.Errorf("creating tenant directory: %w", err)
	}

	// Load index
	indexPath := filepath.Join(s.basePath, "index.json")
	// #nosec G304 -- index path is a fixed filename under the cleaned tenant store directory.
	data, err := os.ReadFile(indexPath)
	if err == nil {
		if unmarshalErr := json.Unmarshal(data, &s.index); unmarshalErr != nil {
			storeLog.Warn("failed to parse tenant store index", "path", indexPath, "err", unmarshalErr)
		}
	}

	return nil
}

// SaveTenant persists a tenant to disk.
func (s *Store) SaveTenant(tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is nil")
	}
	filename, err := tenantFilename(tenant.ID)
	if err != nil {
		return err
	}

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

	// Write to file atomically (temp + rename)
	path, err := tenantFilePath(s.basePath, filename)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, jsonData, 0600); err != nil {
		return fmt.Errorf("writing tenant file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming tenant file: %w", err)
	}

	// Update index
	s.index[tenant.ID] = filename
	return s.saveIndex()
}

// LoadTenant loads a tenant from disk.
func (s *Store) LoadTenant(tenantID string) (*Tenant, error) {
	filename, err := tenantFilename(tenantID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if indexed, exists := s.index[tenantID]; exists && indexed != filename {
		return nil, fmt.Errorf("tenant index entry for %q points to unexpected file %q", tenantID, indexed)
	}

	path, err := tenantFilePath(s.basePath, filename)
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- tenant filename is derived from a validated tenant ID and constrained to the store directory.
	data, err := os.ReadFile(path)
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
		if !validTenantDataFilename(entry.Name()) {
			continue
		}

		path, err := tenantFilePath(s.basePath, entry.Name())
		if err != nil {
			continue
		}
		// #nosec G304 -- entry filename is validated as a tenant data filename and constrained to the store directory.
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Skip unreadable files
		}

		var td tenantData
		if err := json.Unmarshal(data, &td); err != nil {
			continue // Skip invalid files
		}
		if !safeTenantID(td.ID) || entry.Name() != td.ID+".json" {
			continue
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
	filename, err := tenantFilename(tenantID)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if indexed, exists := s.index[tenantID]; exists && indexed != filename {
		return fmt.Errorf("tenant index entry for %q points to unexpected file %q", tenantID, indexed)
	}

	path, err := tenantFilePath(s.basePath, filename)
	if err != nil {
		return err
	}
	// #nosec G304 -- tenant filename is derived from a validated tenant ID and constrained to the store directory.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
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
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Active      bool           `json:"active"`
	APIKeyHash  string         `json:"api_key_hash"`
	Domains     []string       `json:"domains"`
	Quota       ResourceQuota  `json:"quota"`
	Config      *config.Config `json:"config,omitempty"`
}
