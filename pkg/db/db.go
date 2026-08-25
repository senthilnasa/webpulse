package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/senthilnasa/webpulse/pkg/engine"
)

var ErrJobNotFound = errors.New("job not found")

// JobRecord represents persistent database metadata for a diagnostic test job.
type JobRecord struct {
	ID            string                `json:"id"`
	ProjectID     string                `json:"project_id"`
	Status        string                `json:"status"` // queued, running, completed, failed, cancelled
	Profile       string                `json:"profile"`
	TotalURLs     int                   `json:"total_urls"`
	CompletedURLs int                   `json:"completed_urls"`
	FailedURLs    int                   `json:"failed_urls"`
	BlockedURLs   int                   `json:"blocked_urls"`
	SkippedURLs   int                   `json:"skipped_urls"`
	Concurrency   int                   `json:"concurrency"`
	TimeoutSec    int                   `json:"timeout_sec"`
	CreatedAt     time.Time             `json:"created_at"`
	CompletedAt   *time.Time            `json:"completed_at,omitempty"`
	Results       []*engine.TargetResult `json:"results,omitempty"`
}

// ProjectRecord represents a target project workspace.
type ProjectRecord struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	AllowedScopes []string  `json:"allowed_scopes"`
	CreatedAt     time.Time `json:"created_at"`
}

// Store handles persistent storage operations.
type Store struct {
	mu       sync.RWMutex
	filePath string
	Data     struct {
		Projects map[string]*ProjectRecord `json:"projects"`
		Jobs     map[string]*JobRecord     `json:"jobs"`
	}
}

// NewStore initializes database storage backed by a JSON file.
func NewStore(filePath string) (*Store, error) {
	if filePath == "" {
		filePath = "data/webpulse.json"
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	store := &Store{
		filePath: filePath,
	}
	store.Data.Projects = make(map[string]*ProjectRecord)
	store.Data.Jobs = make(map[string]*JobRecord)

	// Load existing if present
	if _, err := os.Stat(filePath); err == nil {
		content, err := os.ReadFile(filePath)
		if err == nil {
			_ = json.Unmarshal(content, &store.Data)
		}
	}

	// Create default project if empty
	if len(store.Data.Projects) == 0 {
		defaultProj := &ProjectRecord{
			ID:          "default",
			Name:        "Default Project",
			Description: "Default URL Testing Project Workspace",
			CreatedAt:   time.Now(),
		}
		store.Data.Projects["default"] = defaultProj
		_ = store.saveUnlocked()
	}

	return store, nil
}

func (s *Store) saveUnlocked() error {
	bytes, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, bytes, 0644)
}

// CreateJob stores a new job record.
func (s *Store) CreateJob(job *JobRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data.Jobs[job.ID] = job
	return s.saveUnlocked()
}

// UpdateJob updates an existing job record and results.
func (s *Store) UpdateJob(job *JobRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data.Jobs[job.ID] = job
	return s.saveUnlocked()
}

// GetJob returns a job record by ID.
func (s *Store) GetJob(jobID string) (*JobRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.Data.Jobs[jobID]
	if !ok {
		return nil, ErrJobNotFound
	}
	return job, nil
}

// ListJobs returns all jobs ordered by created timestamp.
func (s *Store) ListJobs() []*JobRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*JobRecord
	for _, j := range s.Data.Jobs {
		list = append(list, j)
	}

	return list
}

// GetProject returns a project record.
func (s *Store) GetProject(id string) (*ProjectRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.Data.Projects[id]
	if !ok {
		return nil, errors.New("project not found")
	}
	return p, nil
}
