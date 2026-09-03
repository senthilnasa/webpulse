package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/senthilnasa/webpulse/pkg/db"
	"github.com/senthilnasa/webpulse/pkg/doctor"
	"github.com/senthilnasa/webpulse/pkg/egress"
	"github.com/senthilnasa/webpulse/pkg/engine"
	"github.com/senthilnasa/webpulse/pkg/export"
	"github.com/senthilnasa/webpulse/pkg/scope"
	"github.com/senthilnasa/webpulse/pkg/ssrf"
)

type Server struct {
	Store       *db.Store
	Engine      *engine.DiagnosticEngine
	activeJobs  map[string]context.CancelFunc
	jobStreams  map[string][]chan string
	streamMutex sync.Mutex
}

func NewServer(store *db.Store) *Server {
	return &Server{
		Store:      store,
		Engine:     engine.NewEngine(nil),
		activeJobs: make(map[string]context.CancelFunc),
		jobStreams: make(map[string][]chan string),
	}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1", s.handleAPIRoot)
	mux.HandleFunc("/api/v1/", s.handleAPIRoot)

	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/doctor", s.handleDoctor)
	mux.HandleFunc("/api/v1/egress", s.handleEgress)
	mux.HandleFunc("/api/v1/targets/validate", s.handleValidateTargets)

	mux.HandleFunc("/api/v1/jobs", s.handleJobs)
	mux.HandleFunc("/api/v1/jobs/", s.handleJobSubRoutes)
}

func (s *Server) handleAPIRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1" && r.URL.Path != "/api/v1/" {
		writeError(w, http.StatusNotFound, "API endpoint not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":    "WebPulse REST API",
		"version": "1.0.0",
		"endpoints": map[string]string{
			"health":           "/api/v1/health",
			"doctor":           "/api/v1/doctor",
			"egress":           "/api/v1/egress",
			"jobs":             "/api/v1/jobs",
			"validate_targets": "/api/v1/targets/validate",
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	report := doctor.RunDoctor(ctx)
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleEgress(w http.ResponseWriter, r *http.Request) {
	forceRefresh := r.URL.Query().Get("refresh") == "true"
	info, err := egress.DetectEgressInfo(r.Context(), forceRefresh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

type CreateJobRequest struct {
	ProjectID           string            `json:"project_id"`
	URLs                []string          `json:"urls"`
	Profile             string            `json:"profile"`
	Workers             int               `json:"workers"`
	TimeoutSec          int               `json:"timeout_sec"`
	AllowedScopes       []string          `json:"allowed_scopes"`
	HostResolutions     map[string]string `json:"host_resolutions,omitempty"`
	AllowPrivateTargets bool              `json:"allow_private_targets,omitempty"`
	HostsFileContent    string            `json:"hosts_file_content,omitempty"`
	AllowInsecureTLS    bool              `json:"allow_insecure_tls,omitempty"`
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jobs := s.Store.ListJobs()
		writeJSON(w, http.StatusOK, jobs)

	case http.MethodPost:
		var req CreateJobRequest

		// Support multipart file upload or JSON body
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseMultipartForm(10 * 1024 * 1024); err == nil {
				req.Profile = r.FormValue("profile")
				req.ProjectID = r.FormValue("project_id")
				req.HostsFileContent = r.FormValue("hosts_file_content")
				if r.FormValue("allow_insecure_tls") == "true" {
					req.AllowInsecureTLS = true
				}
				file, header, err := r.FormFile("file")
				if err == nil {
					defer file.Close()
					content, _ := io.ReadAll(file)
					urls, _ := export.ReadURLsInput(content, header.Filename)
					req.URLs = urls
				}
			}
		} else {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}

		if len(req.URLs) == 0 {
			writeError(w, http.StatusBadRequest, "No valid target URLs provided.")
			return
		}

		if req.ProjectID == "" {
			req.ProjectID = "default"
		}
		if req.Profile == "" {
			req.Profile = "standard"
		}

		if req.HostResolutions == nil {
			req.HostResolutions = make(map[string]string)
		}
		if req.HostsFileContent != "" {
			parsed, err := export.ParseHostsFile([]byte(req.HostsFileContent))
			if err == nil {
				for k, v := range parsed {
					req.HostResolutions[k] = v
				}
			}
		}

		jobID := fmt.Sprintf("job-%d", time.Now().UnixNano())
		prof := engine.DefaultProfile(req.Profile)
		if req.Workers > 0 {
			prof.Workers = req.Workers
		}
		if req.TimeoutSec > 0 {
			prof.Timeout = time.Duration(req.TimeoutSec) * time.Second
		}
		prof.HostResolutions = req.HostResolutions
		prof.AllowPrivateTargets = req.AllowPrivateTargets
		prof.AllowInsecure = req.AllowInsecureTLS

		jobRec := &db.JobRecord{
			ID:            jobID,
			ProjectID:     req.ProjectID,
			Status:        "running",
			Profile:       prof.Name,
			TotalURLs:     len(req.URLs),
			CompletedURLs: 0,
			Concurrency:   prof.Workers,
			TimeoutSec:    int(prof.Timeout.Seconds()),
			CreatedAt:     time.Now(),
		}

		_ = s.Store.CreateJob(jobRec)

		// Launch background worker
		jobCtx, cancel := context.WithCancel(context.Background())
		s.streamMutex.Lock()
		s.activeJobs[jobID] = cancel
		s.streamMutex.Unlock()

		go func() {
			defer func() {
				s.streamMutex.Lock()
				delete(s.activeJobs, jobID)
				s.streamMutex.Unlock()
			}()

			var scopePolicy *scope.ScopePolicy
			if len(req.AllowedScopes) > 0 {
				scopePolicy = &scope.ScopePolicy{AllowedPatterns: req.AllowedScopes}
			}

			eng := engine.NewEngine(scopePolicy)

			results := eng.ExecuteJob(jobCtx, jobID, req.URLs, prof, func(completed, total int, res *engine.TargetResult) {
				// Persist live progress so polling clients (and reconnecting
				// ones) see the job advance instead of a frozen 0/N.
				_ = s.Store.MutateJob(jobID, false, func(rec *db.JobRecord) {
					rec.CompletedURLs = completed
					switch res.Status {
					case "failed":
						rec.FailedURLs++
					case "blocked":
						rec.BlockedURLs++
					case "skipped":
						rec.SkippedURLs++
					}
					rec.Results = append(rec.Results, res)
				})

				// Broadcast SSE update
				msg, _ := json.Marshal(map[string]interface{}{
					"type":      "progress",
					"completed": completed,
					"total":     total,
					"latest":    res,
				})
				s.broadcastSSE(jobID, string(msg))
			})

			now := time.Now()
			_ = s.Store.MutateJob(jobID, true, func(rec *db.JobRecord) {
				rec.CompletedAt = &now
				if rec.Status != "cancelled" {
					rec.Status = "completed"
				}

				// Reconcile against the ordered result set: progress callbacks
				// record completion order, and cancelled targets never reach
				// them at all.
				rec.Results = results
				rec.CompletedURLs = len(results)
				rec.FailedURLs, rec.BlockedURLs, rec.SkippedURLs = 0, 0, 0
				for _, r := range results {
					switch r.Status {
					case "failed":
						rec.FailedURLs++
					case "blocked":
						rec.BlockedURLs++
					case "skipped":
						rec.SkippedURLs++
					}
				}
			})

			finalMsg, _ := json.Marshal(map[string]interface{}{
				"type":   "completed",
				"job_id": jobID,
			})
			s.broadcastSSE(jobID, string(finalMsg))
		}()

		writeJSON(w, http.StatusAccepted, jobRec)

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleJobSubRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "Invalid job ID")
		return
	}

	jobID := parts[0]
	job, err := s.Store.GetJob(jobID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	if len(parts) == 1 {
		// GET /api/v1/jobs/:id
		writeJSON(w, http.StatusOK, job)
		return
	}

	subRoute := parts[1]

	switch subRoute {
	case "cancel":
		s.streamMutex.Lock()
		cancel, ok := s.activeJobs[jobID]
		s.streamMutex.Unlock()
		if ok && cancel != nil {
			cancel()
			_ = s.Store.MutateJob(jobID, true, func(rec *db.JobRecord) {
				rec.Status = "cancelled"
			})
			writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
		} else {
			writeError(w, http.StatusBadRequest, "Job is not actively running")
		}

	case "results":
		writeJSON(w, http.StatusOK, job.Results)

	case "export.json":
		bytes, _ := export.GenerateJSON(job.Results)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", jobID))
		w.Write(bytes)

	case "export.csv":
		bytes, _ := export.GenerateCSV(job.Results)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", jobID))
		w.Write(bytes)

	case "export.zip":
		bytes, _ := export.GenerateZIP(jobID, job.Profile, job.Results)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", jobID))
		w.Write(bytes)

	case "stream":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "Streaming unsupported")
			return
		}

		messageChan := make(chan string, 256)
		s.streamMutex.Lock()
		s.jobStreams[jobID] = append(s.jobStreams[jobID], messageChan)
		s.streamMutex.Unlock()

		// Unregister on disconnect, otherwise every reopened job detail leaks a
		// subscriber that broadcasts keep writing to.
		defer func() {
			s.streamMutex.Lock()
			defer s.streamMutex.Unlock()
			subs := s.jobStreams[jobID]
			for i, ch := range subs {
				if ch == messageChan {
					s.jobStreams[jobID] = append(subs[:i], subs[i+1:]...)
					break
				}
			}
			if len(s.jobStreams[jobID]) == 0 {
				delete(s.jobStreams, jobID)
			}
		}()

		notify := r.Context().Done()
		for {
			select {
			case <-notify:
				return
			case msg, open := <-messageChan:
				if !open {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			}
		}

	default:
		writeError(w, http.StatusNotFound, "Subroute not found")
	}
}

func (s *Server) handleValidateTargets(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URLs          []string `json:"urls"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var scopePolicy *scope.ScopePolicy
	if len(body.AllowedScopes) > 0 {
		scopePolicy = &scope.ScopePolicy{AllowedPatterns: body.AllowedScopes}
	}
	validator := scope.NewScopeValidator(*scopePolicy)

	type ValidateResult struct {
		URL    string `json:"url"`
		Status string `json:"status"` // PASS, BLOCKED
		Reason string `json:"reason"`
	}

	var results []ValidateResult
	for _, u := range body.URLs {
		if _, err := ssrf.SanitizeURL(u); err != nil {
			results = append(results, ValidateResult{URL: u, Status: "BLOCKED", Reason: err.Error()})
		} else if scopePolicy != nil {
			if err := validator.ValidateURL(u); err != nil {
				results = append(results, ValidateResult{URL: u, Status: "BLOCKED", Reason: err.Error()})
			} else {
				results = append(results, ValidateResult{URL: u, Status: "PASS", Reason: "Valid & Authorized"})
			}
		} else {
			results = append(results, ValidateResult{URL: u, Status: "PASS", Reason: "Valid Target"})
		}
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) broadcastSSE(jobID, message string) {
	s.streamMutex.Lock()
	defer s.streamMutex.Unlock()

	channels := s.jobStreams[jobID]
	for _, ch := range channels {
		select {
		case ch <- message:
		default:
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func ParseIntQuery(r *http.Request, key string, defaultVal int) int {
	if val := r.URL.Query().Get(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
