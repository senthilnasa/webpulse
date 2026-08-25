package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/senthilnasa/webpulse/pkg/api"
	"github.com/senthilnasa/webpulse/pkg/db"
)

func main() {
	port := flag.Int("port", 8090, "HTTP server port")
	dbPath := flag.String("db", "data/webpulse.json", "Path to database file")
	flag.Parse()

	store, err := db.NewStore(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	server := api.NewServer(store)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Serve static frontend files
	staticDir := "frontend/dist"
	if _, err := os.Stat(staticDir); err == nil {
		indexContent, err := os.ReadFile(filepath.Join(staticDir, "index.html"))
		if err == nil {
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// Don't serve HTML index for API routes
				if strings.HasPrefix(r.URL.Path, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprintf(w, `{"error":"API endpoint '%s' not found"}`, r.URL.Path)
					return
				}

				if r.URL.Path != "/" && r.URL.Path != "/index.html" {
					filePath := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
					if fi, err := os.Stat(filePath); err == nil && !fi.IsDir() {
						http.ServeFile(w, r, filePath)
						return
					}
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write(indexContent)
			})
			log.Printf("Serving static frontend assets from %s", staticDir)
		}
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("WebPulse Server starting on http://localhost%s", addr)
	log.Printf("REST API v1 endpoints ready at http://localhost%s/api/v1/", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}
