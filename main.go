package main

import (
	"embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

//go:embed index.html
var dashboard embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "address for the read-only dashboard")
	dataDir := flag.String("data-dir", "./data", "directory for persistent timeline events")
	flag.Parse()

	sampler := &sampler{}
	events, err := newEventStore(*dataDir)
	if err != nil {
		log.Fatalf("could not initialize event store: %v", err)
	}
	history, err := newHistoryStore(*dataDir)
	if err != nil {
		log.Fatalf("could not initialize metric history: %v", err)
	}
	auth, err := newAuthManager(os.Getenv("CHRONOA_ADMIN_PASSWORD"), *dataDir)
	if err != nil {
		log.Fatalf("could not initialize authentication: %v", err)
	}
	pterodactyl, err := newPterodactylClient(os.Getenv("PTERODACTYL_URL"), os.Getenv("PTERODACTYL_API_KEY"))
	if err != nil {
		log.Fatalf("could not initialize Pterodactyl integration: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		body, err := dashboard.ReadFile("index.html")
		if err != nil {
			http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/auth/status", auth.status)
	mux.HandleFunc("/api/auth/login", auth.login)
	mux.HandleFunc("/api/auth/logout", auth.logout)
	mux.HandleFunc("/api/auth/totp/start", auth.startTOTP)
	mux.HandleFunc("/api/auth/totp/verify", auth.verifyTOTPSetup)
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		metrics, err := sampler.collect()
		if err != nil {
			http.Error(w, "could not read Linux metrics", http.StatusInternalServerError)
			return
		}
		if err := events.evaluate(metrics); err != nil {
			log.Printf("could not persist timeline event: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(metrics)
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || parsed < 1 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			limit = min(parsed, maxEvents)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(events.list(r.URL.Query().Get("category"), limit))
	})
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		window, ok := historyWindows[r.URL.Query().Get("range")]
		if !ok {
			http.Error(w, "invalid range", http.StatusBadRequest)
			return
		}
		points, err := history.query(window)
		if err != nil {
			http.Error(w, "could not read metric history", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(points)
	})
	pterodactyl.registerRoutes(mux, auth)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go monitor(sampler, events, history, 30*time.Second)
	log.Printf("Chronoa listening on http://%s", *addr)
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func monitor(sampler *sampler, events *eventStore, history *historyStore, interval time.Duration) {
	collect := func() {
		current, err := sampler.collect()
		if err != nil {
			log.Printf("background metrics collection failed: %v", err)
			return
		}
		if err := events.evaluate(current); err != nil {
			log.Printf("could not persist timeline event: %v", err)
		}
		if err := history.append(current); err != nil {
			log.Printf("could not persist metric sample: %v", err)
		}
	}
	collect()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		collect()
	}
}
