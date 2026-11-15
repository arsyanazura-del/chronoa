package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPterodactylClientListsServersAndCreatesBackup(t *testing.T) {
	var createCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected authorization header")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/client/servers":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"attributes":{"identifier":"abc123","name":"Game One","description":"","status":"running","limits":{"memory":2048},"feature_limits":{"backups":5}}}],"meta":{"pagination":{"total_pages":1}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/client/servers/abc123/backups":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"attributes":{"uuid":"backup-1","name":"Daily","bytes":100,"created_at":"2026-11-15T00:00:00Z","is_successful":true,"is_locked":false}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/client/servers/abc123/backups":
			var input map[string]any
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("invalid backup request: %v", err)
			}
			if input["is_locked"] != false || !strings.HasPrefix(input["name"].(string), "Chronoa ") {
				t.Errorf("unexpected backup request body: %#v", input)
			}
			createCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"data":{"attributes":{"uuid":"backup-new","name":"Chronoa test","bytes":0}}}`))
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := newPterodactylClient(server.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	servers, err := client.listServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Identifier != "abc123" || servers[0].BackupLimit != 5 {
		t.Fatalf("unexpected servers: %+v", servers)
	}
	if !strings.HasSuffix(servers[0].ConsoleURL, "/server/abc123") {
		t.Fatalf("unexpected console URL: %s", servers[0].ConsoleURL)
	}
	backups, err := client.listBackups(context.Background(), "abc123")
	if err != nil || len(backups) != 1 || backups[0].UUID != "backup-1" {
		t.Fatalf("unexpected backups: %+v, error: %v", backups, err)
	}
	backup, err := client.createBackup(context.Background(), "abc123")
	if err != nil || backup.UUID != "backup-new" {
		t.Fatalf("unexpected backup response: %+v, error: %v", backup, err)
	}
	if _, err := client.createBackup(context.Background(), "abc123"); err == nil {
		t.Fatal("repeated backup request should be rate limited")
	}
	if createCount != 1 {
		t.Fatalf("create endpoint called %d times, want 1", createCount)
	}
}

func TestPterodactylClientRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := newPterodactylClient("http://panel.example.com", "test-key"); err == nil {
		t.Fatal("non-HTTPS panel URL should be rejected")
	}
	if _, err := newPterodactylClient("https://user:pass@panel.example.com", "test-key"); err == nil {
		t.Fatal("URL with embedded credentials should be rejected")
	}
	client, err := newPterodactylClient("https://panel.example.com", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.listBackups(context.Background(), "../admin"); err == nil {
		t.Fatal("invalid server identifier should be rejected")
	}
}

func TestPterodactylRoutesRequireMFAAndCSRF(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/client/servers/abc123/backups" {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	client, err := newPterodactylClient(upstream.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	auth := &authManager{sessions: map[string]*authSession{
		"valid-session": {CSRF: "valid-csrf", Expires: time.Now().Add(time.Hour), MFAVerified: true},
	}}
	mux := http.NewServeMux()
	client.registerRoutes(mux, auth)

	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/pterodactyl/servers", nil))
	if unauthorized.Code != http.StatusUnauthorized || upstreamCalls != 0 {
		t.Fatalf("unauthenticated request reached Pterodactyl: status=%d calls=%d", unauthorized.Code, upstreamCalls)
	}

	missingCSRF := httptest.NewRequest(http.MethodPost, "/api/pterodactyl/servers/abc123/backups", nil)
	missingCSRF.AddCookie(&http.Cookie{Name: "__Host-chronoa", Value: "valid-session"})
	missingCSRF.Host = "chronoa.test"
	missingCSRF.Header.Set("Origin", "https://chronoa.test")
	blocked := httptest.NewRecorder()
	mux.ServeHTTP(blocked, missingCSRF)
	if blocked.Code != http.StatusForbidden || upstreamCalls != 0 {
		t.Fatalf("request without CSRF token reached Pterodactyl: status=%d calls=%d", blocked.Code, upstreamCalls)
	}

	valid := httptest.NewRequest(http.MethodPost, "/api/pterodactyl/servers/abc123/backups", nil)
	valid.AddCookie(&http.Cookie{Name: "__Host-chronoa", Value: "valid-session"})
	valid.Host = "chronoa.test"
	valid.Header.Set("Origin", "https://chronoa.test")
	valid.Header.Set("X-CSRF-Token", "valid-csrf")
	accepted := httptest.NewRecorder()
	mux.ServeHTTP(accepted, valid)
	if accepted.Code != http.StatusAccepted || upstreamCalls != 1 {
		t.Fatalf("authorized backup request failed: status=%d calls=%d body=%s", accepted.Code, upstreamCalls, accepted.Body.String())
	}
}
