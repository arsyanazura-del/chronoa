package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultPterodactylURL = "https://panel.rsynzr.cloud"

var serverIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`)
var errBackupRateLimited = errors.New("a backup was already requested for this server recently")

type pterodactylClient struct {
	baseURL    *url.URL
	apiKey     string
	http       *http.Client
	mu         sync.Mutex
	lastBackup map[string]time.Time
}

type pterodactylServer struct {
	Identifier  string `json:"identifier"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Memory      int64  `json:"memory"`
	BackupLimit int    `json:"backupLimit"`
	ConsoleURL  string `json:"consoleUrl"`
}

type pterodactylBackup struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Bytes       int64  `json:"bytes"`
	CreatedAt   string `json:"createdAt"`
	CompletedAt string `json:"completedAt"`
	Successful  *bool  `json:"successful"`
	Locked      bool   `json:"locked"`
}

type pteroEnvelope struct {
	Data []struct {
		Attributes json.RawMessage `json:"attributes"`
	} `json:"data"`
	Meta struct {
		Pagination struct {
			TotalPages int `json:"total_pages"`
		} `json:"pagination"`
	} `json:"meta"`
}

func newPterodactylClient(panelURL, apiKey string) (*pterodactylClient, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, nil
	}
	if strings.TrimSpace(panelURL) == "" {
		panelURL = defaultPterodactylURL
	}
	baseURL, err := url.Parse(strings.TrimRight(strings.TrimSpace(panelURL), "/"))
	if err != nil || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid Pterodactyl panel URL")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && isLoopbackHost(baseURL.Hostname())) {
		return nil, errors.New("Pterodactyl API must use HTTPS")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &pterodactylClient{baseURL: baseURL, apiKey: apiKey, http: client, lastBackup: make(map[string]time.Time)}, nil
}

func (p *pterodactylClient) configured() bool {
	return p != nil && p.baseURL != nil && p.apiKey != ""
}

func (p *pterodactylClient) consoleURL(identifier string) string {
	return strings.TrimRight(p.baseURL.String(), "/") + "/server/" + url.PathEscape(identifier)
}

func (p *pterodactylClient) listServers(ctx context.Context) ([]pterodactylServer, error) {
	var result []pterodactylServer
	for page := 1; page <= 20; page++ {
		var envelope pteroEnvelope
		if err := p.request(ctx, http.MethodGet, "/api/client/servers?page="+strconv.Itoa(page), nil, &envelope); err != nil {
			return nil, err
		}
		for _, item := range envelope.Data {
			var attributes struct {
				Identifier  string `json:"identifier"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Status      string `json:"status"`
				Limits      struct {
					Memory int64 `json:"memory"`
				} `json:"limits"`
				FeatureLimits struct {
					Backups int `json:"backups"`
				} `json:"feature_limits"`
			}
			if err := json.Unmarshal(item.Attributes, &attributes); err != nil {
				return nil, errors.New("invalid Pterodactyl server response")
			}
			if !serverIdentifierPattern.MatchString(attributes.Identifier) {
				continue
			}
			result = append(result, pterodactylServer{
				Identifier:  attributes.Identifier,
				Name:        attributes.Name,
				Description: attributes.Description,
				Status:      attributes.Status,
				Memory:      attributes.Limits.Memory,
				BackupLimit: attributes.FeatureLimits.Backups,
				ConsoleURL:  p.consoleURL(attributes.Identifier),
			})
		}
		if envelope.Meta.Pagination.TotalPages <= page || len(envelope.Data) == 0 {
			break
		}
	}
	return result, nil
}

func (p *pterodactylClient) listBackups(ctx context.Context, identifier string) ([]pterodactylBackup, error) {
	if !serverIdentifierPattern.MatchString(identifier) {
		return nil, errors.New("invalid server identifier")
	}
	result := make([]pterodactylBackup, 0)
	for page := 1; page <= 20; page++ {
		var envelope pteroEnvelope
		path := "/api/client/servers/" + url.PathEscape(identifier) + "/backups?page=" + strconv.Itoa(page)
		if err := p.request(ctx, http.MethodGet, path, nil, &envelope); err != nil {
			return nil, err
		}
		for _, item := range envelope.Data {
			var attributes struct {
				UUID        string `json:"uuid"`
				Name        string `json:"name"`
				Bytes       int64  `json:"bytes"`
				CreatedAt   string `json:"created_at"`
				CompletedAt string `json:"completed_at"`
				Successful  *bool  `json:"is_successful"`
				Locked      bool   `json:"is_locked"`
			}
			if err := json.Unmarshal(item.Attributes, &attributes); err != nil {
				return nil, errors.New("invalid Pterodactyl backup response")
			}
			result = append(result, pterodactylBackup{
				UUID: attributes.UUID, Name: attributes.Name, Bytes: attributes.Bytes,
				CreatedAt: attributes.CreatedAt, CompletedAt: attributes.CompletedAt,
				Successful: attributes.Successful, Locked: attributes.Locked,
			})
		}
		if envelope.Meta.Pagination.TotalPages <= page || len(envelope.Data) == 0 {
			break
		}
		if page == 20 {
			return nil, errors.New("Pterodactyl backup list exceeds maximum pages")
		}
	}
	return result, nil
}

func (p *pterodactylClient) createBackup(ctx context.Context, identifier string) (pterodactylBackup, error) {
	if !serverIdentifierPattern.MatchString(identifier) {
		return pterodactylBackup{}, errors.New("invalid server identifier")
	}
	p.mu.Lock()
	if last := p.lastBackup[identifier]; time.Since(last) < time.Minute {
		p.mu.Unlock()
		return pterodactylBackup{}, errBackupRateLimited
	}
	p.lastBackup[identifier] = time.Now()
	p.mu.Unlock()
	body := struct {
		Name     string `json:"name"`
		IsLocked bool   `json:"is_locked"`
	}{Name: "Chronoa " + time.Now().UTC().Format("2006-01-02 15:04 UTC")}
	path := "/api/client/servers/" + url.PathEscape(identifier) + "/backups"
	var envelope struct {
		Data struct {
			Attributes json.RawMessage `json:"attributes"`
		} `json:"data"`
	}
	if err := p.request(ctx, http.MethodPost, path, body, &envelope); err != nil {
		p.mu.Lock()
		delete(p.lastBackup, identifier)
		p.mu.Unlock()
		return pterodactylBackup{}, err
	}
	var attributes struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Bytes       int64  `json:"bytes"`
		CreatedAt   string `json:"created_at"`
		CompletedAt string `json:"completed_at"`
		Successful  *bool  `json:"is_successful"`
		Locked      bool   `json:"is_locked"`
	}
	if len(envelope.Data.Attributes) > 0 {
		if err := json.Unmarshal(envelope.Data.Attributes, &attributes); err != nil {
			return pterodactylBackup{}, errors.New("invalid Pterodactyl backup response")
		}
	}
	return pterodactylBackup{
		UUID: attributes.UUID, Name: attributes.Name, Bytes: attributes.Bytes,
		CreatedAt: attributes.CreatedAt, CompletedAt: attributes.CompletedAt,
		Successful: attributes.Successful, Locked: attributes.Locked,
	}, nil
}

func (p *pterodactylClient) request(ctx context.Context, method, endpoint string, body any, output any) error {
	if !p.configured() {
		return errors.New("Pterodactyl integration is not configured")
	}
	var requestBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(data)
	}
	requestURL, err := p.baseURL.Parse(endpoint)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(endpoint, "/api/client/") {
		return errors.New("invalid Pterodactyl API path")
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), requestBody)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+p.apiKey)
	request.Header.Set("Accept", "Application/vnd.pterodactyl.v1+json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.http.Do(request)
	if err != nil {
		return fmt.Errorf("Pterodactyl API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Pterodactyl API returned HTTP %d", response.StatusCode)
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(output); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return errors.New("invalid Pterodactyl API response")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *pterodactylClient) registerRoutes(mux *http.ServeMux, auth *authManager) {
	mux.HandleFunc("/api/pterodactyl/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		panelURL := ""
		if p != nil && p.baseURL != nil {
			panelURL = p.baseURL.String()
		}
		writeJSON(w, http.StatusOK, map[string]any{"configured": p.configured(), "panelUrl": panelURL})
	})
	mux.HandleFunc("/api/pterodactyl/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		if !p.configured() {
			http.Error(w, "Pterodactyl integration is not configured", http.StatusServiceUnavailable)
			return
		}
		servers, err := p.listServers(r.Context())
		if err != nil {
			http.Error(w, "could not load authorized Pterodactyl servers", http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, servers)
	})
	mux.HandleFunc("/api/pterodactyl/servers/{identifier}/backups", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireMFA(w, r) {
			return
		}
		if !p.configured() {
			http.Error(w, "Pterodactyl integration is not configured", http.StatusServiceUnavailable)
			return
		}
		identifier := r.PathValue("identifier")
		if !serverIdentifierPattern.MatchString(identifier) {
			http.Error(w, "invalid server identifier", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			_, session, ok := auth.session(r)
			if !ok || !validCSRF(r, session.CSRF) {
				http.Error(w, "invalid request token", http.StatusForbidden)
				return
			}
			backup, err := p.createBackup(r.Context(), identifier)
			if err != nil {
				if errors.Is(err, errBackupRateLimited) {
					http.Error(w, err.Error(), http.StatusTooManyRequests)
					return
				}
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, http.StatusAccepted, backup)
			return
		}
		backups, err := p.listBackups(r.Context(), identifier)
		if err != nil {
			http.Error(w, "could not load server backups", http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, backups)
	})
}
