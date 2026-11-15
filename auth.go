package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	adminUsername      = "rsynzr"
	passwordIterations = 600_000
	sessionLifetime    = 12 * time.Hour
	loginWindow        = 15 * time.Minute
	loginBlock         = 15 * time.Minute
	maxLoginFailures   = 5
	maxAuthSessions    = 20
)

type authState struct {
	TOTPSecret     string   `json:"totpSecret"`
	RecoveryHashes []string `json:"recoveryHashes"`
}

type authSession struct {
	CSRF          string
	Expires       time.Time
	MFAVerified   bool
	PendingSecret string
}

type loginAttempt struct {
	WindowStart time.Time
	Failures    int
	BlockedTill time.Time
}

type authManager struct {
	mu             sync.Mutex
	passwordSalt   []byte
	passwordHash   []byte
	totpSecret     string
	recoveryHashes []string
	sessions       map[string]*authSession
	attempts       map[string]loginAttempt
	statePath      string
}

func newAuthManager(password, dataDir string) (*authManager, error) {
	if len(password) < 14 {
		return nil, errors.New("CHRONOA_ADMIN_PASSWORD must contain at least 14 characters; use a new password")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	passwordHash, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return nil, err
	}
	manager := &authManager{
		passwordSalt: salt,
		passwordHash: passwordHash,
		sessions:     make(map[string]*authSession),
		attempts:     make(map[string]loginAttempt),
		statePath:    filepath.Join(dataDir, "auth.json"),
	}
	data, err := os.ReadFile(manager.statePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		info, statErr := os.Stat(manager.statePath)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("auth state file permissions must be 0600")
		}
		var state authState
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("decode auth state: %w", err)
		}
		manager.totpSecret = state.TOTPSecret
		manager.recoveryHashes = state.RecoveryHashes
	}
	return manager, nil
}

func (a *authManager) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, session, ok := a.session(r)
	a.mu.Lock()
	mfaEnabled := a.totpSecret != ""
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": ok,
		"setupRequired": ok && !mfaEnabled,
		"mfaEnabled":    mfaEnabled,
		"username":      adminUsername,
		"csrf":          session.CSRF,
	})
}

func (a *authManager) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !validOrigin(r) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	ip := clientIP(r)
	if a.isBlocked(ip) {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}
	derived, err := pbkdf2.Key(sha256.New, input.Password, a.passwordSalt, passwordIterations, 32)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(input.Username), []byte(adminUsername)) == 1
	passwordOK := subtle.ConstantTimeCompare(derived, a.passwordHash) == 1
	a.mu.Lock()
	totpSecret := a.totpSecret
	a.mu.Unlock()
	if !usernameOK || !passwordOK {
		a.recordFailure(ip)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if totpSecret != "" && !verifyTOTP(totpSecret, input.Code, time.Now()) {
		if !a.consumeRecoveryCode(input.Code) {
			a.recordFailure(ip)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
	}
	a.clearFailures(ip)
	csrf, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	sessionToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.pruneSessionsLocked(time.Now())
	if len(a.sessions) >= maxAuthSessions {
		a.mu.Unlock()
		http.Error(w, "too many active sessions", http.StatusTooManyRequests)
		return
	}
	a.sessions[sessionToken] = &authSession{CSRF: csrf, Expires: time.Now().Add(sessionLifetime), MFAVerified: totpSecret != ""}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "__Host-chronoa", Value: sessionToken, Path: "/", Expires: time.Now().Add(sessionLifetime), MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	a.mu.Lock()
	mfaEnabled := a.totpSecret != ""
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "setupRequired": !mfaEnabled, "mfaEnabled": mfaEnabled, "username": adminUsername, "csrf": csrf})
}

func (a *authManager) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, session, ok := a.session(r)
	if !ok || !validCSRF(r, session.CSRF) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "__Host-chronoa", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *authManager) startTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, session, ok := a.session(r)
	if !ok || session.MFAVerified || !validCSRF(r, session.CSRF) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		http.Error(w, "could not create TOTP secret", http.StatusInternalServerError)
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	label := url.QueryEscape("Chronoa:" + adminUsername)
	issuer := url.QueryEscape("Chronoa")
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuer)
	a.mu.Lock()
	if active := a.sessions[token]; active != nil {
		active.PendingSecret = secret
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
}

func (a *authManager) verifyTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, session, ok := a.session(r)
	if !ok || session.MFAVerified || session.PendingSecret == "" || !validCSRF(r, session.CSRF) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil || !verifyTOTP(session.PendingSecret, input.Code, time.Now()) {
		http.Error(w, "invalid authenticator code", http.StatusBadRequest)
		return
	}
	codes, hashes, err := makeRecoveryCodes(10)
	if err != nil {
		http.Error(w, "could not create recovery codes", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	if err := a.saveStateLocked(session.PendingSecret, hashes); err != nil {
		a.mu.Unlock()
		http.Error(w, "could not save TOTP configuration", http.StatusInternalServerError)
		return
	}
	a.totpSecret = session.PendingSecret
	a.recoveryHashes = hashes
	if active := a.sessions[token]; active != nil {
		active.PendingSecret = ""
		active.MFAVerified = true
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recoveryCodes": codes})
}

func (a *authManager) requireMFA(w http.ResponseWriter, r *http.Request) bool {
	_, session, ok := a.session(r)
	if !ok || !session.MFAVerified {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *authManager) session(r *http.Request) (string, authSession, bool) {
	cookie, err := r.Cookie("__Host-chronoa")
	if err != nil {
		return "", authSession{}, false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	session := a.sessions[cookie.Value]
	if session == nil || !now.Before(session.Expires) {
		delete(a.sessions, cookie.Value)
		return "", authSession{}, false
	}
	return cookie.Value, *session, true
}

func (a *authManager) isBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.attempts[ip]
	return time.Now().Before(attempt.BlockedTill)
}

func (a *authManager) recordFailure(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	attempt := a.attempts[ip]
	if now.Sub(attempt.WindowStart) > loginWindow {
		attempt = loginAttempt{WindowStart: now}
	}
	attempt.Failures++
	if attempt.Failures >= maxLoginFailures {
		attempt.BlockedTill = now.Add(loginBlock)
	}
	a.attempts[ip] = attempt
	if len(a.attempts) > 1024 {
		for address, existing := range a.attempts {
			if now.Sub(existing.WindowStart) > loginWindow && now.After(existing.BlockedTill) {
				delete(a.attempts, address)
			}
		}
	}
}

func (a *authManager) clearFailures(ip string) {
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

func (a *authManager) pruneSessionsLocked(now time.Time) {
	for token, session := range a.sessions {
		if !now.Before(session.Expires) {
			delete(a.sessions, token)
		}
	}
}

func (a *authManager) consumeRecoveryCode(code string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if normalized == "" {
		return false
	}
	digest := sha256.Sum256([]byte(normalized))
	encoded := hex.EncodeToString(digest[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, stored := range a.recoveryHashes {
		if subtle.ConstantTimeCompare([]byte(encoded), []byte(stored)) != 1 {
			continue
		}
		next := append([]string(nil), a.recoveryHashes[:i]...)
		next = append(next, a.recoveryHashes[i+1:]...)
		if err := a.saveStateLocked(a.totpSecret, next); err != nil {
			return false
		}
		a.recoveryHashes = next
		return true
	}
	return false
}

func (a *authManager) saveStateLocked(secret string, recoveryHashes []string) error {
	data, err := json.Marshal(authState{TOTPSecret: secret, RecoveryHashes: recoveryHashes})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(a.statePath), ".auth-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, a.statePath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(a.statePath))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	current := now.Unix() / 30
	for drift := int64(-1); drift <= 1; drift++ {
		if current+drift < 0 {
			continue
		}
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(current+drift))
		mac := hmac.New(sha1.New, secretBytes)
		_, _ = mac.Write(counter[:])
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
		expected := fmt.Sprintf("%06d", value%1_000_000)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCode(secret string, now time.Time) string {
	secretBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, secretBytes)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func makeRecoveryCodes(count int) ([]string, []string, error) {
	codes := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		buffer := make([]byte, 6)
		if _, err := rand.Read(buffer); err != nil {
			return nil, nil, err
		}
		encoded := strings.ToUpper(hex.EncodeToString(buffer))
		code := encoded[:6] + "-" + encoded[6:]
		digest := sha256.Sum256([]byte(encoded))
		codes = append(codes, code)
		hashes = append(hashes, hex.EncodeToString(digest[:]))
	}
	return codes, hashes, nil
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func validCSRF(r *http.Request, expected string) bool {
	provided := r.Header.Get("X-CSRF-Token")
	if expected == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return false
	}
	return validOrigin(r)
}

func validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host != r.Host {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())
}

func clientIP(r *http.Request) string {
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return address
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
