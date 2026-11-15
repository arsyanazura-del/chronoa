package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	directory := t.TempDir()
	manager, err := newAuthManager("replacement-test-password-2026", directory)
	if err != nil {
		t.Fatal(err)
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"username":"rsynzr","password":"replacement-test-password-2026"}`))
	loginRequest.Host = "chronoa.test"
	loginRequest.Header.Set("Origin", "https://chronoa.test")
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.RemoteAddr = "192.0.2.10:1234"
	loginResponse := httptest.NewRecorder()
	manager.login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", loginResponse.Code, loginResponse.Body.String())
	}
	var loginResult struct {
		CSRF          string `json:"csrf"`
		SetupRequired bool   `json:"setupRequired"`
	}
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &loginResult); err != nil {
		t.Fatal(err)
	}
	if !loginResult.SetupRequired || loginResult.CSRF == "" {
		t.Fatalf("login should require TOTP enrollment: %+v", loginResult)
	}
	cookie := loginResponse.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie has weak settings: %+v", cookie)
	}

	startRequest := httptest.NewRequest(http.MethodPost, "/api/auth/totp/start", nil)
	startRequest.Host = "chronoa.test"
	startRequest.Header.Set("Origin", "https://chronoa.test")
	startRequest.Header.Set("X-CSRF-Token", loginResult.CSRF)
	startRequest.AddCookie(cookie)
	startResponse := httptest.NewRecorder()
	manager.startTOTP(startResponse, startRequest)
	if startResponse.Code != http.StatusOK {
		t.Fatalf("TOTP start status = %d: %s", startResponse.Code, startResponse.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(startResponse.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}

	code := totpCode(setup.Secret, time.Now())
	verifyBody, _ := json.Marshal(map[string]string{"code": code})
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/auth/totp/verify", bytes.NewReader(verifyBody))
	verifyRequest.Host = "chronoa.test"
	verifyRequest.Header.Set("Origin", "https://chronoa.test")
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyRequest.Header.Set("X-CSRF-Token", loginResult.CSRF)
	verifyRequest.AddCookie(cookie)
	verifyResponse := httptest.NewRecorder()
	manager.verifyTOTPSetup(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("TOTP verify status = %d: %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	var verified struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(verifyResponse.Body.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if len(verified.RecoveryCodes) != 10 {
		t.Fatalf("recovery code count = %d, want 10", len(verified.RecoveryCodes))
	}
	info, err := os.Stat(filepath.Join(directory, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("auth state permissions = %o, want 600", info.Mode().Perm())
	}

	reloaded, err := newAuthManager("replacement-test-password-2026", directory)
	if err != nil {
		t.Fatal(err)
	}
	secondLoginBody, _ := json.Marshal(map[string]string{
		"username": "rsynzr", "password": "replacement-test-password-2026", "code": totpCode(setup.Secret, time.Now()),
	})
	secondLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(secondLoginBody))
	secondLogin.Host = "chronoa.test"
	secondLogin.Header.Set("Origin", "https://chronoa.test")
	secondLogin.Header.Set("Content-Type", "application/json")
	secondLogin.RemoteAddr = "192.0.2.11:1234"
	secondResponse := httptest.NewRecorder()
	reloaded.login(secondResponse, secondLogin)
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("MFA login status = %d: %s", secondResponse.Code, secondResponse.Body.String())
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	manager, err := newAuthManager("replacement-test-password-2026", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codes, hashes, err := makeRecoveryCodes(2)
	if err != nil {
		t.Fatal(err)
	}
	manager.recoveryHashes = hashes
	if !manager.consumeRecoveryCode(codes[0]) {
		t.Fatal("first recovery code should be accepted")
	}
	if manager.consumeRecoveryCode(codes[0]) {
		t.Fatal("recovery code should not be reusable")
	}
}

func TestVerifyTOTPRejectsInvalidCode(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0)
	if !verifyTOTP(secret, totpCode(secret, now), now) {
		t.Fatal("valid code was rejected")
	}
	if verifyTOTP(secret, "000000", now) && totpCode(secret, now) != "000000" {
		t.Fatal("invalid code was accepted")
	}
}

func TestLoginRejectsCrossOriginRequest(t *testing.T) {
	manager, err := newAuthManager("replacement-test-password-2026", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"username":"rsynzr","password":"replacement-test-password-2026"}`))
	request.Host = "chronoa.test"
	request.Header.Set("Origin", "https://attacker.test")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	manager.login(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d, want 403", response.Code)
	}
}
