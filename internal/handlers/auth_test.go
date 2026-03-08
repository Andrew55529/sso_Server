package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Andrew55529/sso_Server/internal/database"
	"github.com/Andrew55529/sso_Server/internal/handlers"
	"github.com/Andrew55529/sso_Server/internal/tokens"
)

func setupTest(t *testing.T) (*handlers.AuthHandler, *tokens.Manager) {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	db, err := database.Open(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	tm := tokens.NewManager("asec", "rsec", "isec", time.Minute, time.Hour, time.Minute)
	h := handlers.NewAuthHandler(db, tm)
	return h, tm
}

func postJSON(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestRegister(t *testing.T) {
	h, _ := setupTest(t)

	tests := []struct {
		name   string
		body   map[string]string
		status int
	}{
		{"valid", map[string]string{"email": "test@example.com", "username": "testuser", "password": "Secret123"}, http.StatusCreated},
		{"duplicate", map[string]string{"email": "test@example.com", "username": "testuser", "password": "Secret123"}, http.StatusConflict},
		{"missing email", map[string]string{"username": "testuser", "password": "Secret123"}, http.StatusBadRequest},
		{"weak password", map[string]string{"email": "weak@example.com", "username": "weak", "password": "short"}, http.StatusBadRequest},
		{"invalid email", map[string]string{"email": "notanemail", "username": "x", "password": "Secret123"}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := postJSON(t, h.Register, "/auth/register", tt.body)
			if rr.Code != tt.status {
				t.Errorf("got status %d, want %d — body: %s", rr.Code, tt.status, rr.Body.String())
			}
		})
	}
}

func TestLogin(t *testing.T) {
	h, _ := setupTest(t)

	// Register first
	postJSON(t, h.Register, "/auth/register", map[string]string{
		"email": "user@example.com", "username": "user", "password": "Secret123",
	})

	t.Run("valid login", func(t *testing.T) {
		rr := postJSON(t, h.Login, "/auth/login", map[string]string{
			"email": "user@example.com", "password": "Secret123",
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
		}
		var ts tokens.TokenSet
		if err := json.NewDecoder(rr.Body).Decode(&ts); err != nil {
			t.Fatal(err)
		}
		if ts.AccessToken == "" || ts.IDToken == "" || ts.RefreshToken == "" {
			t.Error("missing tokens in response")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		rr := postJSON(t, h.Login, "/auth/login", map[string]string{
			"email": "user@example.com", "password": "wrongpass",
		})
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("unknown email", func(t *testing.T) {
		rr := postJSON(t, h.Login, "/auth/login", map[string]string{
			"email": "nobody@example.com", "password": "Secret123",
		})
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})
}

func TestRefreshAndLogout(t *testing.T) {
	h, _ := setupTest(t)

	postJSON(t, h.Register, "/auth/register", map[string]string{
		"email": "refresh@example.com", "username": "rfuser", "password": "Secret123",
	})
	loginResp := postJSON(t, h.Login, "/auth/login", map[string]string{
		"email": "refresh@example.com", "password": "Secret123",
	})
	var ts tokens.TokenSet
	json.NewDecoder(loginResp.Body).Decode(&ts)

	t.Run("valid refresh", func(t *testing.T) {
		rr := postJSON(t, h.Refresh, "/auth/refresh", map[string]string{
			"refresh_token": ts.RefreshToken,
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
		}
		var newTs tokens.TokenSet
		json.NewDecoder(rr.Body).Decode(&newTs)
		if newTs.AccessToken == "" {
			t.Error("no access token in refresh response")
		}
		// Old token should be revoked now
		rr2 := postJSON(t, h.Refresh, "/auth/refresh", map[string]string{
			"refresh_token": ts.RefreshToken,
		})
		if rr2.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 on reuse of old refresh token, got %d", rr2.Code)
		}
		ts = newTs
	})

	t.Run("logout revokes token", func(t *testing.T) {
		postJSON(t, h.Logout, "/auth/logout", map[string]string{
			"refresh_token": ts.RefreshToken,
		})
		rr := postJSON(t, h.Refresh, "/auth/refresh", map[string]string{
			"refresh_token": ts.RefreshToken,
		})
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 after logout, got %d", rr.Code)
		}
	})
}

func TestUserinfo(t *testing.T) {
	h, tm := setupTest(t)

	postJSON(t, h.Register, "/auth/register", map[string]string{
		"email": "info@example.com", "username": "infouser", "password": "Secret123",
	})
	loginResp := postJSON(t, h.Login, "/auth/login", map[string]string{
		"email": "info@example.com", "password": "Secret123",
	})
	var ts tokens.TokenSet
	json.NewDecoder(loginResp.Body).Decode(&ts)

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+ts.AccessToken)
		rr := httptest.NewRecorder()
		handlers.RequireAuth(tm)(http.HandlerFunc(h.Userinfo)).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		rr := httptest.NewRecorder()
		handlers.RequireAuth(tm)(http.HandlerFunc(h.Userinfo)).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rr := httptest.NewRecorder()
		handlers.RequireAuth(tm)(http.HandlerFunc(h.Userinfo)).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})
}
