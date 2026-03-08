package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/Andrew55529/sso_Server/internal/database"
	"github.com/Andrew55529/sso_Server/internal/tokens"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	db *database.DB
	tm *tokens.Manager
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(db *database.DB, tm *tokens.Manager) *AuthHandler {
	return &AuthHandler{db: db, tm: tm}
}

// --- register ---

type registerRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Register handles POST /auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	if err := validateRegister(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	user, err := h.db.CreateUser(req.Email, req.Username, string(hash), "user")
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         user.ID,
		"email":      user.Email,
		"username":   user.Username,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

// --- login ---

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login handles POST /auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, err := h.db.GetUserByEmail(req.Email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !user.Active {
		writeError(w, http.StatusForbidden, "account is disabled")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ts, refreshExpiry, err := h.tm.IssueTokenSet(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue tokens")
		return
	}
	if err := h.db.StoreRefreshToken(user.ID, ts.RefreshToken, refreshExpiry); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store token")
		return
	}

	writeJSON(w, http.StatusOK, ts)
}

// --- refresh ---

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh handles POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	rt, err := h.db.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	if rt.Revoked {
		writeError(w, http.StatusUnauthorized, "refresh token has been revoked")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "refresh token has expired")
		return
	}

	user, err := h.db.GetUserByID(rt.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}
	if !user.Active {
		writeError(w, http.StatusForbidden, "account is disabled")
		return
	}

	// Rotate: revoke old token, issue new set.
	if err := h.db.RevokeRefreshToken(req.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke token")
		return
	}

	ts, refreshExpiry, err := h.tm.IssueTokenSet(user.ID, user.Email, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue tokens")
		return
	}
	if err := h.db.StoreRefreshToken(user.ID, ts.RefreshToken, refreshExpiry); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store token")
		return
	}

	writeJSON(w, http.StatusOK, ts)
}

// --- logout ---

// Logout handles POST /auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.RefreshToken != "" {
		_ = h.db.RevokeRefreshToken(req.RefreshToken)
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// --- userinfo ---

// Userinfo handles GET /auth/userinfo (requires access token).
func (h *AuthHandler) Userinfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":      claims.Subject,
		"email":    claims.Email,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

// --- validation helpers ---

func validateRegister(req registerRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("invalid email address")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if len(req.Username) < 2 {
		return fmt.Errorf("username must be at least 2 characters")
	}
	if len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hasUpper := false
	hasDigit := false
	for _, ch := range req.Password {
		if unicode.IsUpper(ch) {
			hasUpper = true
		}
		if unicode.IsDigit(ch) {
			hasDigit = true
		}
	}
	if !hasUpper || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter and one digit")
	}
	return nil
}
