package tokens

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the standard JWT payload for access and id tokens.
type Claims struct {
	jwt.RegisteredClaims
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role,omitempty"`
	TokenUse string `json:"token_use"` // "access" | "id"
}

// TokenSet holds the three tokens returned after successful auth.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// Manager handles token creation and validation.
type Manager struct {
	accessSecret  []byte
	refreshSecret []byte
	idSecret      []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	idTTL         time.Duration
}

// NewManager creates a Manager with the provided secrets and TTLs.
func NewManager(accessSecret, refreshSecret, idSecret string, accessTTL, refreshTTL, idTTL time.Duration) *Manager {
	return &Manager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		idSecret:      []byte(idSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		idTTL:         idTTL,
	}
}

// IssueTokenSet creates access, id and refresh tokens for a user.
func (m *Manager) IssueTokenSet(userID int64, email, username, role string) (TokenSet, time.Time, error) {
	now := time.Now()

	accessToken, err := m.issueJWT(userID, email, username, role, "access", now, m.accessTTL, m.accessSecret)
	if err != nil {
		return TokenSet{}, time.Time{}, fmt.Errorf("access token: %w", err)
	}

	idToken, err := m.issueJWT(userID, email, username, role, "id", now, m.idTTL, m.idSecret)
	if err != nil {
		return TokenSet{}, time.Time{}, fmt.Errorf("id token: %w", err)
	}

	rawRefresh, err := generateOpaqueToken()
	if err != nil {
		return TokenSet{}, time.Time{}, fmt.Errorf("refresh token: %w", err)
	}
	refreshExpiry := now.Add(m.refreshTTL)

	return TokenSet{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.accessTTL.Seconds()),
	}, refreshExpiry, nil
}

// ValidateAccessToken parses and validates an access token, returning its claims.
func (m *Manager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	return m.parseJWT(tokenStr, m.accessSecret)
}

// ValidateIDToken parses and validates an id token.
func (m *Manager) ValidateIDToken(tokenStr string) (*Claims, error) {
	return m.parseJWT(tokenStr, m.idSecret)
}

// RefreshTTL returns the configured refresh token TTL.
func (m *Manager) RefreshTTL() time.Duration { return m.refreshTTL }

func (m *Manager) issueJWT(userID int64, email, username, role, use string, now time.Time, ttl time.Duration, secret []byte) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
		Email:    email,
		Username: username,
		Role:     role,
		TokenUse: use,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func (m *Manager) parseJWT(tokenStr string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// generateOpaqueToken produces a cryptographically random hex string.
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
