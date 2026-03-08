package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/Andrew55529/sso_Server/internal/models"
)

// DB wraps a SQLite connection.
type DB struct {
	conn *sql.DB
}

// Open creates or opens the SQLite database at dbPath.
func Open(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes the underlying connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			email         TEXT    NOT NULL UNIQUE,
			username      TEXT    NOT NULL,
			password_hash TEXT    NOT NULL,
			role          TEXT    NOT NULL DEFAULT 'user',
			active        INTEGER NOT NULL DEFAULT 1,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT    NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked    INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
		CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
	`)
	return err
}

// --- User operations ---

// CreateUser inserts a new user and returns it.
func (db *DB) CreateUser(email, username, passwordHash, role string) (*models.User, error) {
	now := time.Now().UTC()
	res, err := db.conn.Exec(
		`INSERT INTO users(email, username, password_hash, role, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
		email, username, passwordHash, role, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.User{
		ID:           id,
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// GetUserByEmail returns a user by email.
func (db *DB) GetUserByEmail(email string) (*models.User, error) {
	row := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, role, active, created_at, updated_at FROM users WHERE email = ?`,
		email,
	)
	return scanUser(row)
}

// GetUserByID returns a user by id.
func (db *DB) GetUserByID(id int64) (*models.User, error) {
	row := db.conn.QueryRow(
		`SELECT id, email, username, password_hash, role, active, created_at, updated_at FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

// ListUsers returns all users.
func (db *DB) ListUsers(limit, offset int) ([]models.User, int, error) {
	var total int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.conn.Query(
		`SELECT id, email, username, password_hash, role, active, created_at, updated_at FROM users ORDER BY id LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, *u)
	}
	return users, total, rows.Err()
}

// UpdateUserActive sets the active flag for a user.
func (db *DB) UpdateUserActive(id int64, active bool) error {
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := db.conn.Exec(
		`UPDATE users SET active=?, updated_at=? WHERE id=?`,
		activeInt, time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	return err
}

// UpdateUserRole updates the role of a user.
func (db *DB) UpdateUserRole(id int64, role string) error {
	_, err := db.conn.Exec(
		`UPDATE users SET role=?, updated_at=? WHERE id=?`,
		role, time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	return err
}

// DeleteUser permanently deletes a user and their tokens.
func (db *DB) DeleteUser(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// --- Refresh token operations ---

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// StoreRefreshToken hashes and stores a refresh token.
func (db *DB) StoreRefreshToken(userID int64, rawToken string, expiresAt time.Time) error {
	hash := hashToken(rawToken)
	_, err := db.conn.Exec(
		`INSERT INTO refresh_tokens(user_id, token_hash, expires_at, created_at) VALUES(?,?,?,?)`,
		userID, hash, expiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// ValidateRefreshToken looks up a refresh token by its hash and checks validity.
func (db *DB) ValidateRefreshToken(rawToken string) (*models.RefreshToken, error) {
	hash := hashToken(rawToken)
	row := db.conn.QueryRow(
		`SELECT id, user_id, token_hash, expires_at, created_at, revoked FROM refresh_tokens WHERE token_hash=?`,
		hash,
	)
	var rt models.RefreshToken
	var expiresAt, createdAt string
	var revoked int
	if err := row.Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &expiresAt, &createdAt, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, err
	}
	rt.ExpiresAt = parseTime(expiresAt)
	rt.CreatedAt = parseTime(createdAt)
	rt.Revoked = revoked == 1
	return &rt, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (db *DB) RevokeRefreshToken(rawToken string) error {
	hash := hashToken(rawToken)
	_, err := db.conn.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?`, hash)
	return err
}

// RevokeAllUserTokens revokes every refresh token belonging to a user.
func (db *DB) RevokeAllUserTokens(userID int64) error {
	_, err := db.conn.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE user_id=?`, userID)
	return err
}

// PruneExpiredTokens removes tokens that have expired more than a day ago.
func (db *DB) PruneExpiredTokens() error {
	_, err := db.conn.Exec(`DELETE FROM refresh_tokens WHERE expires_at < datetime('now', '-1 day')`)
	return err
}

// --- helpers ---

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(s scanner) (*models.User, error) {
	var u models.User
	var createdAt, updatedAt string
	var active int
	err := s.Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.Role, &active, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	u.Active = active == 1
	u.CreatedAt = parseTime(createdAt)
	u.UpdatedAt = parseTime(updatedAt)
	return &u, nil
}

// parseTime attempts to parse a datetime string stored by SQLite.
// It tries RFC3339Nano first (our preferred format), then falls back to
// the default SQLite CURRENT_TIMESTAMP format ("2006-01-02 15:04:05").
func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	t, _ := time.Parse("2006-01-02 15:04:05", s)
	return t
}
