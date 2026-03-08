package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all server configuration.
type Config struct {
	// HTTP server
	HTTPAddr string

	// Database
	DBPath string

	// JWT secrets
	AccessSecret  string
	RefreshSecret string
	IDSecret      string

	// Token TTLs
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	IDTTL      time.Duration

	// Admin credentials
	AdminUser     string
	AdminPassword string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		HTTPAddr:      getEnv("HTTP_ADDR", ":8080"),
		DBPath:        getEnv("DB_PATH", "./data/sso.db"),
		AccessSecret:  getEnv("ACCESS_SECRET", "change-me-access-secret"),
		RefreshSecret: getEnv("REFRESH_SECRET", "change-me-refresh-secret"),
		IDSecret:      getEnv("ID_SECRET", "change-me-id-secret"),
		AccessTTL:     getDurationEnv("ACCESS_TTL_MINUTES", 15) * time.Minute,
		RefreshTTL:    getDurationEnv("REFRESH_TTL_DAYS", 30) * 24 * time.Hour,
		IDTTL:         getDurationEnv("ID_TTL_MINUTES", 15) * time.Minute,
		AdminUser:     getEnv("ADMIN_USER", "admin"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "admin"),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDurationEnv(key string, def int64) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Duration(n)
		}
	}
	return time.Duration(def)
}
