package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Andrew55529/sso_Server/internal/config"
	"github.com/Andrew55529/sso_Server/internal/database"
	"github.com/Andrew55529/sso_Server/internal/handlers"
	"github.com/Andrew55529/sso_Server/internal/tokens"
	webembed "github.com/Andrew55529/sso_Server/web/embed"
)

func main() {
	cfg := config.Load()

	// Open database.
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("close database: %v", err)
		}
	}()

	// Token manager.
	tm := tokens.NewManager(
		cfg.AccessSecret,
		cfg.RefreshSecret,
		cfg.IDSecret,
		cfg.AccessTTL,
		cfg.RefreshTTL,
		cfg.IDTTL,
	)

	// Load admin template.
	tmplFuncs := template.FuncMap{
		"prevPage": func(p int) int { return p - 1 },
		"nextPage": func(p int) int { return p + 1 },
	}
	tmpl, err := template.New("admin.html").Funcs(tmplFuncs).ParseFS(webembed.TemplateFS, "templates/admin.html")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	// Handlers.
	authH := handlers.NewAuthHandler(db, tm)
	adminH := handlers.NewAdminHandler(db, cfg.AdminUser, cfg.AdminPassword, tmpl)

	// Router.
	mux := http.NewServeMux()

	// Auth endpoints.
	requireAuth := handlers.RequireAuth(tm)
	mux.HandleFunc("/auth/register", authH.Register)
	mux.HandleFunc("/auth/login", authH.Login)
	mux.HandleFunc("/auth/refresh", authH.Refresh)
	mux.HandleFunc("/auth/logout", authH.Logout)
	mux.Handle("/auth/userinfo", requireAuth(http.HandlerFunc(authH.Userinfo)))

	// Health check.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Admin UI + JSON API.
	adminH.Register(mux, "/admin")

	// Background token pruning.
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.PruneExpiredTokens(); err != nil {
				log.Printf("prune tokens: %v", err)
			}
		}
	}()

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      handlers.CORS(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("SSO server listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-quit
	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
	log.Println("Server stopped")
}
