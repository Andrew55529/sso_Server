package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/Andrew55529/sso_Server/internal/database"
	"github.com/Andrew55529/sso_Server/internal/models"
)

// AdminHandler provides a basic admin UI and JSON API for managing users.
type AdminHandler struct {
	db           *database.DB
	adminUser    string
	adminPasswd  string
	tmpl         *template.Template
}

// NewAdminHandler creates an AdminHandler. tmpl should be the parsed admin template.
func NewAdminHandler(db *database.DB, adminUser, adminPasswd string, tmpl *template.Template) *AdminHandler {
	return &AdminHandler{
		db:          db,
		adminUser:   adminUser,
		adminPasswd: adminPasswd,
		tmpl:        tmpl,
	}
}

// basicAuth validates HTTP Basic Auth.
func (h *AdminHandler) basicAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return user == h.adminUser && pass == h.adminPasswd
}

func (h *AdminHandler) requireBasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.basicAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SSO Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Register mounts admin routes under the given mux prefix.
func (h *AdminHandler) Register(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/", h.requireBasicAuth(h.dashboard))
	mux.HandleFunc(prefix+"/users", h.requireBasicAuth(h.listUsersJSON))
	mux.HandleFunc(prefix+"/users/", h.requireBasicAuth(h.userActions))
}

// --- UI ---

type dashboardData struct {
	Users []models.User
	Total int
	Page  int
	Limit int
	Pages int
}

func (h *AdminHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 20
	offset := (page - 1) * limit

	users, total, err := h.db.ListUsers(limit, offset)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pages := total / limit
	if total%limit != 0 {
		pages++
	}

	data := dashboardData{
		Users: users,
		Total: total,
		Page:  page,
		Limit: limit,
		Pages: pages,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.Execute(w, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// --- JSON API ---

func (h *AdminHandler) listUsersJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	users, total, err := h.db.ListUsers(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *AdminHandler) userActions(w http.ResponseWriter, r *http.Request) {
	// Path: /admin/users/{id}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, id)
	case http.MethodPut, http.MethodPost:
		switch action {
		case "activate":
			h.setActive(w, r, id, true)
		case "deactivate":
			h.setActive(w, r, id, false)
		case "role":
			h.changeRole(w, r, id)
		case "revoke-tokens":
			h.revokeTokens(w, r, id)
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown action: %s", action))
		}
	case http.MethodDelete:
		h.deleteUser(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *AdminHandler) getUser(w http.ResponseWriter, _ *http.Request, id int64) {
	user, err := h.db.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *AdminHandler) setActive(w http.ResponseWriter, _ *http.Request, id int64, active bool) {
	if err := h.db.UpdateUserActive(id, active); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	if !active {
		_ = h.db.RevokeAllUserTokens(id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (h *AdminHandler) changeRole(w http.ResponseWriter, r *http.Request, id int64) {
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		writeError(w, http.StatusBadRequest, "role is required")
		return
	}
	if err := h.db.UpdateUserRole(id, body.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update role")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "role updated"})
}

func (h *AdminHandler) revokeTokens(w http.ResponseWriter, _ *http.Request, id int64) {
	if err := h.db.RevokeAllUserTokens(id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "tokens revoked"})
}

func (h *AdminHandler) deleteUser(w http.ResponseWriter, _ *http.Request, id int64) {
	if err := h.db.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "user deleted"})
}
