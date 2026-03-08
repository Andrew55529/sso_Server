package handlers

import (
	"html/template"
	"net/http"
)

// DemoHandler serves the browser-testable playground page.
type DemoHandler struct {
	tmpl *template.Template
}

// NewDemoHandler creates a DemoHandler.
func NewDemoHandler(tmpl *template.Template) *DemoHandler {
	return &DemoHandler{tmpl: tmpl}
}

// ServeHTTP handles GET /demo.
func (h *DemoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.Execute(w, nil); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
