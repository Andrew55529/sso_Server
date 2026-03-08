// Package webembed provides embedded web assets.
package webembed

import "embed"

//go:embed templates/*.html
var TemplateFS embed.FS
