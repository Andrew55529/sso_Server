// Package main is a self-contained example application that uses the SSO server
// for authentication. It demonstrates how a third-party service can rely on the
// SSO to register/login users and then validate their identity via the
// /auth/userinfo endpoint.
//
// Usage:
//
//	SSO_URL=http://localhost:8080 go run ./examples/demo_server
//
// Then open http://localhost:8081 in your browser.
package main

import (
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─── config ──────────────────────────────────────────────────────────────────

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	ssoURL      = getenv("SSO_URL", "http://localhost:8080")
	httpAddr    = getenv("HTTP_ADDR", ":8081")
	// cookieSecure should be set to true when the server runs behind HTTPS.
	// Defaults to false so the demo works out-of-the-box over plain HTTP.
	cookieSecure = os.Getenv("COOKIE_SECURE") == "true"
)

const tokenCookie = "sso_access_token"

// ─── main ────────────────────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/protected", protectedHandler)
	mux.HandleFunc("/logout", logoutHandler)

	log.Printf("Example server listening on %s  (SSO: %s)", httpAddr, ssoURL)
	log.Printf("Open http://localhost%s in your browser", httpAddr)
	if err := http.ListenAndServe(httpAddr, mux); err != nil {
		log.Fatal(err)
	}
}

// ─── handlers ────────────────────────────────────────────────────────────────

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	token := getTokenFromCookie(r)
	render(w, homeTmpl, map[string]any{
		"LoggedIn": token != "",
		"SSOUrl":   ssoURL,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, loginTmpl, map[string]any{"Error": ""})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	payload, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := httpPost(ssoURL+"/auth/login", payload)
	if err != nil {
		render(w, loginTmpl, map[string]any{"Error": "Cannot reach SSO server: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusOK {
		errMsg := "Login failed"
		if e, ok := result["error"].(string); ok {
			errMsg = e
		}
		render(w, loginTmpl, map[string]any{"Error": errMsg})
		return
	}

	accessToken, _ := result["access_token"].(string)
	setTokenCookie(w, accessToken)
	http.Redirect(w, r, "/protected", http.StatusSeeOther)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, registerTmpl, map[string]any{"Error": "", "Success": ""})
		return
	}

	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")

	payload, _ := json.Marshal(map[string]string{
		"email":    email,
		"username": username,
		"password": password,
	})
	resp, err := httpPost(ssoURL+"/auth/register", payload)
	if err != nil {
		render(w, registerTmpl, map[string]any{
			"Error":   "Cannot reach SSO server: " + err.Error(),
			"Success": "",
		})
		return
	}
	defer resp.Body.Close()

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusCreated {
		errMsg := "Registration failed"
		if e, ok := result["error"].(string); ok {
			errMsg = e
		}
		render(w, registerTmpl, map[string]any{"Error": errMsg, "Success": ""})
		return
	}

	render(w, registerTmpl, map[string]any{
		"Error":   "",
		"Success": "Account created! You can now log in.",
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromCookie(r)
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Validate token by calling SSO /auth/userinfo
	req, _ := http.NewRequest(http.MethodGet, ssoURL+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		// Token invalid or SSO unreachable — clear cookie and redirect
		clearTokenCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&userInfo)

	render(w, protectedTmpl, map[string]any{
		"UserInfo": userInfo,
		"SSOUrl":   ssoURL,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearTokenCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func httpPost(url string, body []byte) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return client.Post(url, "application/json", strings.NewReader(string(body)))
}

func getTokenFromCookie(r *http.Request) string {
	c, err := r.Cookie(tokenCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure,
	})
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// ─── HTML templates ───────────────────────────────────────────────────────────

var baseStyle = `
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
    margin: 0;
    padding: 0;
    min-height: 100vh;
  }
  nav {
    background: #1e40af;
    color: #fff;
    padding: .8rem 2rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }
  nav .brand { font-weight: 700; font-size: 1.1rem; text-decoration: none; color: #fff; }
  nav a { color: #bfdbfe; text-decoration: none; font-size: .9rem; }
  nav a:hover { color: #fff; }
  nav .spacer { flex: 1; }
  .container { max-width: 480px; margin: 3rem auto; padding: 0 1rem; }
  .card {
    background: #fff;
    border-radius: 10px;
    padding: 2rem;
    box-shadow: 0 1px 4px rgba(0,0,0,.12);
  }
  h2 { margin: 0 0 1.5rem; font-size: 1.3rem; color: #1e40af; }
  label { display: block; font-size: .85rem; color: #475569; margin-bottom: .25rem; }
  input[type="text"], input[type="email"], input[type="password"] {
    width: 100%;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: .55rem .75rem;
    font-size: .9rem;
    margin-bottom: 1rem;
    transition: border-color .15s;
  }
  input:focus { outline: none; border-color: #1e40af; }
  .btn {
    display: inline-block;
    border: none;
    border-radius: 6px;
    padding: .6rem 1.3rem;
    cursor: pointer;
    font-size: .9rem;
    font-weight: 600;
    text-decoration: none;
    transition: opacity .15s;
  }
  .btn:hover { opacity: .85; }
  .btn-primary { background: #1e40af; color: #fff; }
  .btn-green   { background: #16a34a; color: #fff; }
  .btn-red     { background: #ef4444; color: #fff; }
  .btn-outline { background: #fff; color: #1e40af; border: 1.5px solid #1e40af; }
  .alert {
    padding: .7rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
    font-size: .9rem;
  }
  .alert-error   { background: #fee2e2; color: #991b1b; }
  .alert-success { background: #dcfce7; color: #166534; }
  .link-row { margin-top: 1rem; font-size: .85rem; color: #64748b; }
  .link-row a { color: #1e40af; }
  table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  th { text-align: left; font-size: .78rem; text-transform: uppercase; color: #64748b; padding: .4rem 0; border-bottom: 1px solid #e2e8f0; }
  td { padding: .5rem 0; font-size: .9rem; vertical-align: top; word-break: break-all; }
  .key { color: #64748b; font-weight: 600; width: 100px; font-size: .8rem; }
  .badge {
    display: inline-block;
    padding: .2rem .6rem;
    border-radius: 999px;
    font-size: .75rem;
    font-weight: 600;
  }
  .badge-admin { background: #fef3c7; color: #92400e; }
  .badge-user  { background: #e0e7ff; color: #3730a3; }
</style>
`

var homeTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Example App</title>` + baseStyle + `</head>
<body>
<nav>
  <a class="brand" href="/">🏠 Example App</a>
  <a href="/protected">Protected Page</a>
  <span class="spacer"></span>
  {{if .LoggedIn}}
    <a href="/logout" style="color:#fca5a5">Logout</a>
  {{else}}
    <a href="/login">Login</a>
    <a href="/register">Register</a>
  {{end}}
</nav>
<div class="container">
  <div class="card">
    <h2>Welcome to the Example App</h2>
    <p>This is a simple example server that delegates authentication to the
    <strong>SSO server</strong> running at <code>{{.SSOUrl}}</code>.</p>

    {{if .LoggedIn}}
      <p>✅ You are <strong>logged in</strong>.</p>
      <a class="btn btn-primary" href="/protected">Go to Protected Page →</a>
      &nbsp;
      <a class="btn btn-outline" href="/logout">Logout</a>
    {{else}}
      <p>You are <strong>not logged in</strong>. Use the buttons below to authenticate via SSO.</p>
      <div style="display:flex;gap:.8rem;flex-wrap:wrap">
        <a class="btn btn-primary" href="/login">Login</a>
        <a class="btn btn-green" href="/register">Register</a>
      </div>
    {{end}}

    <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0"/>
    <p style="font-size:.85rem;color:#64748b">
      💡 Try the SSO Playground at <a href="{{.SSOUrl}}/demo" target="_blank">{{.SSOUrl}}/demo</a>
      to see raw tokens and API responses.
    </p>
  </div>
</div>
</body>
</html>`))

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Login — Example App</title>` + baseStyle + `</head>
<body>
<nav>
  <a class="brand" href="/">🏠 Example App</a>
  <span class="spacer"></span>
  <a href="/register">Register</a>
</nav>
<div class="container">
  <div class="card">
    <h2>🔑 Login</h2>
    {{if .Error}}<div class="alert alert-error">{{.Error}}</div>{{end}}
    <form method="POST" action="/login">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" placeholder="user@example.com" required autofocus />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="Password" required />
      <button class="btn btn-primary" type="submit" style="width:100%">Login</button>
    </form>
    <div class="link-row">Don't have an account? <a href="/register">Register</a></div>
  </div>
</div>
</body>
</html>`))

var registerTmpl = template.Must(template.New("register").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Register — Example App</title>` + baseStyle + `</head>
<body>
<nav>
  <a class="brand" href="/">🏠 Example App</a>
  <span class="spacer"></span>
  <a href="/login">Login</a>
</nav>
<div class="container">
  <div class="card">
    <h2>📝 Register</h2>
    {{if .Error}}<div class="alert alert-error">{{.Error}}</div>{{end}}
    {{if .Success}}<div class="alert alert-success">{{.Success}} <a href="/login">Log in →</a></div>{{end}}
    <form method="POST" action="/register">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" placeholder="user@example.com" required autofocus />
      <label for="username">Username</label>
      <input id="username" name="username" type="text" placeholder="johndoe" required />
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             placeholder="Min 8 chars, 1 uppercase, 1 digit" required />
      <button class="btn btn-green" type="submit" style="width:100%">Create Account</button>
    </form>
    <div class="link-row">Already have an account? <a href="/login">Login</a></div>
  </div>
</div>
</body>
</html>`))

var protectedTmpl = template.Must(template.New("protected").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Protected — Example App</title>` + baseStyle + `</head>
<body>
<nav>
  <a class="brand" href="/">🏠 Example App</a>
  <span class="spacer"></span>
  <a href="/logout" style="color:#fca5a5">Logout</a>
</nav>
<div class="container">
  <div class="card">
    <h2>🔒 Protected Page</h2>
    <p>✅ You are authenticated! The SSO server confirmed your identity.</p>

    <table>
      <thead>
        <tr><th>Field</th><th>Value</th></tr>
      </thead>
      <tbody>
        {{range $k, $v := .UserInfo}}
        <tr>
          <td class="key">{{$k}}</td>
          <td>
            {{if eq $k "role"}}
              <span class="badge {{if eq $v "admin"}}badge-admin{{else}}badge-user{{end}}">{{$v}}</span>
            {{else}}
              {{$v}}
            {{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>

    <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0"/>
    <p style="font-size:.85rem;color:#64748b">
      This page is protected: if you are not logged in, you get redirected to
      <code>/login</code>. The access token is stored in an <code>HttpOnly</code>
      cookie and validated on every request by calling the SSO
      <code>/auth/userinfo</code> endpoint.
    </p>
    <a class="btn btn-red" href="/logout">Logout</a>
  </div>
</div>
</body>
</html>`))
