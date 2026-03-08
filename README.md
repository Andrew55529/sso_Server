# sso_Server

A lightweight **Single Sign-On (SSO) server** written in Go.  
Issues `access_token`, `id_token` and `refresh_token` (JWT / opaque), stores everything in **SQLite**, and ships a **basic admin panel** out of the box.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Token issuance** | `access_token` & `id_token` (HS256 JWT), `refresh_token` (opaque, stored hashed) |
| **Token rotation** | Every `/auth/refresh` call issues a new token set and revokes the old refresh token |
| **User registration** | `POST /auth/register` with email, username, and a strong password |
| **Admin panel** | Browser UI at `/admin/` (HTTP Basic Auth) — list, activate/deactivate, change role, revoke tokens, delete |
| **Admin JSON API** | Full CRUD REST under `/admin/users/` |
| **SQLite** | Single-file database, zero infrastructure dependencies |
| **Docker-compose** | One command deployment |
| **Graceful shutdown** | SIGINT / SIGTERM handled correctly |

---

## 🚀 Quick Start

### With Docker Compose (recommended)

```bash
# 1. Clone and enter the directory
git clone https://github.com/Andrew55529/sso_Server.git
cd sso_Server

# 2. Copy and edit env (optional — defaults are fine for local testing)
cp .env.example .env

# 3. Start
docker compose up --build -d

# 4. Check health
curl http://localhost:8080/health
```

### Local development

```bash
go build -o sso-server ./cmd/server
DB_PATH=./data/sso.db ./sso-server
```

---

## 🔐 Auth Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Login — returns `access_token`, `id_token`, `refresh_token` |
| `POST` | `/auth/refresh` | Rotate tokens using a valid `refresh_token` |
| `POST` | `/auth/logout` | Revoke a `refresh_token` |
| `GET` | `/auth/userinfo` | Get current user info (requires `Authorization: Bearer <access_token>`) |
| `GET` | `/health` | Health check |

### Register

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","username":"alice","password":"Secret123"}'
```

Password rules: minimum 8 characters, at least one uppercase letter and one digit.

### Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Secret123"}'
```

Response:

```json
{
  "access_token": "eyJ...",
  "id_token":     "eyJ...",
  "refresh_token": "ecba9a81...",
  "token_type":   "Bearer",
  "expires_in":   900
}
```

### Refresh

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"ecba9a81..."}'
```

### Userinfo

```bash
curl http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer eyJ..."
```

---

## 🛡️ Admin Panel

Open **http://localhost:8080/admin/** in your browser.  
Default credentials: `admin` / `admin` (change via `ADMIN_USER` / `ADMIN_PASSWORD`).

### Admin JSON API (Basic Auth)

```bash
# List users
curl -u admin:admin http://localhost:8080/admin/users?page=1&limit=20

# Deactivate a user
curl -u admin:admin -X POST http://localhost:8080/admin/users/1/deactivate

# Change role
curl -u admin:admin -X PUT http://localhost:8080/admin/users/1/role \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# Revoke all tokens
curl -u admin:admin -X POST http://localhost:8080/admin/users/1/revoke-tokens

# Delete user
curl -u admin:admin -X DELETE http://localhost:8080/admin/users/1
```

See `examples/requests.http` for the full set of ready-to-run HTTP requests (compatible with VS Code REST Client and JetBrains HTTP Client).

---

## ⚙️ Configuration

All options are set via **environment variables** (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `HTTP_ADDR` | `:8080` | Listen address |
| `DB_PATH` | `./data/sso.db` | SQLite file path |
| `ACCESS_SECRET` | `change-me-access-secret` | HMAC secret for access tokens |
| `REFRESH_SECRET` | `change-me-refresh-secret` | HMAC secret for refresh tokens |
| `ID_SECRET` | `change-me-id-secret` | HMAC secret for id tokens |
| `ACCESS_TTL_MINUTES` | `15` | Access / id token lifetime (minutes) |
| `REFRESH_TTL_DAYS` | `30` | Refresh token lifetime (days) |
| `ADMIN_USER` | `admin` | Admin panel username |
| `ADMIN_PASSWORD` | `admin` | Admin panel password |

> ⚠️ **Change all secrets before deploying to production!**

---

## 🧪 Running Tests

```bash
CGO_ENABLED=1 go test ./...
```

### Smoke test (requires a running server)

```bash
BASE=http://localhost:8080 bash examples/test.sh
```

---

## 📁 Project Structure

```
.
├── cmd/server/         # Main entry point
├── internal/
│   ├── config/         # Configuration (env vars)
│   ├── database/       # SQLite data layer
│   ├── handlers/       # HTTP handlers & middleware
│   ├── models/         # Domain models
│   └── tokens/         # JWT & opaque token management
├── web/embed/
│   └── templates/      # Admin UI (HTML)
├── examples/
│   ├── requests.http   # HTTP Client examples
│   └── test.sh         # curl-based smoke test
├── Dockerfile
├── docker-compose.yml
└── .env.example
```
