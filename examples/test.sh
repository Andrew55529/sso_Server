#!/usr/bin/env bash
# examples/test.sh — Quick smoke-test of the SSO server.
# Usage: BASE=http://localhost:8080 bash examples/test.sh

set -euo pipefail

BASE="${BASE:-http://localhost:8080}"
EMAIL="testuser_$(date +%s)@example.com"
PASSWORD="Secret123"
USERNAME="testuser"

sep() { printf '\n\e[1;36m=== %s ===\e[0m\n' "$1"; }

# ── Health ────────────────────────────────────────────────────────────────
sep "Health"
curl -sf "$BASE/health" | jq .

# ── Register ─────────────────────────────────────────────────────────────
sep "Register"
curl -sf -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" | jq .

# ── Login ─────────────────────────────────────────────────────────────────
sep "Login"
TOKENS=$(curl -sf -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$TOKENS" | jq .

ACCESS_TOKEN=$(echo "$TOKENS"  | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r '.refresh_token')

# ── Userinfo ──────────────────────────────────────────────────────────────
sep "Userinfo"
curl -sf "$BASE/auth/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# ── Refresh ───────────────────────────────────────────────────────────────
sep "Refresh"
NEW_TOKENS=$(curl -sf -X POST "$BASE/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
echo "$NEW_TOKENS" | jq .
REFRESH_TOKEN=$(echo "$NEW_TOKENS" | jq -r '.refresh_token')

# ── Admin list users ──────────────────────────────────────────────────────
sep "Admin — list users"
curl -sf -u admin:admin "$BASE/admin/users" | jq .

# ── Logout ────────────────────────────────────────────────────────────────
sep "Logout"
curl -sf -X POST "$BASE/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}" | jq .

# Verify refresh is rejected after logout
sep "Refresh after logout (should fail with 401)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
echo "HTTP status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "401" ]]; then
  echo "✅ Correctly rejected"
else
  echo "❌ Unexpected status" && exit 1
fi

echo ""
echo "✅ All checks passed!"
