#!/usr/bin/env bash
# Walks through the API with curl: authentication, access control, SQLi and XSS checks.
# Start the server first:  flask --app wsgi run --port 8000
set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
DEMO_USER="${DEMO_USER:-alice}"
DEMO_PASSWORD="${DEMO_PASSWORD:-Demo-Passw0rd!}"

step() { printf '\n\033[1;34m=== %s\033[0m\n' "$1"; }

# Prints the curl command (quoted, token shortened to $TOKEN), then runs it and
# shows the JSON body and HTTP status
call() {
  local shown="" arg dq='"' escaped_dq='\"' token_name='$TOKEN'
  for arg in "$@"; do
    if [[ "$arg" =~ ^[A-Za-z0-9_./:=-]+$ ]]; then
      shown+="$arg "
    elif [[ "$arg" == *"'"* ]]; then
      shown+="\"${arg//$dq/$escaped_dq}\" "
    else
      shown+="'$arg' "
    fi
  done
  if [[ -n "${TOKEN:-}" ]]; then shown="${shown//"$TOKEN"/$token_name}"; fi
  printf '\033[0;90m$ curl %s\033[0m\n' "$shown"
  curl -s -w '\n-> HTTP %{http_code}\n' "$@"
}

step "1. Register a user (password is stored as a bcrypt hash)"
call -X POST "$BASE_URL/auth/register" -H "Content-Type: application/json" \
  -d "{\"username\": \"$DEMO_USER\", \"password\": \"$DEMO_PASSWORD\"}"

step "2. Login with a wrong password -> 401"
call -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\": \"$DEMO_USER\", \"password\": \"wrong-password\"}"

step "3. Login with SQL injection in the username -> 401 (no bypass)"
call -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\": \"$DEMO_USER' OR '1'='1\", \"password\": \"x\"}"

step "4. Access protected data WITHOUT a token -> 401"
call "$BASE_URL/api/data"

step "5. Access protected data with a FORGED token -> 401"
call "$BASE_URL/api/data" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."

step "6. Login with the correct password -> 200 + JWT"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\": \"$DEMO_USER\", \"password\": \"$DEMO_PASSWORD\"}")
echo "$LOGIN_RESPONSE"
TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"

step "7. Create a post (custom endpoint POST /api/data) -> 201"
call -X POST "$BASE_URL/api/data" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"title": "Hello", "content": "My first secure post"}'

step "8. Create a post containing an XSS payload -> stored, but escaped on output"
call -X POST "$BASE_URL/api/data" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"title": "<script>alert(1)</script>", "content": "<img src=x onerror=alert(1)>"}'

step "9. Read protected data WITH the token -> 200"
call "$BASE_URL/api/data" -H "$AUTH"

step "10. Search with a SQL injection payload -> treated as plain text, 0 results"
call -G "$BASE_URL/api/data" -H "$AUTH" --data-urlencode "q=' OR 1=1 --"
