#!/usr/bin/env bash
# Smoke-test critical API endpoints (local or deployed).
# Usage: ./scripts/verify_deploy.sh [BASE_URL]
# Example: ./scripts/verify_deploy.sh https://fitlife-api.onrender.com

set -euo pipefail

BASE="${1:-http://127.0.0.1:8000}"
API="${BASE%/}/api"
PASS=0
FAIL=0

ok() { echo "✓ $1"; PASS=$((PASS + 1)); }
bad() { echo "✗ $1"; FAIL=$((FAIL + 1)); }

echo "Testing FitLife API at $BASE"
echo "---"

HEALTH=$(curl -s -m 30 "$API/health" 2>/dev/null || echo "")
echo "$HEALTH" | grep -q '"status":"ok"' && ok "Health" || bad "Health ($HEALTH)"

USER="verify_$(date +%s)"
curl -s -m 30 -X POST "$API/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"TestPass123!\",\"confirm_password\":\"TestPass123!\"}" \
  | grep -q 'message' && ok "Signup" || bad "Signup"

LOGIN=$(curl -s -m 30 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"TestPass123!\"}")
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)

if [[ -n "$TOKEN" ]]; then
  ok "Login"
  curl -s -m 30 -H "Authorization: Bearer $TOKEN" "$API/auth/me" | grep -q "$USER" && ok "Auth /me" || bad "Auth /me"
  for path in exercises articles recipes blogs; do
    curl -s -m 30 -H "Authorization: Bearer $TOKEN" "$API/content/$path" | grep -q . && ok "Content /$path" || bad "Content /$path"
  done
  curl -s -m 30 -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"exercise_name":"Push-ups","sets":3,"reps":10}' "$API/activity/workouts" \
    | grep -q 'id' && ok "Log workout" || bad "Log workout"
  curl -s -m 30 -H "Authorization: Bearer $TOKEN" "$API/activity/dashboard" | grep -q 'total_workouts' && ok "Dashboard" || bad "Dashboard"
else
  bad "Login ($LOGIN)"
fi

echo "---"
echo "Passed: $PASS | Failed: $FAIL"
[[ "$FAIL" -eq 0 ]]
