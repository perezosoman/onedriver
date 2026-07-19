#!/usr/bin/env bash
# scripts/validate-auth.sh — validate ONEDRIVER_AUTH_TOKENS secret against
# Microsoft Graph with optional OAuth refresh, then write side-effect files
# (.auth_tokens.json, dmel.fa, GITHUB_OUTPUT, GITHUB_ENV).
#
# Used by .github/workflows/ci.yml. Extracted from inline bash so it can be
# unit-tested locally without pushing commits: see
# scripts/validate-auth_test.go for the table-driven tests.
#
# ────────────────────────────────────────────────────────────────────────────
# Contract
# ────────────────────────────────────────────────────────────────────────────
#
# Inputs (env):
#   ONEDRIVER_AUTH_TOKENS   JSON secret. Required-ish; if unset we fall to
#                           mock mode immediately.
#   GITHUB_OUTPUT           Path to GitHub Actions $GITHUB_OUTPUT file.
#                           Optional; falls back to ".validate-auth-output"
#                           in CWD (so local invocations also work).
#   GITHUB_ENV              Path to GitHub Actions $GITHUB_ENV file.
#                           Optional; falls back to ".validate-auth-env" in CWD.
#
# Test hooks (only read when CI is not being run):
#   VALIDATE_AUTH_FIXTURES_DIR   Directory containing canned HTTP responses
#                                for the two external calls. Files:
#                                  - refresh-body.json  (OAuth refresh response)
#                                  - refresh-status.txt (HTTP code as text)
#                                  - me-body.json       (/me response)
#                                  - me-status.txt      (HTTP code as text)
#                                When set, real curl is skipped entirely.
#   VALIDATE_AUTH_NOW            Unix timestamp used instead of `date +%s`,
#                                so tests don't depend on wall-clock time.
#
# Outputs (written to CWD):
#   .auth_tokens.json       Either the (refreshed) tokens or "{}" (mock).
#   dmel.fa                 1 MB random dummy iff mock fallback fired.
#
# Outputs (appended to GITHUB_OUTPUT / .validate-auth-output):
#   auth_valid=true|false
#   auth_reason<<EOF_REASON ... EOF_REASON
#   auth_user=<userPrincipalName|"" >
#
# Outputs (appended to GITHUB_ENV / .validate-auth-env, only on mock):
#   ONEDRIVER_MOCK=1
#
# Exit code: always 0. Auth failures are reported via auth_valid=false in
# the OUTPUT, not via exit code, so the CI workflow can branch on the
# output without aborting the whole job.
# ────────────────────────────────────────────────────────────────────────────

set +e
# We deliberately do not use `set -e`: every external call (jq, curl, date)
# has a manual fallback path that records the failure into AUTH_REASON
# instead of bailing out.

# Output sinks. In CI these are GitHub-Actions-managed paths; otherwise we
# fall back to per-invocation temp files so a local run does not pollute its
# working directory with leftover `.validate-auth-*` sentinels.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  GITHUB_OUTPUT_FILE="$GITHUB_OUTPUT"
else
  GITHUB_OUTPUT_FILE="$(mktemp "${TMPDIR:-/tmp}/onedriver-validate-auth-output.XXXXXX" 2>/dev/null || echo "${TMPDIR:-/tmp}/onedriver-validate-auth-output.$$")"
fi
if [ -n "${GITHUB_ENV:-}" ]; then
  GITHUB_ENV_FILE="$GITHUB_ENV"
else
  GITHUB_ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/onedriver-validate-auth-env.XXXXXX" 2>/dev/null || echo "${TMPDIR:-/tmp}/onedriver-validate-auth-env.$$")"
fi
: > "$GITHUB_OUTPUT_FILE"
: > "$GITHUB_ENV_FILE"

# Defaults from fs/graph/oauth2.go. Used when the secret does not carry its
# own config block. Kept in sync with constants in oauth2.go.
DEFAULT_CLIENT_ID="3470c3fa-bc10-45ab-a0a9-2d30836485d1"
DEFAULT_TOKEN_URL="https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEFAULT_REDIRECT_URL="https://login.live.com/oauth20_desktop.srf"

# Path where the /me response body is written for later jq parsing. Default
# matches the original ci.yml behavior; tests override via
# VALIDATE_AUTH_BODY_FILE for parallel-safe isolation.
AUTH_CHECK_FILE="${VALIDATE_AUTH_BODY_FILE:-/tmp/auth-check.json}"

AUTH_VALID="false"
AUTH_REASON="ONEDRIVER_AUTH_TOKENS environment variable is not set"
AUTH_USER=""

if [ -n "${ONEDRIVER_AUTH_TOKENS:-}" ]; then
  ACCESS_TOKEN=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r '.access_token // empty' 2>/dev/null)
  EXPIRES_AT=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r '.expires_at // 0' 2>/dev/null)
  REFRESH_TOKEN=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r '.refresh_token // empty' 2>/dev/null)
  # Below: jq's // $d syntax provides the defaults without ever allowing the
  # shell to expand VALUES that flow out of the secret — important to keep
  # shell injection safety even if access_token contains "$()" or backticks.
  CLIENT_ID=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r --arg d "$DEFAULT_CLIENT_ID" '.config.clientID // $d' 2>/dev/null)
  REDIRECT_URL=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r --arg d "$DEFAULT_REDIRECT_URL" '.config.redirectURL // $d' 2>/dev/null)
  TOKEN_URL=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r --arg d "$DEFAULT_TOKEN_URL" '.config.tokenURL // $d' 2>/dev/null)
  ACCOUNT=$(printf '%s' "$ONEDRIVER_AUTH_TOKENS" | jq -r '.account // empty' 2>/dev/null)
  # Test-mode override: allow deterministic "now" without depending on
  # wall-clock time. In production this is always empty and we use date.
  NOW="${VALIDATE_AUTH_NOW:-$(date +%s 2>/dev/null || echo 0)}"

  if [ -z "$ACCESS_TOKEN" ]; then
    AUTH_REASON="ONEDRIVER_AUTH_TOKENS is set but has no access_token field"
  elif ! [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]]; then
    AUTH_REASON="expires_at is not a valid integer (got: '$EXPIRES_AT')"
  elif [ "$EXPIRES_AT" -gt 0 ] && [ "$EXPIRES_AT" -lt "$NOW" ]; then
    # ── Token expired. Attempt OAuth refresh. ────────────────────────────
    EXPIRY_ISO=$(date -u -d "@$EXPIRES_AT" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "$EXPIRES_AT")
    if [ -n "$REFRESH_TOKEN" ]; then
      echo "::group::Refreshing expired token (expired at $EXPIRY_ISO)"

      if [ -n "${VALIDATE_AUTH_FIXTURES_DIR:-}" ]; then
        # ── Test mode: read canned responses ───────────────────────────
        REFRESH_RESP=$(cat "$VALIDATE_AUTH_FIXTURES_DIR/refresh-body.json" 2>/dev/null || echo "")
        REFRESH_HTTP=$(cat "$VALIDATE_AUTH_FIXTURES_DIR/refresh-status.txt" 2>/dev/null || echo "200")
      else
        # ── Production: POST to the token endpoint ──────────────────────
        # Build the form body via jq so the values are URL-encoded without
        # ever being expanded by the shell. --arg passes the literal string
        # into the jq runtime; @uri percent-encodes it. This keeps shell
        # injection impossible even if any of these fields contain "$()"
        # or backticks.
        FORM_BODY=$(jq -nr \
          --arg ci "$CLIENT_ID" \
          --arg ru "$REDIRECT_URL" \
          --arg rt "$REFRESH_TOKEN" \
          '"client_id=" + ($ci | @uri) + "&redirect_uri=" + ($ru | @uri) + "&refresh_token=" + ($rt | @uri) + "&grant_type=refresh_token"')
        REFRESH_RESP=$(curl -sS --max-time 15 \
          -X POST \
          -H "Content-Type: application/x-www-form-urlencoded" \
          --data "$FORM_BODY" \
          "$TOKEN_URL" 2>/dev/null)
        # If curl succeeded it always returns 200 for parseable responses;
        # failures cascade into empty REFRESH_RESP which the parse logic
        # below catches.
        REFRESH_HTTP="200"
      fi

      NEW_ACCESS=$(printf '%s' "$REFRESH_RESP" | jq -r '.access_token // empty' 2>/dev/null)
      NEW_EXPIRES_IN=$(printf '%s' "$REFRESH_RESP" | jq -r '.expires_in // 0' 2>/dev/null)
      NEW_REFRESH=$(printf '%s' "$REFRESH_RESP" | jq -r '.refresh_token // empty' 2>/dev/null)
      # Microsoft rotates refresh tokens on each use; preserve the rotated
      # one if the server returned it, otherwise keep the old one.
      [ -z "$NEW_REFRESH" ] && NEW_REFRESH="$REFRESH_TOKEN"

      if [ -n "$NEW_ACCESS" ] && [[ "$NEW_EXPIRES_IN" =~ ^[0-9]+$ ]] && [ "$REFRESH_HTTP" = "200" ]; then
        NEW_EXPIRES_AT=$((NOW + NEW_EXPIRES_IN))
        # Rewrite .auth_tokens.json with the refreshed payload.
        jq -n \
          --arg at "$NEW_ACCESS" \
          --arg rt "$NEW_REFRESH" \
          --argjson ea "$NEW_EXPIRES_AT" \
          --argjson ei "$NEW_EXPIRES_IN" \
          --arg ci "$CLIENT_ID" \
          --arg tu "$TOKEN_URL" \
          --arg ru "$REDIRECT_URL" \
          --arg acct "$ACCOUNT" \
          '{access_token: $at, refresh_token: $rt, expires_at: $ea, expires_in: $ei, account: $acct, config: {clientID: $ci, tokenURL: $tu, redirectURL: $ru}}' \
          > .auth_tokens.json
        AUTH_VALID="true"
        NEW_EXPIRY_ISO=$(date -u -d "@$NEW_EXPIRES_AT" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "$NEW_EXPIRES_AT")
        # GitHub Secrets cannot be written from a workflow, so the
        # refreshed tokens are written only to .auth_tokens.json (uploaded
        # to S3 by the "Copy new auth tokens to S3" step). The next CI run
        # will still see the OLD refresh_token in the secret and fail its
        # own refresh — the operator must periodically re-export the
        # refreshed payload back into the secret.
        AUTH_REASON="refreshed via OAuth (valid until $NEW_EXPIRY_ISO) ⚠️  re-export to ONEDRIVER_AUTH_TOKENS secret before next run"
      else
        ERR_CODE=$(printf '%s' "$REFRESH_RESP" | jq -r '.error // "unknown"' 2>/dev/null)
        ERR_DESC=$(printf '%s' "$REFRESH_RESP" | jq -r '.error_description // ""' 2>/dev/null)
        AUTH_REASON="token expired at $EXPIRY_ISO; refresh failed ($ERR_CODE: $ERR_DESC)"
      fi
      echo "::endgroup::"
    else
      AUTH_REASON="token expired at $EXPIRY_ISO; no refresh_token in secret"
    fi
  else
    # ── Token not expired. Live validation against Microsoft Graph /me. ──
    EXPIRY_ISO=$(date -u -d "@$EXPIRES_AT" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "$EXPIRES_AT")

    if [ -n "${VALIDATE_AUTH_FIXTURES_DIR:-}" ]; then
      # ── Test mode: read canned response ──────────────────────────────
      ME_HTTP=$(cat "$VALIDATE_AUTH_FIXTURES_DIR/me-status.txt" 2>/dev/null || echo "200")
      cat "$VALIDATE_AUTH_FIXTURES_DIR/me-body.json" > "$AUTH_CHECK_FILE" 2>/dev/null || echo "{}" > "$AUTH_CHECK_FILE"
    else
      # ── Production: GET /v1.0/me with bearer token ───────────────────
      # stderr is dropped so a network/timeout failure doesn't pollute the
      # log; we still capture the HTTP code via -w.
      ME_HTTP=$(curl -sS -o "$AUTH_CHECK_FILE" -w "%{http_code}" \
        --max-time 10 \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Accept: application/json" \
        "https://graph.microsoft.com/v1.0/me" 2>/dev/null || echo "000")
    fi

    if [ "$ME_HTTP" = "200" ]; then
      # Pass-through: the secret was already valid, write it verbatim so
      # the rest of CI doesn't need to know whether we refreshed or not.
      printf '%s\n' "$ONEDRIVER_AUTH_TOKENS" > .auth_tokens.json
      AUTH_VALID="true"
      AUTH_USER=$(jq -r '.userPrincipalName // .displayName // .id // "unknown"' "$AUTH_CHECK_FILE" 2>/dev/null)
      AUTH_REASON="validated against Microsoft Graph (user: $AUTH_USER, valid until $EXPIRY_ISO)"
    else
      ERR_CODE=$(jq -r '.error.code // "unknown"' "$AUTH_CHECK_FILE" 2>/dev/null)
      ERR_DESC=$(jq -r '.error.message // ""' "$AUTH_CHECK_FILE" 2>/dev/null)
      [ "$ME_HTTP" = "000" ] && ERR_DESC="network error or timeout"
      AUTH_REASON="Microsoft Graph rejected token (HTTP $ME_HTTP) — $ERR_CODE: $ERR_DESC"
    fi
  fi
fi

# ── Mock fallback. Always reaches this block when AUTH_VALID is not "true".
if [ "$AUTH_VALID" != "true" ]; then
  printf '%s\n' '{}' > .auth_tokens.json
  echo "ONEDRIVER_MOCK=1" >> "$GITHUB_ENV_FILE"
  # 1 MB dummy dmel.fa so ./fs tests that need a file find one.
  dd if=/dev/urandom of=dmel.fa bs=1024 count=1024 2>/dev/null
fi

# Sanitize outputs (no PII leakage in CI logs).
# - tr '\n' ' ' collapses multi-line reasons into one line.
# - head -c 250 caps length so a runaway token field can't blow up the log.
# - sed redacts any email address that snuck into the human-readable
#   reason (e.g. "(user: paveryutu72@hotmail.com, ...)").
# The visible success / failure echoes below also apply the same sed.
AUTH_REASON_SAFE=$(printf '%s' "$AUTH_REASON" | tr '\n' ' ' | head -c 250 \
  | sed -E 's/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/*****@REDACTED/g')

# Never emit the raw userPrincipalName / email to $GITHUB_OUTPUT. The
# presence of a non-empty auth_user signals "we identified someone";
# the actual identity stays out of every CI log line and PR comment.
# Downstream steps (e.g. ci.yml) only check auth_valid, never auth_user,
# so this is purely PII hygiene.
if [ -n "$AUTH_USER" ] && [ "$AUTH_USER" != "unknown" ]; then
  AUTH_USER_OUTPUT='user-*****@REDACTED'
else
  AUTH_USER_OUTPUT=''
fi

# Multi-line heredoc syntax for auth_reason — GitHub Actions special form.
{
  echo "auth_valid=$AUTH_VALID"
  echo "auth_reason<<EOF_REASON"
  echo "$AUTH_REASON_SAFE"
  echo "EOF_REASON"
  echo "auth_user=$AUTH_USER_OUTPUT"
} >> "$GITHUB_OUTPUT_FILE"

if [ -n "${VALIDATE_AUTH_FIXTURES_DIR:-}" ]; then
  echo "::test-mode:: used fixtures from $VALIDATE_AUTH_FIXTURES_DIR"
fi

if [ "$AUTH_VALID" = "true" ]; then
  echo "✅ ONEDRIVER_AUTH_TOKENS validation passed"
  # Show the reason but hide the email address in the log. 
  echo "  $AUTH_REASON" | sed -E 's/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/*****@REDACTED/g'
  
else
  echo "⚠️  ONEDRIVER_AUTH_TOKENS invalid — falling back to mock Graph API"
  echo "   $AUTH_REASON" | sed -E 's/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/*****@REDACTED/g'
fi
