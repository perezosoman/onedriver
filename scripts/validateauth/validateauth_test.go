// scripts/validateauth/validateauth_test.go exercises
// scripts/validate-auth.sh end-to-end against canned HTTP responses,
// without ever touching the real Microsoft endpoints.
//
// Package layout:
//
//	scripts/validate-auth.sh           ← the bash script under test
//	scripts/validateauth/              ← this package
//	scripts/validateauth/validateauth_test.go
//	scripts/validateauth/testdata/auth-fixtures/{happy-refresh,...}
//
// How a single test scenario runs:
//
//  1. Pick a fixture directory under scripts/validateauth/testdata/auth-fixtures/
//     (or "": no fixtures → real curl would be invoked, which the tests
//     deliberately avoid by exercising branches that don't reach curl).
//  2. Compose ONEDRIVER_AUTH_TOKENS JSON via a builder.
//  3. Run `bash scripts/validate-auth.sh` in a fresh t.TempDir(), with
//     GITHUB_OUTPUT / GITHUB_ENV / VALIDATE_AUTH_FIXTURES_DIR /
//     VALIDATE_AUTH_NOW / VALIDATE_AUTH_BODY_FILE set to per-run temp
//     paths / canned values.
//  4. Read the side-effect files (.auth_tokens.json, dmel.fa) and the
//     output sink files (GITHUB_OUTPUT_FILE, GITHUB_ENV_FILE).
//  5. Assert.
//
// Run from repo root:
//
//	go test ./scripts/validateauth/...
package validateauth

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scriptPath is the absolute path of the bash script under test.
//
// Resolved once at test load time. The script lives one level up from
// this package: ../scripts/validate-auth.sh relative to the package dir
// scripts/validateauth/.
var scriptPath = func() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	// Go tests run with cwd = package dir = scripts/validateauth/.
	p, err := filepath.Abs(filepath.Join(wd, "..", "validate-auth.sh"))
	if err != nil {
		panic(err)
	}
	return p
}()

// builtinFixtures maps scenario names to fixture-dir basenames under
// scripts/validateauth/testdata/auth-fixtures/. Tests pass these names
// via the fixtures string field — "" means no fixtures, in which case the
// test must NOT exercise a path that would hit curl.
var builtinFixtures = map[string]string{
	"happy-refresh":    "happy-refresh",
	"failed-refresh":   "failed-refresh",
	"refresh-empty":    "refresh-empty-access",
	"happy-me":         "happy-me",
	"rejected-me":      "rejected-me",
	"me-network-error": "me-network-error",
}

// fixedNOW is the deterministic "current time" used by every test. We set
// VALIDATE_AUTH_NOW to this so tests pass regardless of wall-clock time.
// Tokens either expire before this (NOW-60 = 1699999940) or stay valid
// until after this (NOW+3600 = 1700003600).
const fixedNOW = int64(1_700_000_000)

// TestValidateAuthSh is the table-driven test. Each case composes a
// simulated secret, runs the script, and checks the side effects.
func TestValidateAuthSh(t *testing.T) {
	wd, _ := os.Getwd()
	fixturesRoot := filepath.Join(wd, "testdata", "auth-fixtures")

	cases := []struct {
		name string
		// secretBuilder, if non-nil, returns the JSON value of
		// ONEDRIVER_AUTH_TOKENS for this scenario (returning "" ==
		// unset, which is different from "{}" which is "set but empty").
		secretBuilder func(t *testing.T) string
		// fixtures is the basename of the canned-responses directory,
		// or "" for no fixtures (used by tests that should never reach
		// curl).
		fixtures string
		// wantValid is the expected value of "auth_valid" in the
		// GITHUB_OUTPUT sink.
		wantValid string
		// wantReasonHas is a substring that must appear in auth_reason.
		wantReasonHas string
		// wantMockEnv: true → expect ONEDRIVER_MOCK=1 in GITHUB_ENV.
		wantMockEnv bool
		// wantDmelFa: true → expect CWD/dmel.fa to exist and be > 1 KB.
		wantDmelFa bool
		// wantTokensHas checks the body of .auth_tokens.json after the
		// run. Empty string means "check literally equal to {}".
		wantTokensHas string
	}{
		{
			name:          "secret_absent_falls_back_to_mock",
			secretBuilder: nil,
			fixtures:      "",
			wantValid:     "false",
			wantReasonHas: "environment variable is not set",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name:          "invalid_json_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string { return "not-json-at-all{{{ " },
			fixtures:      "",
			wantValid:     "false",
			wantReasonHas: "no access_token", // access_token jq parse returns empty → "no access_token" reason
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "no_access_token_field_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "",
					RefreshToken: "rt",
					ExpiresAt:    fixedNOW + 3600,
				})
			},
			fixtures:      "",
			wantValid:     "false",
			wantReasonHas: "no access_token",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "non_integer_expires_at_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				// expires_at must be a string for jq to yield non-integer.
				// We bypass the typed builder to test this branch.
				return `{"access_token":"at","refresh_token":"rt","expires_at":"not-a-number"}`
			},
			fixtures:      "",
			wantValid:     "false",
			wantReasonHas: "expires_at is not a valid integer",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "expired_without_refresh_token_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "at",
					RefreshToken: "",
					ExpiresAt:    fixedNOW - 60, // expired
				})
			},
			fixtures:      "",
			wantValid:     "false",
			wantReasonHas: "no refresh_token",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "expired_refresh_succeeds_writes_new_tokens",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "old-at",
					RefreshToken: "old-rt",
					ExpiresAt:    fixedNOW - 60,
					Account:      "[email protected]",
				})
			},
			fixtures:      "happy-refresh",
			wantValid:     "true",
			wantReasonHas: "refreshed via OAuth",
			wantMockEnv:   false,
			wantDmelFa:    false,
			wantTokensHas: "new-access-token-rotated-by-microsoft",
		},
		{
			name: "expired_refresh_fails_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "old-at",
					RefreshToken: "old-rt",
					ExpiresAt:    fixedNOW - 60,
				})
			},
			fixtures:      "failed-refresh",
			wantValid:     "false",
			wantReasonHas: "refresh failed (invalid_grant",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			// Defensive: Microsoft returns 400 on auth errors, not 200
			// with empty token. But a regression that ignored the
			// [ -n "$NEW_ACCESS" ] guard would silently treat 200 +
			// empty access_token as success. We assert the same
			// "refresh failed" substring as the failed-refresh case so
			// the two defensive scenarios stay comparable.
			name: "expired_refresh_with_empty_access_token_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "old-at",
					RefreshToken: "old-rt",
					ExpiresAt:    fixedNOW - 60,
				})
			},
			fixtures:      "refresh-empty",
			wantValid:     "false",
			wantReasonHas: "refresh failed (invalid_grant",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			// EXPIRES_AT=0 means "no expiry info given". The script
			// treats 0 as not-expired (guards against accidentally
			// classifying epoch timestamps as valid-after-now).
			name: "expires_at_zero_treated_as_not_expired_runs_me_check",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "at-good",
					RefreshToken: "rt",
					ExpiresAt:    0, // ← no expiry info
				})
			},
			fixtures:      "happy-me",
			wantValid:     "true",
			wantReasonHas: "validated against Microsoft Graph",
			wantMockEnv:   false,
			wantDmelFa:    false,
			wantTokensHas: "at-good",
		},
		{
			name: "not_expired_me_200_validates_and_passes_through",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "at-good",
					RefreshToken: "rt",
					ExpiresAt:    fixedNOW + 3600,
					Account:      "[email protected]",
				})
			},
			fixtures:      "happy-me",
			wantValid:     "true",
			wantReasonHas: "validated against Microsoft Graph",
			wantMockEnv:   false,
			wantDmelFa:    false,
			wantTokensHas: "at-good", // pass-through: original goes in, comes out verbatim
		},
		{
			name: "not_expired_me_401_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "at-revoked",
					RefreshToken: "rt",
					ExpiresAt:    fixedNOW + 3600,
				})
			},
			fixtures:      "rejected-me",
			wantValid:     "false",
			wantReasonHas: "Microsoft Graph rejected token (HTTP 401)",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "not_expired_me_network_error_falls_back_to_mock",
			secretBuilder: func(t *testing.T) string {
				return mkSecret(t, secretOpts{
					AccessToken:  "at",
					RefreshToken: "rt",
					ExpiresAt:    fixedNOW + 3600,
				})
			},
			fixtures:      "me-network-error",
			wantValid:     "false",
			wantReasonHas: "network error or timeout",
			wantMockEnv:   true,
			wantDmelFa:    true,
		},
		{
			name: "shell_injection_safe_on_malicious_secret",
			secretBuilder: func(t *testing.T) string {
				// If anything in the pipeline ever expanded a $(...) or
				// backtick from the secret, this test would create a file
				// /tmp/INJECTION_FIRED — the assertion below checks for
				// that file's ABSENCE.
				return mkSecret(t, secretOpts{
					AccessToken:  "$(touch /tmp/INJECTION_FIRED)",
					RefreshToken: "`touch /tmp/INJECTION_FIRED`",
					ExpiresAt:    fixedNOW + 3600,
					Account:      "; touch /tmp/INJECTION_FIRED ;",
				})
			},
			fixtures:      "happy-me",
			wantValid:     "true",
			wantReasonHas: "validated against Microsoft Graph",
			wantMockEnv:   false,
			wantDmelFa:    false,
			wantTokensHas: "$(touch /tmp/INJECTION_FIRED)", // literal preserved, not executed
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			// Wire up env for the script. We deliberately start from a
			// minimal set (PATH, HOME) to keep the script hermetic — the
			// bash script will not see the host's ONEDRIVER_AUTH_TOKENS,
			// GITHUB_OUTPUT, GITHUB_ENV, etc.
			env := []string{
				"PATH=" + os.Getenv("PATH"),
				"HOME=" + os.Getenv("HOME"),
				// Default to unset (intentionally empty) so the
				// "secret_absent" branch is reachable.
				"ONEDRIVER_AUTH_TOKENS=",
			}
			if tc.secretBuilder != nil {
				env = append(env, "ONEDRIVER_AUTH_TOKENS="+tc.secretBuilder(t))
			}
			githubOutput := filepath.Join(dir, "gh-output")
			githubEnv := filepath.Join(dir, "gh-env")
			// Per-run body file: prevents cross-test races when this
			// package is run in parallel with `go test -parallel` or
			// t.Parallel(). The script writes the /me response body
			// here.
			bodyFile := filepath.Join(dir, "auth-check.json")
			env = append(env,
				"GITHUB_OUTPUT="+githubOutput,
				"GITHUB_ENV="+githubEnv,
				"VALIDATE_AUTH_BODY_FILE="+bodyFile,
				fmt.Sprintf("VALIDATE_AUTH_NOW=%d", fixedNOW),
			)
			if tc.fixtures != "" {
				base, ok := builtinFixtures[tc.fixtures]
				if !ok {
					t.Fatalf("unknown fixtures name: %q", tc.fixtures)
				}
				env = append(env,
					"VALIDATE_AUTH_FIXTURES_DIR="+filepath.Join(fixturesRoot, base),
				)
			}

			cmd := exec.Command("bash", scriptPath)
			cmd.Dir = dir
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("script exited with error: %v\nscript output:\n%s",
					err, string(out))
			}

			// ── assert auth_valid ───────────────────────────────────────
			ghOutputBytes, err := os.ReadFile(githubOutput)
			if err != nil {
				t.Fatalf("read GITHUB_OUTPUT: %v", err)
			}
			if !strings.Contains(string(ghOutputBytes),
				"auth_valid="+tc.wantValid) {
				t.Errorf("auth_valid mismatch\nwant: %q\ngot:\n%s",
					tc.wantValid, string(ghOutputBytes))
			}

			// ── assert auth_reason substring ─────────────────────────────
			if !strings.Contains(string(ghOutputBytes), tc.wantReasonHas) {
				t.Errorf("auth_reason mismatch\nwant substring: %q\ngot:\n%s",
					tc.wantReasonHas, string(ghOutputBytes))
			}

			// ── assert ONEDRIVER_MOCK setting ───────────────────────────
			ghEnvBytes, err := os.ReadFile(githubEnv)
			if err != nil {
				t.Fatalf("read GITHUB_ENV: %v", err)
			}
			mockSet := strings.Contains(string(ghEnvBytes), "ONEDRIVER_MOCK=1")
			if mockSet != tc.wantMockEnv {
				t.Errorf("ONEDRIVER_MOCK mismatch\nwant: %v\ngot env file:\n%s",
					tc.wantMockEnv, string(ghEnvBytes))
			}

			// ── assert dmel.fa existence ────────────────────────────────
			dmelBytes := int64(-1)
			if info, err := os.Stat(filepath.Join(dir, "dmel.fa")); err == nil {
				dmelBytes = info.Size()
			}
			hasDmel := dmelBytes > 1024
			if hasDmel != tc.wantDmelFa {
				t.Errorf("dmel.fa mismatch\nwant: %v\ngot size: %d",
					tc.wantDmelFa, dmelBytes)
			}

			// ── assert .auth_tokens.json contents ────────────────────────
			tokensBytes, err := os.ReadFile(filepath.Join(dir, ".auth_tokens.json"))
			if err != nil {
				t.Fatalf("read .auth_tokens.json: %v", err)
			}
			tokens := string(tokensBytes)
			if tc.wantMockEnv {
				// Mock fallback writes literally "{}" — verify bytes
				// match exactly so we catch any drift (e.g. a stray
				// newline that the OAuth parser later chokes on).
				if strings.TrimSpace(tokens) != "{}" {
					t.Errorf("mock-mode tokens file should be '{}'\ngot: %q",
						tokens)
				}
			}
			if tc.wantTokensHas != "" && !strings.Contains(tokens, tc.wantTokensHas) {
				t.Errorf(".auth_tokens.json mismatch\nwant substring: %q\ngot: %q",
					tc.wantTokensHas, tokens)
			}

			// ── shell-injection specific assertion ───────────────────────
			if tc.name == "shell_injection_safe_on_malicious_secret" {
				// Defense in depth: clean any leftover sentinel from a
				// previous broken run BEFORE the script executes, then
				// again after, so a regression is reported reliably and
				// doesn't poison subsequent runs on a shared box.
				_ = os.Remove("/tmp/INJECTION_FIRED")
				t.Cleanup(func() { _ = os.Remove("/tmp/INJECTION_FIRED") })
				if _, err := os.Stat("/tmp/INJECTION_FIRED"); err == nil {
					t.Errorf("shell injection succeeded — /tmp/INJECTION_FIRED exists!")
				}
			}
		})
	}
}

// TestValidateAuthShSyntaxErr is a basic "did we leave a typo" guard.
// Even if no scenario exercises a given line, a malformed bash script
// would fail here. Runs `bash -n` rather than the full script so it
// stays cheap and dependency-free.
func TestValidateAuthShSyntaxErr(t *testing.T) {
	cmd := exec.Command("bash", "-n", scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n reported syntax error: %v\noutput:\n%s", err, out)
	}
}

// ── helper builders ──────────────────────────────────────────────────────

type secretOpts struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
	Account      string
	// If true, leave out the access_token field entirely. Used to test
	// the "no access_token" branch (jq yields null → "" → branch taken).
	OmitAccess bool
}

// mkSecret composes a deterministic JSON object that mimics the
// ONEDRIVER_AUTH_TOKENS secret. Kept deliberately simple (no Go json
// struct indirection) so failures point at the actual shape, not at a
// serialization layer.
func mkSecret(t *testing.T, opts secretOpts) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("{")
	if !opts.OmitAccess {
		fmt.Fprintf(&sb, `"access_token":%q`, opts.AccessToken)
	}
	if opts.RefreshToken != "" {
		fmt.Fprintf(&sb, `,"refresh_token":%q`, opts.RefreshToken)
	}
	fmt.Fprintf(&sb, `,"expires_at":%d`, opts.ExpiresAt)
	if opts.Account != "" {
		fmt.Fprintf(&sb, `,"account":%q`, opts.Account)
	}
	// Config block closes ONLY the inner object; the trailing `}` below
	// closes the top-level object. (Earlier drafts accidentally double-
	// closed, producing "}}}".)
	sb.WriteString(`,"config":{"clientID":"test-client","tokenURL":"https://example.test/token","redirectURL":"https://example.test/redirect"}`)
	sb.WriteString("}")
	out := sb.String()
	// Sanity: result must parse as JSON.
	var any interface{}
	if err := json.Unmarshal([]byte(out), &any); err != nil {
		t.Fatalf("mkSecret produced invalid JSON: %v\n%s", err, out)
	}
	return out
}
