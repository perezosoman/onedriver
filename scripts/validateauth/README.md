# `scripts/validate-auth.sh` & tests

This directory holds the unit tests (`validateauth_test.go`) plus canned
HTTP fixtures (`testdata/auth-fixtures/`) for the `scripts/validate-auth.sh`
bash script that lives one level up (`scripts/validate-auth.sh`). The
script is invoked from the CI workflow
(`.github/workflows/ci.yml`, step *"Validate ONEDRIVER_AUTH_TOKENS
upfront"*) but is **fully self-contained** — you can run, test, and
extend it locally without touching the GitHub Actions machinery.

## TL;DR

```bash
# Run the unit-test suite (no network, no secrets needed):
go test -v -count=1 ./scripts/validateauth/...

# Run the script against a real OneDrive secret (writes
# .auth_tokens.json, dmel.fa, and authenticates via Microsoft Graph):
export ONEDRIVER_AUTH_TOKENS='{"access_token":"...","expires_at":...}'
bash scripts/validate-auth.sh
```

## What the script does

`scripts/validate-auth.sh` reads a JSON secret
(`$ONEDRIVER_AUTH_TOKENS`) shaped like the real
[Microsoft OAuth2 token JSON](../fs/graph/oauth2.go) and decides
before any test binary runs whether to put the suite into:

- **Real-auth mode** — `auth_valid=true`, exits with the (possibly
  refreshed) `.auth_tokens.json` ready for `fs/graph.Authenticate(...)`.
- **Mock mode** — `auth_valid=false`, writes an empty
  `.auth_tokens.json`, sets `ONEDRIVER_MOCK=1` so the rest of CI
  swaps to the local mock Graph server, and writes a 1 MB dummy
  `dmel.fa` so `./fs` tests that need a fixture file find one.

The decision is silent (always exits 0); downstream CI steps read
`steps.<id>.outputs.auth_valid` from `$GITHUB_OUTPUT` and switch
behaviour on it.

The script also performs a **silent OAuth refresh** when the access
token is expired but a `refresh_token` is present — useful because
CI secrets tend to drift out of date between rotates.

## I/O contract

| Env var (input)              | Purpose                                                                                |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| `ONEDRIVER_AUTH_TOKENS`      | JSON secret (see `fs/graph/oauth2.go` for field names). Required when used in CI.      |
| `GITHUB_OUTPUT`              | Path to the per-step `$GITHUB_OUTPUT` file (auto-set by GitHub Actions). Fallback: `mktemp`. |
| `GITHUB_ENV`                 | Path to the per-step `$GITHUB_ENV` file. Fallback: `mktemp`.                            |
| `VALIDATE_AUTH_FIXTURES_DIR` | **Test mode only**: directory of canned `refresh-*.json/txt` and `me-*.json/txt`.       |
| `VALIDATE_AUTH_NOW`          | **Test mode only**: Unix timestamp used instead of `date +%s` for deterministic expiry. |
| `VALIDATE_AUTH_BODY_FILE`    | **Test mode only**: per-run path for the `/me` response body so tests don't race on `/tmp/auth-check.json`. |

Side-effect files (written to CWD regardless of mode):

| File                | Contents                                       | When written           |
| ------------------- | ---------------------------------------------- | ---------------------- |
| `.auth_tokens.json` | Real (refreshed) payload **or** `"{}"` (mock).  | Always.                |
| `dmel.fa`           | 1 MB random dummy, only when auth invalid.       | Only in mock fallback. |

Side-effect `$GITHUB_OUTPUT` (always):

```
auth_valid=true|false
auth_reason<<EOF_REASON
…human-readable diagnostic…
EOF_REASON
auth_user=<userPrincipalName|"">
```

## Running the test suite

```
go test -v -count=1 ./scripts/validateauth/...
```

The suite has 14 table-driven subtests plus a `bash -n` syntax
check. Total runtime is ~0.4 s with no network. Each subtest:

1. Builds a JSON secret via `mkSecret(...)`.
2. Spawns `bash scripts/validate-auth.sh` in `t.TempDir()` with the
   per-test env wired up.
3. Asserts `(auth_valid, auth_reason, ONEDRIVER_MOCK, dmel.fa,
   .auth_tokens.json)` against expectations.

Per-test env (`GITHUB_OUTPUT`, `GITHUB_ENV`,
`VALIDATE_AUTH_FIXTURES_DIR`, `VALIDATE_AUTH_BODY_FILE`,
`VALIDATE_AUTH_NOW`) is fully isolated — if you later add
`t.Parallel()` calls inside the loop, the suite will remain safe
under `go test -parallel N …`. The subtests call no `t.Parallel()`
today, so concurrency is off by default.

## Invoking the script locally

```bash
# Step 1: put a real-looking secret in your env.
export ONEDRIVER_AUTH_TOKENS=$(cat ~/.onedriver/auth_tokens.json)

# Step 2: invoke from the repo root so the relative writes
# (.auth_tokens.json, dmel.fa) land in the current directory.
cd /path/to/onedriver
bash scripts/validate-auth.sh

# Step 3: inspect the side effects.
echo "--- .auth_tokens.json ---"
cat .auth_tokens.json
echo "--- dmel.fa (or note its absence) ---"
ls -la dmel.fa 2>/dev/null || echo "(no dmel.fa → mock fallback fired)"
```

The script will read your secret, attempt the API check (and refresh
if needed), then either validate the token or fall back to mock
mode. Both modes print a human-readable summary to stdout.

## Adding a new test case

The pattern is: **(fixture files)** → **(map entry)** → **(case in
slice)**. Below is the concrete recipe; substitute your own scenario
name and JSON.

### Step 1 · Pick a scenario name

Use a snake_case identifier. Examples already in the suite:
`happy-refresh`, `failed-refresh`, `happy-me`, `rejected-me`,
`me-network-error`, `refresh-empty-access`. The same identifier
becomes the test subtest name.

### Step 2 · Create the fixture directory

If your scenario exercises the refresh path (expired token), put these
two files in `testdata/auth-fixtures/<scenario>/`:

```
refresh-body.json       # raw JSON body the fake server returns
refresh-status.txt      # HTTP status code as plain text (e.g. "400")
```

If your scenario exercises the `/me` path (non-expired token),
use:

```
me-body.json            # raw JSON body the fake /me returns
me-status.txt           # HTTP status code, e.g. "401"
```

The fixture directory may contain only the files needed by the
branch under test — empty directories are fine if unused.

### Step 3 · Register the scenario in the fixtures map

In `validateauth_test.go`, add an entry to the `builtinFixtures`
map:

```go
var builtinFixtures = map[string]string{
    // …existing entries…
    "your-scenario": "your-scenario", // ← add this
}
```

The key is what you'll pass via `fixtures:` in the test case; the
value is the directory basename under
`testdata/auth-fixtures/`. (They're equal here, but you can
alias them if you want a shorter test-side name.)

### Step 4 · Add a case to the slice

Append a new struct to `cases` in `TestValidateAuthSh`:

```go
{
    name: "your_scenario_does_x",
    secretBuilder: func(t *testing.T) string {
        return mkSecret(t, secretOpts{
            AccessToken:  "at",
            RefreshToken: "rt",
            ExpiresAt:    fixedNOW - 60,    // expired   → refresh path
            // ExpiresAt: fixedNOW + 3600, // not expired → /me path
        })
    },
    fixtures:      "your-scenario",       // from builtinFixtures
    wantValid:     "false",               // or "true"
    wantReasonHas: "substring",           // substring of expected auth_reason
    wantMockEnv:   true,                  // ONEDRIVER_MOCK=1 in $GITHUB_ENV?
    wantDmelFa:    true,                  // dummy dmel.fa generated?
    wantTokensHas: "",                    // leave empty — see below
},
```

Notes on `wantTokensHas`:

- Empty string skips the substring check entirely.
- When `wantMockEnv` is true, the test *additionally* asserts that
  `strings.TrimSpace(.auth_tokens.json) == "{}"` — that's the
  mock-mode literal payload and is verified separately from the
  `wantTokensHas` substring.
- Set a non-empty value only when you want a positive substring
  match (typically `"at-good"` after a successful `/me`, or the
  fixture's `access_token` value after a successful refresh).

For the full list of fields accepted by `mkSecret`, see the
`secretOpts` struct in `validateauth_test.go`
(`AccessToken`, `RefreshToken`, `ExpiresAt`, `Account`,
`OmitAccess`). The exact `wantValid` / `wantReasonHas` /
`wantMockEnv` triple you should use depends on which branch you
want to exercise — see the existing cases for analogues.

### Step 5 · Run the new case

First, the targeted run to confirm your case behaves correctly:

```
go test -v -count=1 -run 'TestValidateAuthSh/your_scenario' ./scripts/...
```

**Then run the full suite** — a typo in `"your-scenario"` or a slice
entry that mis-spells one of the `want*` fields can silently break
sibling cases without failing the targeted run:

```
go test -v -count=1 ./scripts/validateauth/...
```

If it fails, read the diff between `want*` and the actual
`GITHUB_OUTPUT_FILE` content printed by the assertion; the script
is black-box at this layer so the assertion messages are the
fastest path to fixing the case.

## Adding a brand-new path to the script

If you're fixing a bug or adding a new branch (e.g. *"token from a
different tenant requires a different tenant ID"*):

1. Add the logic to `scripts/validate-auth.sh` with new env-var
   hooks if needed; update the contract doc-comment at the top of
   the file.
2. Add a new test case as above.
3. If the test fails in CI but passes locally, suspect
   `testdata/` files not tracked by git — see the troubleshooting
   section below.

## Troubleshooting

### Test passes locally, fails in CI

`scripts/validateauth/testdata/auth-fixtures/*.json` and `*.txt` are
git-tracked via the negation block at the bottom of `.gitignore`.
Double-check with:

```
git check-ignore -v scripts/validateauth/testdata/auth-fixtures/<name>/<file>
```

If the output is non-empty, the file is being ignored. The fix is to
add a corresponding `!…` line to `.gitignore`, or simply to
`git add -f` the file.

### `/tmp/INJECTION_FIRED` exists between test runs

The `shell_injection_safe_on_malicious_secret` case asserts that
`/tmp/INJECTION_FIRED` was NOT created by the script (i.e. the
malicious `$(touch …)`, backtick, and `;` payloads in the secret
were never executed by the shell). The *test* (not the bash
script) pre-cleans the file via `_ = os.Remove(...)` and registers
`t.Cleanup` to remove it again after the assertion, so the
"is the file present?" check is reliable across runs. If the file
still shows up after a test runs, an actual shell-injection
regression has been introduced.

Manual cleanup if needed:

```
rm -f /tmp/INJECTION_FIRED
```

### Failure message reads "refresh failed (: )" / "validated against
Microsoft Graph (user: unknown)"

This is the canonical signature of a *missing fixture file*: the
script falls through to `|| echo ""` / `|| echo "200"` defaults, so
the REFRESH_RESP is empty and the /me check returns 200 with an
empty body. Verify:

1. The fixture file exists at the expected path
   (`testdata/auth-fixtures/<scenario>/<file>`).
2. The file is tracked (`git ls-files --error-unmatch …`).
3. The script's `VALIDATE_AUTH_FIXTURES_DIR` env var points to the
   parent directory of the scenario, not the scenario itself.

### Want to trace what the script sees

Run it manually with `bash -x`:

```
bash -x scripts/validate-auth.sh
```

Every variable substitution and `cat` invocation will be echoed.
Combine with `VALIDATE_AUTH_FIXTURES_DIR=…` to exercise a specific
scenario.

## CI integration

The workflow runs:

1. `go test -v -count=1 ./scripts/...` first (this suite).
2. `bash scripts/validate-auth.sh` with the
   `ONEDRIVER_AUTH_TOKENS` secret set from
   `${{ secrets.ONEDRIVER_AUTH_TOKENS }}`.

If the unit-test step fails, the workflow aborts before exercising
the real script — so a regression here *prevents* a misleading
flaky CI run, rather than masking it.

## Limitations

- Assumes a POSIX `bash`, GNU `date -u -d @…`, `jq`, and `curl`.
  All four are present in the CI container but a developer on
  macOS or Alpine will need to substitute BSD-equivalents or use
  `brew install coreutils jq curl bash`.
- The script writes `.auth_tokens.json` to CWD — running it from a
  directory you don't own will fail at the post-mock-fallback
  `dd if=/dev/urandom of=dmel.fa` step.
- The script does not attempt destructive operations (it never
  deletes `.auth_tokens.json` or rotates secrets by itself); it
  only augments or replaces them.
