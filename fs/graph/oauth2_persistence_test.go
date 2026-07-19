package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// TestToFile_RefreshTokenPersistedOnDisk is the regression test for the bug
// reported as: "Al hacer make test por primera vez, .auth_tokens.json se
// genera pero sin refresh_token".
//
// Auth.ToFile() historically delegated refresh_token persistence entirely
// to the system keyring and stripped it from the disk JSON. In environments
// without a working secret-service (no DBus, headless containers, fresh
// sandboxed test runs) the keyring.Set call failed silently and the JSON
// was written without refresh_token, breaking every subsequent refresh
// attempt and forcing a full interactive reauthentication each run.
//
// The fix makes the disk JSON the canonical persistence layer and the
// keyring a defense-in-depth copy. This test asserts the disk contract
// directly by inspecting the JSON written by ToFile(), regardless of
// whether the keyring write succeeded.
func TestToFile_RefreshTokenPersistedOnDisk(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "auth_tokens.json")

	auth := Auth{
		AccessToken:  "fake-access-token-abc123",
		RefreshToken: "fake-refresh-token-xyz789",
		ExpiresAt:    time.Now().Unix() + 3600,
		Account:      "test@example.onmicrosoft.com",
		AuthConfig: AuthConfig{
			ClientID:    "fake-client-id",
			TokenURL:    "https://example.invalid/token",
			CodeURL:     "https://example.invalid/authorize",
			RedirectURL: "https://example.invalid/redirect",
		},
	}

	// Best-effort cleanup of any keyring entry written during the test.
	// We deliberately do not fail the test if keyring.Delete fails —
	// the disk persistence we are testing does not depend on keyring.
	t.Cleanup(func() {
		_ = keyring.Delete("onedriver", tmpFile)
	})

	require.NoError(t, auth.ToFile(tmpFile))

	contents, err := os.ReadFile(tmpFile)
	require.NoError(t, err, "auth file must be written to disk")
	require.NotEmpty(t, contents, "auth file must not be empty")

	var got map[string]any
	require.NoError(t, json.Unmarshal(contents, &got),
		"auth file must be valid JSON, got: %s", string(contents))

	rt, ok := got["refresh_token"].(string)
	if assert.Truef(t, ok,
		"refresh_token must be present in %s (got JSON keys: %v)",
		tmpFile, got) {
		assert.Equal(t, "fake-refresh-token-xyz789", rt,
			"refresh_token value must match what was passed to ToFile()")
	}

	at, ok := got["access_token"].(string)
	if assert.True(t, ok, "access_token must be present in %s", tmpFile) {
		assert.Equal(t, "fake-access-token-abc123", at)
	}

	// File mode must remain 0600 so refresh_token on plaintext disk is
	// owner-only — preserves the security level of the keyring model.
	info, err := os.Stat(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"auth file must be owner-only readable (0600)")
}

// TestToFile_EmptyRefreshTokenBehaviour documents that an Auth struct
// without a refresh_token (e.g. an initial auth round-trip that the
// server declined to give one to) still produces a parseable, well-formed
// JSON, with refresh_token explicitly set to the empty string.
func TestToFile_EmptyRefreshTokenBehaviour(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "auth_tokens.json")

	auth := Auth{
		AccessToken: "fake-access-token",
		// RefreshToken intentionally empty:
		RefreshToken: "",
		ExpiresAt:    time.Now().Unix() + 3600,
		AuthConfig: AuthConfig{
			ClientID:    "fake-client-id",
			TokenURL:    "https://example.invalid/token",
			CodeURL:     "https://example.invalid/authorize",
			RedirectURL: "https://example.invalid/redirect",
		},
	}

	t.Cleanup(func() {
		_ = keyring.Delete("onedriver", tmpFile)
	})

	require.NoError(t, auth.ToFile(tmpFile))

	contents, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// refresh_token field is present in the JSON (even if empty string),
	// which lets the consumer know the key existed but was empty rather
	// than inferring absence-as-error.
	assert.Contains(t, string(contents), `"refresh_token":""`,
		"empty refresh_token should serialise as an explicit empty field, got: %s",
		string(contents))
}
