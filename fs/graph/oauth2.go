package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dario.cat/mergo"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// these are default values if not specified
const (
	authClientID    = "3470c3fa-bc10-45ab-a0a9-2d30836485d1"
	authCodeURL     = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	authTokenURL    = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	authRedirectURL = "https://login.live.com/oauth20_desktop.srf"
)

func (a *AuthConfig) applyDefaults() error {
	return mergo.Merge(a, AuthConfig{
		ClientID:    authClientID,
		CodeURL:     authCodeURL,
		TokenURL:    authTokenURL,
		RedirectURL: authRedirectURL,
	})
}

// AuthConfig configures the authentication flow
type AuthConfig struct {
	ClientID    string `json:"clientID" yaml:"clientID"`
	CodeURL     string `json:"codeURL" yaml:"codeURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`
}

// Auth represents a set of oauth2 authentication tokens
type Auth struct {
	AuthConfig   `json:"config"`
	Account      string `json:"account"`
	ExpiresIn    int64  `json:"expires_in"` // only used for parsing
	ExpiresAt    int64  `json:"expires_at"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	path         string // auth tokens remember their path for use by Refresh()
}

// AuthError is an authentication error from the Microsoft API. Generally we don't see
// these unless something goes catastrophically wrong with Microsoft's authentication
// services.
type AuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	ErrorURI         string `json:"error_uri"`
	Timestamp        string `json:"timestamp"` // json.Unmarshal doesn't like this timestamp format
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
}

// ToFile writes auth tokens to a file.
//
// The refresh_token is best-effort ALSO written to the system keyring as
// defense-in-depth (when a desktop secret-service is available, this is
// strictly better than plaintext). However, it is ALWAYS also persisted
// on disk so that environments without a working keyring (no DBus
// session, headless container, CI runner, fresh SSH login) do not
// silently lose the refresh capability — historically this caused
// `make test` to generate a .auth_tokens.json with an empty
// refresh_token, forcing full re-authentication on every subsequent
// invocation.
//
// The disk JSON file is 0600 (owner-only read), matching the effective
// security level of the keyring for the same user. Keyring write
// failures are logged as warnings, never as errors — the disk copy is
// canonical for refresh purposes.
func (a Auth) ToFile(file string) error {
	a.path = file

	if a.RefreshToken != "" {
		// Route through keyringSetImpl so dbus-timeout hangs cannot block
		// the call (mirrors the keyringGetImpl timeout for reads).
		if err := keyringSetImpl(file, a.RefreshToken); err != nil {
			log.Warn().
				Err(err).
				Str("path", file).
				Msg("Failed to store refresh token in keyring; refresh_token will be sourced from disk on next load")
		}
	}

	byteData, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(file, byteData, 0600)
}

// FromFile populates an auth struct from a file
func (a *Auth) FromFile(file string) error {
	contents, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	a.path = file
	err = json.Unmarshal(contents, a)
	if err != nil {
		return err
	}

	// load refresh token from system keyring (fallback: keep whatever was in the JSON)
	// Skip keyring when running under go test or in mock mode — dbus may hang.
	// keyringGetImpl wraps the read in a 3-second timeout so a blackholed
	// dbus can never block token loading.
	if os.Getenv("ONEDRIVER_MOCK") != "1" && !isTestBinary() {
		if token, err := keyringGetImpl(file); err == nil && token != "" {
			a.RefreshToken = token
		}
	}
	return a.applyDefaults()
}

// isTestBinary returns true when the process is a test binary (go test).
func isTestBinary() bool {
	return strings.HasSuffix(os.Args[0], ".test") ||
		strings.Contains(os.Args[0], "/_test/") ||
		strings.HasPrefix(filepath.Base(os.Args[0]), "___")
}

// Refresh auth tokens if expired.
func (a *Auth) Refresh() {
	if a.ExpiresAt <= time.Now().Unix() {
		oldTime := a.ExpiresAt
		data := url.Values{
			"client_id":     {a.ClientID},
			"redirect_uri":  {a.RedirectURL},
			"refresh_token": {a.RefreshToken},
			"grant_type":    {"refresh_token"},
		}
		postData := strings.NewReader(data.Encode())
		resp, err := http.Post(a.TokenURL,
			"application/x-www-form-urlencoded",
			postData)

		var reauth bool
		if err != nil {
			if IsOffline(err) || resp == nil {
				log.Trace().Err(err).Msg("Network unreachable during token renewal, ignoring.")
				return
			}
			log.Error().Err(err).Msg("Could not POST to renew tokens, forcing reauth.")
			reauth = true
		} else {
			// put here so as to avoid spamming the log when offline
			log.Info().Msg("Auth tokens expired, attempting renewal.")
			// Close resp.Body only when we received a response. Guarded
			// because http.Post may return resp=nil with err!=nil in
			// certain malformed/redirect-loop scenarios; deferring
			// unconditionally would nil-deref the test binary.
			defer func() {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}()
		}

		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Warn().
				Err(readErr).
				Msg("Could not read token refresh response body; tokens remain stale")
			return
		}
		if err := json.Unmarshal(body, a); err != nil {
			// Could not parse the response body — likely a redirect HTML page
			// or a proxy error. Bail out immediately so silent fallback to
			// newAuth (or the manual "stale AccessToken carried forward"
			// trap that calls a.ToFile() with the original fields intact)
			// does not bite us.
			log.Warn().
				Err(err).
				Bytes("body", body).
				Msg("Could not parse token refresh response; tokens remain stale")
			return
		}
		if a.ExpiresAt == oldTime {
			a.ExpiresAt = time.Now().Unix() + a.ExpiresIn
		}

		if reauth || a.AccessToken == "" || a.RefreshToken == "" {
			log.Error().
				Bytes("response", body).
				Int("http_code", resp.StatusCode).
				Msg("Failed to renew access tokens. Attempting to reauthenticate.")
			// CRITICAL: do NOT prompt for interactive OAuth in CI or mock mode.
			// Such a prompt would block on stdin forever and time out the test
			// binary. In CI, callers should detect the stale token state and
			// either skip dependent work or fail fast. In mock mode, the test
			// harness expects a self-contained server-side refresh path.
			if os.Getenv("CI") != "" || os.Getenv("ONEDRIVER_MOCK") == "1" {
				log.Error().
					Msg("Refusing to trigger interactive reauth in CI/mock mode; tokens remain stale")
				return
			}
			a = newAuth(a.AuthConfig, a.path, false)
		} else {
			a.ToFile(a.path)
		}
	}
}

// Get the appropriate authentication URL for the Graph OAuth2 challenge.
func getAuthURL(a AuthConfig) string {
	return a.CodeURL +
		"?client_id=" + a.ClientID +
		"&scope=" + url.PathEscape("user.read files.readwrite.all offline_access") +
		"&response_type=code" +
		"&redirect_uri=" + url.QueryEscape(a.RedirectURL)
}

// getAuthCodeHeadless has the user perform authentication in their own browser
// instead of WebKit2GTK and then input the auth code in the terminal.
func getAuthCodeHeadless(a AuthConfig, accountName string) (string, error) {
	fmt.Printf("Please visit the following URL:\n%s\n\n", getAuthURL(a))
	fmt.Println("Please enter the redirect URL once you are redirected to a " +
		"blank page (after \"Let this app access your info?\"):")
	var response string
	fmt.Scanln(&response)
	code, err := parseAuthCode(response)
	if err != nil {
		return "", fmt.Errorf("no validation code returned, or code was invalid: %w", err)
	}
	return code, nil
}

// parseAuthCode is used to parse the auth code out of the redirect the server gives us
// after successful authentication
func parseAuthCode(authURL string) (string, error) {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	params := parsed.Query()
	return params.Get("code"), nil
}

// Exchange an auth code for a set of access tokens (returned as a new Auth struct).
func getAuthTokens(a AuthConfig, authCode string) *Auth {
	data := url.Values{
		"client_id":    {a.ClientID},
		"redirect_uri": {a.RedirectURL},
		"code":         {authCode},
		"grant_type":   {"authorization_code"},
	}
	postData := strings.NewReader(data.Encode())
	resp, err := http.Post(a.TokenURL,
		"application/x-www-form-urlencoded",
		postData)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not POST to obtain auth tokens.")
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal().
			Err(readErr).
			Int("status", resp.StatusCode).
			Msg("Could not read token endpoint response body")
	}
	var auth Auth
	if err := json.Unmarshal(body, &auth); err != nil {
		// Treat unparseable responses as fatal in initial auth: a partial
		// Auth struct would silently propagate empty AccessToken /
		// RefreshToken downstream and force users into an infinite
		// reauth loop.
		log.Error().
			Err(err).
			Int("status", resp.StatusCode).
			Bytes("response", body).
			Msg("Could not parse token endpoint response")
		log.Fatal().Msg("Failed to parse auth tokens. Authentication cannot continue.")
	}
	if auth.ExpiresAt == 0 {
		auth.ExpiresAt = time.Now().Unix() + auth.ExpiresIn
	}
	auth.AuthConfig = a

	if auth.AccessToken == "" || auth.RefreshToken == "" {
		var authErr AuthError
		var fields zerolog.Logger
		if err := json.Unmarshal(body, &authErr); err == nil {
			// we got a parseable error message out of microsoft's servers
			fields = log.With().
				Int("status", resp.StatusCode).
				Str("error", authErr.Error).
				Str("errorDescription", authErr.ErrorDescription).
				Str("helpUrl", authErr.ErrorURI).
				Logger()
		} else {
			// things are extra broken and this is an error type we haven't seen before
			fields = log.With().
				Int("status", resp.StatusCode).
				Bytes("response", body).
				Err(err).
				Logger()
		}
		fields.Fatal().Msg(
			"Failed to retrieve access tokens. Authentication cannot continue.",
		)
	}
	return &auth
}

// newAuth performs initial authentication flow and saves tokens to disk. The headless
// parameter determines if we will try to auth directly in the terminal instead of
// doing it via embedded browser.
func newAuth(config AuthConfig, path string, headless bool) *Auth {
	// load the old account name
	old := Auth{}
	old.FromFile(path)

	config.applyDefaults()
	var code string
	var err error
	if headless {
		code, err = getAuthCodeHeadless(config, old.Account)
	} else {
		// in a build without CGO, this will be the same as above
		code, err = getAuthCode(config, old.Account)
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Authentication failed. Please restart the application and try again.")
	}
	auth := getAuthTokens(config, code)

	if user, err := GetUser(context.Background(), auth); err == nil {
		auth.Account = user.UserPrincipalName
	}
	auth.ToFile(path)
	return auth
}

// Authenticate performs authentication to Graph or load auth/refreshes it
// from an existing file. If headless is true, we will authenticate in the
// terminal.
func Authenticate(config AuthConfig, path string, headless bool) *Auth {
	auth := &Auth{}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		// no tokens found, gotta start oauth flow from beginning
		auth = newAuth(config, path, headless)
	} else {
		// we already have tokens, no need to force a new auth flow
		auth.FromFile(path)
		auth.Refresh()
	}
	return auth
}
