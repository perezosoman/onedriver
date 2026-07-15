package graph

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// hasValidAuthTokens verifies if .auth_tokens.json contains valid credentials
func hasValidAuthTokens(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	content := strings.TrimSpace(string(data))
	if content == "" || content == "{}" || len(content) < 50 {
		return false
	}

	return true
}

// AuthAvailable is set by TestMain and indicates whether valid OneDrive
// credentials were found. Tests that require authentication should call
// t.Skip() when this is false.
var AuthAvailable bool

func TestMain(m *testing.M) {
	os.Chdir("../..")
	f, _ := os.OpenFile("fusefs_tests.log", os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: f, TimeFormat: "15:04:05"})
	defer f.Close()

	// Check if we have valid auth tokens
	authTokenPath := ".auth_tokens.json"
	if hasValidAuthTokens(authTokenPath) {
		AuthAvailable = true
		auth := Authenticate(AuthConfig{}, authTokenPath, false)
		user, _ := GetUser(auth)
		drive, _ := GetDrive(auth)
		log.Info().
			Str("account", user.UserPrincipalName).
			Str("type", drive.DriveType).
			Msg("Starting tests")
	} else {
		fmt.Println("⚠️  OneDrive credentials not available — authenticated tests will be skipped")
	}

	os.Exit(m.Run())
}
