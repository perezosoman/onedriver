package fs

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/jstaf/onedriver/fs/graph"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	mountLoc     = "mount"
	testDBLoc    = "tmp"
	TestDir      = mountLoc + "/onedriver_tests"
	DeltaDir     = TestDir + "/delta"
	retrySeconds = 60 * time.Second //lint:ignore ST1011 a
)

// checkValidAuthTokens verifies if .auth_tokens.json contains valid credentials
func checkValidAuthTokens(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn().Err(err).Msg("Could not read auth tokens file")
		return false
	}

	// Check if file is empty or just "{}"
	content := strings.TrimSpace(string(data))
	if content == "" || content == "{}" {
		log.Warn().Msg("Auth tokens file is empty or contains only empty JSON")
		return false
	}

	// Basic check - valid tokens should have more content
	if len(content) < 50 {
		log.Warn().Msgf("Auth tokens file seems invalid (too short: %d bytes)", len(content))
		return false
	}

	return true
}

// requireAuth skips the test if OneDrive authentication is not available
func requireAuth(t *testing.T) {
	if skipAuthTests {
		t.Skip("Skipping test - OneDrive credentials not available (expected in CI without AWS S3)")
	}
}

var (
	auth          *graph.Auth
	fs            *Filesystem
	hasValidAuth  bool // flag to track if we have valid OneDrive credentials
	skipAuthTests bool // flag to skip tests requiring OneDrive
)

// Tests are done in the main project directory with a mounted filesystem to
// avoid having to repeatedly recreate auth_tokens.json and juggle multiple auth
// sessions.
func TestMain(m *testing.M) {
	// determine if we're running a single test in vscode or something
	var singleTest bool
	for _, arg := range os.Args {
		if strings.Contains(arg, "-test.run") {
			singleTest = true
		}
	}

	os.Chdir("..")
	// attempt to unmount regardless of what happens (in case previous tests
	// failed and didn't clean themselves up)
	exec.Command("fusermount3", "-uz", mountLoc).Run()
	os.Mkdir(mountLoc, 0755)
	// wipe all cached data from previous tests
	os.RemoveAll(testDBLoc)
	os.Mkdir(testDBLoc, 0755)

	f, _ := os.OpenFile("fusefs_tests.log", os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: f, TimeFormat: "15:04:05"})
	defer f.Close()

	// Check if we have valid auth tokens before attempting to authenticate
	authTokenPath := ".auth_tokens.json"
	hasValidAuth = checkValidAuthTokens(authTokenPath)

	if !hasValidAuth {
		// In CI or mock mode: skip tests that need auth (no interactive login)
		if os.Getenv("CI") == "1" || os.Getenv("ONEDRIVER_MOCK") == "1" {
			log.Warn().Msg("⚠️  No valid OneDrive credentials found - tests requiring OneDrive will be skipped")
			log.Warn().Msg("This is expected in CI environments without AWS S3 access")
			skipAuthTests = true
			fmt.Println("⚠️  Running in offline mode - OneDrive-dependent tests will be skipped")
			code := m.Run()
			os.Exit(code)
		}
		// Local mode: let Authenticate() show the OAuth dialog to obtain credentials
		fmt.Println("No credentials found — starting OAuth flow to obtain them...")
	}

	auth = graph.Authenticate(graph.AuthConfig{}, authTokenPath, false)
	fs = NewFilesystem(auth, filepath.Join(testDBLoc, "test"))
	server, _ := fuse.NewServer(
		fs,
		mountLoc,
		&fuse.MountOptions{
			Name:          "onedriver",
			FsName:        "onedriver",
			DisableXAttrs: true,
			MaxBackground: 1024,
		},
	)

	// setup sigint handler for graceful unmount on interrupt/terminate
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
	go UnmountHandler(sigChan, server)

	// mount fs in background thread
	go server.Serve()

	// cleanup from last run
	log.Info().Msg("Setup test environment ---------------------------------")
	if err := os.RemoveAll(TestDir); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Mkdir(TestDir, 0755)
	os.Mkdir(DeltaDir, 0755)

	// create paging test files before the delta thread is created
	if !singleTest {
		os.Mkdir(filepath.Join(TestDir, "paging"), 0755)
		createPagingTestFiles()
	}
	go fs.DeltaLoop(5 * time.Second)

	// not created by default on onedrive for business
	os.Mkdir(mountLoc+"/Documents", 0755)

	// we do not cd into the mounted directory or it will hang indefinitely on
	// unmount with "device or resource busy"
	log.Info().Msg("Test session start ---------------------------------")

	// run tests
	code := m.Run()

	log.Info().Msg("Test session end -----------------------------------")
	fmt.Printf("Waiting 5 seconds for any remaining uploads to complete")
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		fmt.Printf(".")
	}
	fmt.Printf("\n")

	// unmount
	if server.Unmount() != nil {
		log.Error().Msg("Failed to unmount test fuse server, attempting lazy unmount")
		exec.Command("fusermount3", "-zu", "mount").Run()
	}
	fmt.Println("Successfully unmounted fuse server!")
	os.Exit(code)
}

// Apparently 200 reqests is the default paging limit.
// Upload at least this many for a later test before the delta thread is created.
func createPagingTestFiles() {
	fmt.Println("Setting up paging test files.")
	var group sync.WaitGroup
	var errCounter int64
	for i := 0; i < 250; i++ {
		group.Add(1)
		go func(n int, wg *sync.WaitGroup) {
			_, err := graph.Put(
				graph.ResourcePath(fmt.Sprintf("/onedriver_tests/paging/%d.txt", n))+":/content",
				auth,
				strings.NewReader("test\n"),
			)
			if err != nil {
				log.Error().Err(err).Msg("Paging upload fail.")
				atomic.AddInt64(&errCounter, 1)
			}
			wg.Done()
		}(i, &group)
	}
	group.Wait()
	log.Info().Msgf("%d failed paging uploads.\n", errCounter)
	fmt.Println("Finished with paging test setup.")
}
