package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Tests for GraphURL validation (Phase 1)
// ============================================================================

func TestSetGraphURL_ValidHTTPS(t *testing.T) {
	t.Parallel()
	original := GetGraphURL()
	defer SetGraphURL(original)

	err := SetGraphURL("https://graph.microsoft.com/v1.0")
	assert.NoError(t, err)
	assert.Equal(t, "https://graph.microsoft.com/v1.0", GetGraphURL())
}

func TestSetGraphURL_HTTPAllowedForLocalhost(t *testing.T) {
	t.Parallel()
	original := GetGraphURL()
	defer SetGraphURL(original)

	err := SetGraphURL("http://localhost:8080")
	assert.NoError(t, err, "HTTP should be allowed for localhost")
}

func TestSetGraphURL_HTTPAllowedFor127(t *testing.T) {
	t.Parallel()
	original := GetGraphURL()
	defer SetGraphURL(original)

	err := SetGraphURL("http://127.0.0.1:8080")
	assert.NoError(t, err, "HTTP should be allowed for 127.0.0.1")
}

func TestSetGraphURL_HTTPRejectedForExternalHost(t *testing.T) {
	t.Parallel()
	original := GetGraphURL()
	defer SetGraphURL(original)

	err := SetGraphURL("http://malicious.com/api")
	assert.Error(t, err, "HTTP should be rejected for external hosts")
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestSetGraphURL_InvalidURL(t *testing.T) {
	t.Parallel()
	original := GetGraphURL()
	defer SetGraphURL(original)

	err := SetGraphURL("not-a-valid-url")
	assert.Error(t, err)
}

// ============================================================================
// Tests for GraphError (Phase 1)
// ============================================================================

func TestGraphError_Error(t *testing.T) {
	t.Parallel()
	err := &GraphError{
		StatusCode: 404,
		Code:       "itemNotFound",
		Message:    "The specified item could not be found",
	}
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "itemNotFound")
}

func TestGraphError_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = &GraphError{
		StatusCode: 401,
		Code:       "unauthenticated",
		Message:    "Access token is missing",
	}
	assert.NotNil(t, err)
}

func TestGraphError_Unwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("network timeout")
	err := &GraphError{
		StatusCode: 504,
		Code:       "timeout",
		Message:    "Gateway timeout",
		Cause:      cause,
	}
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestGraphError_Is(t *testing.T) {
	t.Parallel()
	err := &GraphError{StatusCode: 404, Code: "itemNotFound"}
	target := &GraphError{StatusCode: 404}
	assert.True(t, errors.Is(err, target))
}

// ============================================================================
// Tests for IsOffline (Phase 1)
// ============================================================================

func TestIsOffline_NilError(t *testing.T) {
	t.Parallel()
	assert.False(t, IsOffline(nil))
}

func TestIsOffline_GraphError(t *testing.T) {
	t.Parallel()
	err := &GraphError{StatusCode: 404, Code: "itemNotFound"}
	assert.False(t, IsOffline(err), "GraphError means we're online")
}

func TestIsOffline_NetworkError(t *testing.T) {
	t.Parallel()
	err := errors.New("dial tcp: lookup graph.microsoft.com: no such host")
	assert.True(t, IsOffline(err), "DNS failure should indicate offline")
}

func TestIsOffline_TimeoutError(t *testing.T) {
	t.Parallel()
	err := errors.New("net/http: request canceled (Client.Timeout exceeded)")
	assert.True(t, IsOffline(err), "Timeout should indicate offline")
}

// ============================================================================
// Tests for Request function (Phase 2)
// ============================================================================

// setupMockServer creates a test server that simulates Graph API responses
func setupMockServer(t *testing.T) (*httptest.Server, *Auth) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/me" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"userPrincipalName": "test@example.com",
			})

		case r.URL.Path == "/me/drive" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        "test-drive-id",
				"driveType": "personal",
			})

		case r.URL.Path == "/test-error-404":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "itemNotFound",
					"message": "Item not found",
				},
			})

		case r.URL.Path == "/test-error-500":
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "generalException",
					"message": "Internal server error",
				},
			})

		case r.URL.Path == "/test-error-401":
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "unauthenticated",
					"message": "Access token is missing or invalid",
				},
			})

		case r.URL.Path == "/test-large-response":
			// Send a response larger than maxResponseSize
			w.Header().Set("Content-Type", "application/octet-stream")
			largeData := make([]byte, 150*1024*1024) // 150 MB
			w.Write(largeData)

		case r.URL.Path == "/test-echo" && r.Method == "POST":
			// Echo back the request body
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)

		case r.URL.Path == "/test-check-auth":
			// Check that Authorization header is correct
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Authorization header must use 'Bearer' (capitalized)",
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		default:
			http.NotFound(w, r)
		}
	}))

	// Configure GraphURL to use mock server
	original := GetGraphURL()
	SetGraphURL(server.URL)
	t.Cleanup(func() {
		server.Close()
		SetGraphURL(original)
	})

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	return server, auth
}

func TestRequest_SuccessfulGet(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	resp, err := Get(ctx, "/me", auth)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var user User
	err = json.Unmarshal(resp, &user)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", user.UserPrincipalName)
}

func TestRequest_404ReturnsGraphError(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	_, err := Get(ctx, "/test-error-404", auth)
	assert.Error(t, err)

	var graphErr *GraphError
	assert.True(t, errors.As(err, &graphErr))
	assert.Equal(t, 404, graphErr.StatusCode)
	assert.Equal(t, "itemNotFound", graphErr.Code)
}

func TestRequest_500ReturnsGraphError(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	_, err := Get(ctx, "/test-error-500", auth)
	assert.Error(t, err)

	var graphErr *GraphError
	assert.True(t, errors.As(err, &graphErr))
	assert.Equal(t, 500, graphErr.StatusCode)
}

func TestRequest_ContextCancellation(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	_, err := Get(ctx, "/me", auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestRequest_ContextTimeout(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Wait for timeout

	_, err := Get(ctx, "/me", auth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestRequest_LargeResponseLimited(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	// This should fail because response exceeds maxResponseSize
	_, err := Get(ctx, "/test-large-response", auth)
	assert.Error(t, err)
	// The error should indicate the response was too large
}

func TestRequest_PostWithBody(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	body := map[string]string{"test": "data"}
	bodyBytes, _ := json.Marshal(body)

	resp, err := Post(ctx, "/test-echo", auth, bytes.NewReader(bodyBytes))
	assert.NoError(t, err)

	var result map[string]string
	err = json.Unmarshal(resp, &result)
	assert.NoError(t, err)
	assert.Equal(t, "data", result["test"])
}

func TestRequest_BearerTokenCapitalized(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	// This endpoint checks that Authorization header uses "Bearer" (capitalized)
	resp, err := Get(ctx, "/test-check-auth", auth)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestRequest_EmptyAuth(t *testing.T) {
	_, _ = setupMockServer(t)
	ctx := context.Background()

	emptyAuth := &Auth{}
	_, err := Get(ctx, "/me", emptyAuth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty auth")
}

func TestRequest_NilAuth(t *testing.T) {
	_, _ = setupMockServer(t)
	ctx := context.Background()

	_, err := Get(ctx, "/me", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty auth")
}

// ============================================================================
// Tests for connection pooling (Phase 2)
// ============================================================================

func TestRequest_ConnectionPooling(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	// Make multiple requests - they should reuse connections
	for i := 0; i < 5; i++ {
		resp, err := Get(ctx, "/me", auth)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	}

	// Verify that httpClient is shared (not created per request)
	assert.NotNil(t, httpClient)
	assert.NotNil(t, httpClient.Transport)
}

// ============================================================================
// Tests for helper functions
// ============================================================================

func TestIsValidHTTPMethod(t *testing.T) {
	t.Parallel()

	validMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for _, method := range validMethods {
		assert.True(t, isValidHTTPMethod(method), "%s should be valid", method)
	}

	invalidMethods := []string{"OPTIONS", "HEAD", "TRACE", "CONNECT", "INVALID"}
	for _, method := range invalidMethods {
		assert.False(t, isValidHTTPMethod(method), "%s should be invalid", method)
	}
}

func TestIsValidHTTPMethod_CaseInsensitive(t *testing.T) {
	t.Parallel()

	assert.True(t, isValidHTTPMethod("get"))
	assert.True(t, isValidHTTPMethod("post"))
	assert.True(t, isValidHTTPMethod("PUT"))
}

func TestResourcePath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/me/drive/root", ResourcePath("/"))
	assert.Equal(t, "/me/drive/root:%2Fsome%20path", ResourcePath("/some path"))
}

func TestIDPath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/me/drive/root", IDPath("root"))
	assert.Equal(t, "/me/drive/items/test-id", IDPath("test-id"))
}

// ============================================================================
// Integration test with mock server
// ============================================================================

func TestGetUser_WithMockServer(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	user, err := GetUser(ctx, auth)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", user.UserPrincipalName)
}

func TestGetDrive_WithMockServer(t *testing.T) {
	_, auth := setupMockServer(t)
	ctx := context.Background()

	drive, err := GetDrive(ctx, auth)
	assert.NoError(t, err)
	assert.Equal(t, "test-drive-id", drive.ID)
	assert.Equal(t, "personal", drive.DriveType)
}
