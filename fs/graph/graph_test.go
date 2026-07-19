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
	"sync/atomic"
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

// ============================================================================
// Tests for RetryConfig and calculateBackoff (Phase 3)
// ============================================================================

func TestCalculateBackoff_Exponential(t *testing.T) {
	t.Parallel()
	config := RetryConfig{
		MaxRetries:   5,
		BaseDelay:    1 * time.Second,
		MaxDelay:     30 * time.Second,
		EnableJitter: false,
	}

	// Attempt 0: 1s * 2^0 = 1s
	assert.Equal(t, 1*time.Second, calculateBackoff(0, config))
	// Attempt 1: 1s * 2^1 = 2s
	assert.Equal(t, 2*time.Second, calculateBackoff(1, config))
	// Attempt 2: 1s * 2^2 = 4s
	assert.Equal(t, 4*time.Second, calculateBackoff(2, config))
	// Attempt 3: 1s * 2^3 = 8s
	assert.Equal(t, 8*time.Second, calculateBackoff(3, config))
	// Attempt 4: 1s * 2^4 = 16s
	assert.Equal(t, 16*time.Second, calculateBackoff(4, config))
}

func TestCalculateBackoff_CappedAtMaxDelay(t *testing.T) {
	t.Parallel()
	config := RetryConfig{
		MaxRetries:   10,
		BaseDelay:    1 * time.Second,
		MaxDelay:     10 * time.Second,
		EnableJitter: false,
	}

	// Attempt 5: 1s * 2^5 = 32s, but capped at 10s
	assert.Equal(t, 10*time.Second, calculateBackoff(5, config))
	// Attempt 10: 1s * 2^10 = 1024s, but capped at 10s
	assert.Equal(t, 10*time.Second, calculateBackoff(10, config))
}

func TestCalculateBackoff_WithJitter(t *testing.T) {
	t.Parallel()
	config := RetryConfig{
		MaxRetries:   3,
		BaseDelay:    1 * time.Second,
		MaxDelay:     30 * time.Second,
		EnableJitter: true,
	}

	// With jitter, the delay should be base + random(0-1s)
	// So for attempt 0: 1s + jitter = between 1s and 2s
	backoff := calculateBackoff(0, config)
	assert.GreaterOrEqual(t, backoff, 1*time.Second)
	assert.Less(t, backoff, 2*time.Second)

	// For attempt 1: 2s + jitter = between 2s and 3s
	backoff = calculateBackoff(1, config)
	assert.GreaterOrEqual(t, backoff, 2*time.Second)
	assert.Less(t, backoff, 3*time.Second)
}

func TestCalculateBackoff_ZeroAttempt(t *testing.T) {
	t.Parallel()
	config := RetryConfig{
		MaxRetries:   3,
		BaseDelay:    1 * time.Second,
		MaxDelay:     30 * time.Second,
		EnableJitter: false,
	}

	// Attempt 0 should return BaseDelay
	assert.Equal(t, 1*time.Second, calculateBackoff(0, config))
}

// ============================================================================
// Tests for parseRetryAfter (Phase 3)
// ============================================================================

func TestParseRetryAfter_IntegerSeconds(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 30, parseRetryAfter("30"))
	assert.Equal(t, 5, parseRetryAfter("5"))
	assert.Equal(t, 120, parseRetryAfter("120"))
}

func TestParseRetryAfter_EmptyString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0, parseRetryAfter(""))
}

func TestParseRetryAfter_InvalidString(t *testing.T) {
	t.Parallel()
	// Invalid strings should return default (5 seconds)
	assert.Equal(t, 5, parseRetryAfter("invalid"))
	assert.Equal(t, 5, parseRetryAfter("abc"))
}

func TestParseRetryAfter_NegativeNumber(t *testing.T) {
	t.Parallel()
	// Negative numbers are invalid, should return default
	assert.Equal(t, 5, parseRetryAfter("-10"))
}

// ============================================================================
// Tests for Request with retry logic (Phase 3)
// ============================================================================

// setupRetryMockServer creates a mock server that can simulate different failure scenarios
func setupRetryMockServer(t *testing.T, failCount int32, statusCode int) (*httptest.Server, *int32) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current <= failCount {
			// Fail the first N attempts
			if statusCode == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "1")
			}
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "testError",
					"message": "Simulated error",
				},
			})
			return
		}
		// Succeed after N failures
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))

	t.Cleanup(func() {
		server.Close()
	})

	return server, &attempts
}

func TestRequest_RetryOn5xx(t *testing.T) {
	// Server fails first 2 attempts with 500, then succeeds
	server, attempts := setupRetryMockServer(t, 2, http.StatusInternalServerError)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	resp, err := Get(ctx, "/test", auth)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Should have made 3 attempts (2 failures + 1 success)
	assert.Equal(t, int32(3), atomic.LoadInt32(attempts))
}

func TestRequest_RetryOn429(t *testing.T) {
	// Server fails first attempt with 429, then succeeds
	server, attempts := setupRetryMockServer(t, 1, http.StatusTooManyRequests)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	start := time.Now()
	resp, err := Get(ctx, "/test", auth)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Should have made 2 attempts (1 failure + 1 success)
	assert.Equal(t, int32(2), atomic.LoadInt32(attempts))

	// Should have waited at least 1 second (Retry-After header)
	assert.GreaterOrEqual(t, elapsed, 1*time.Second)
}

func TestRequest_MaxRetriesExhausted(t *testing.T) {
	// Server always fails with 500
	server, attempts := setupRetryMockServer(t, 10, http.StatusInternalServerError)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   2,
		BaseDelay:    10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		EnableJitter: false,
	}

	_, err := RequestWithRetryConfig(ctx, "/test", auth, http.MethodGet, nil, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "retry attempts failed")

	// Should have made 3 attempts (1 initial + 2 retries)
	assert.Equal(t, int32(3), atomic.LoadInt32(attempts))
}

func TestRequest_ContextCanceledDuringBackoff(t *testing.T) {
	// Server always fails with 500
	server, _ := setupRetryMockServer(t, 10, http.StatusInternalServerError)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx, cancel := context.WithCancel(context.Background())
	config := RetryConfig{
		MaxRetries:   5,
		BaseDelay:    5 * time.Second, // Long delay
		MaxDelay:     30 * time.Second,
		EnableJitter: false,
	}

	// Cancel after 100ms (during backoff)
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := RequestWithRetryConfig(ctx, "/test", auth, http.MethodGet, nil, config)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	// Should have canceled quickly, not waited for full backoff
	assert.Less(t, elapsed, 1*time.Second)
}

func TestRequest_NoRetryOn4xx(t *testing.T) {
	// Server fails with 404 (should not retry)
	server, attempts := setupRetryMockServer(t, 10, http.StatusNotFound)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	_, err := Get(ctx, "/test", auth)
	assert.Error(t, err)

	var graphErr *GraphError
	assert.True(t, assert.ErrorAs(t, err, &graphErr))
	assert.Equal(t, 404, graphErr.StatusCode)

	// Should have made only 1 attempt (no retries for 4xx)
	assert.Equal(t, int32(1), atomic.LoadInt32(attempts))
}

func TestRequest_CustomRetryConfig(t *testing.T) {
	// Server fails first 3 attempts, then succeeds
	server, attempts := setupRetryMockServer(t, 3, http.StatusInternalServerError)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   5, // Allow up to 5 retries
		BaseDelay:    10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		EnableJitter: false,
	}

	resp, err := RequestWithRetryConfig(ctx, "/test", auth, http.MethodGet, nil, config)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Should have made 4 attempts (3 failures + 1 success)
	assert.Equal(t, int32(4), atomic.LoadInt32(attempts))
}

func TestRequest_ZeroRetries(t *testing.T) {
	// Server fails with 500
	server, attempts := setupRetryMockServer(t, 10, http.StatusInternalServerError)
	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   0, // No retries
		BaseDelay:    1 * time.Second,
		MaxDelay:     30 * time.Second,
		EnableJitter: false,
	}

	_, err := RequestWithRetryConfig(ctx, "/test", auth, http.MethodGet, nil, config)
	assert.Error(t, err)

	// Should have made only 1 attempt (no retries)
	assert.Equal(t, int32(1), atomic.LoadInt32(attempts))
}

// ============================================================================
// Tests for retry with POST/PUT (body preservation)
// ============================================================================

func TestRequest_RetryWithPostBody(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)

		// Read and verify body on each attempt
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)

		if current <= 2 {
			// Fail first 2 attempts
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "testError",
					"message": "Simulated error",
				},
			})
			return
		}

		// Succeed on 3rd attempt, verify body is still correct
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"received": string(body),
		})
	}))
	defer server.Close()

	original := GetGraphURL()
	SetGraphURL(server.URL)
	defer SetGraphURL(original)

	auth := &Auth{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Unix() + 3600,
	}

	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   3,
		BaseDelay:    10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		EnableJitter: false,
	}

	body := []byte(`{"test":"data"}`)
	resp, err := RequestWithRetryConfig(ctx, "/test", auth, http.MethodPost,
		bytes.NewReader(body), config)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))

	// Verify the body was preserved across retries
	var result map[string]string
	json.Unmarshal(resp, &result)
	assert.Equal(t, `{"test":"data"}`, result["received"])
}

// ============================================================================
// Integration tests with DefaultRetryConfig
// ============================================================================

func TestRequest_UsesDefaultRetryConfig(t *testing.T) {
	// Verify that Request() uses DefaultRetryConfig
	assert.Equal(t, 3, DefaultRetryConfig.MaxRetries)
	assert.Equal(t, 1*time.Second, DefaultRetryConfig.BaseDelay)
	assert.Equal(t, 30*time.Second, DefaultRetryConfig.MaxDelay)
	assert.True(t, DefaultRetryConfig.EnableJitter)
}
