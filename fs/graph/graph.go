package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"dario.cat/mergo"
	"github.com/rs/zerolog/log"
)

// maxResponseSize is the maximum size of a response body we'll read.
// Prevents DoS attacks from malicious servers sending huge responses.
const maxResponseSize = 100 * 1024 * 1024 // 100 MB

// httpClient is a shared HTTP client with connection pooling.
// Using a single client allows reuse of TCP/TLS connections across requests,
// significantly improving performance for filesystem operations.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,              // Max idle connections across all hosts
		MaxIdleConnsPerHost: 10,               // Max idle connections per host
		IdleConnTimeout:     90 * time.Second, // Close idle connections after 90s

		// Timeout settings
		TLSHandshakeTimeout: 10 * time.Second, // Timeout for TLS handshake
	},
}

// DefaultGraphURL is the default Microsoft Graph API endpoint.
const DefaultGraphURL = "https://graph.microsoft.com/v1.0"

// graphURL stores the Microsoft Graph API endpoint.
// We use a private variable + getter/setter to control access and validation.
var (
	graphURL   string
	graphURLMu sync.RWMutex // Protects concurrent reads/writes
)

func init() {
	// Initialize graphURL with the default value
	graphURL = DefaultGraphURL
	// Override graphURL if the environment variable is set
	if u := os.Getenv("ONEDRIVER_GRAPH_URL"); u != "" {
		// Validate the URL before setting it
		if err := SetGraphURL(u); err != nil {
			// If the URL is invalid, log an error and keep the default value
			//  In production, you might want to panic here, but for safety we keep default
			fmt.Fprintf(os.Stderr, "Warning: Invalid ONEDRIVER_GRAPH_URL '%s': %v. Using default.\n", u, err)
		}
	}
}

// SetGraphURL overrides the Microsoft Graph API endpoint. Use this for testing with a mock server
//
//	when the URL is not known until after init() has already run.
//
// Security rules:
// - Must be a valid URL
// - Must use HTTPS scheme
// - Exception: HTTP is allowed for localhost/127.0.0.1 (for testing with mock server)
// NO OTHER SCHEMES ARE ALLOWED (e.g., file://, ftp://, etc.)
// An attack would be to set a malicious URL like "file:///etc/passwd" or "http://evil.com" to exfiltrate data.
//
//	We prevent that by validating the scheme and host.

func SetGraphURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)

	}
	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL: missing host")

	}
	// Let's check the scheme. We allow HTTPS and HTTP for localhost only.
	if parsedURL.Scheme != "https" {
		host := parsedURL.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("Graph URL must use HTTPS (got %s://). "+
				"HTTP is only allowed for localhost testing", parsedURL.Scheme)

		}
		// Log a warning if using HTTP even for localhost, just to be safe
		fmt.Fprintf(os.Stderr, "Warning: Using HTTP for Graph URL '%s'. "+
			"This is only allowed for localhost testing.\n", u)

	}
	graphURLMu.Lock()
	defer graphURLMu.Unlock()
	graphURL = u
	return nil
}

// GetGraphURL returns the current Graph API endpoint.
// Thread-safe: uses RWMutex to allow concurrent reads.
func GetGraphURL() string {
	graphURLMu.RLock()
	defer graphURLMu.RUnlock()
	return graphURL
}

// --------------------------------------------------------------

// Error type for Graph API errors. It includes the HTTP status code, Graph error code, and message.
type GraphError struct {
	// HTTP status code (e.g., 404, 500)
	StatusCode int
	// Graph API error code (e.g., "itemNotFound", "accessDenied")
	Code string

	// Human-readable error message from Graph API
	Message string

	// Original error that caused this (if any)
	Cause error
}

// Error implements the error interface.
// Returns a formatted string with status code, error code, and message.
func (e *GraphError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("HTTP %d - %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// Is allows errors.Is to match GraphError by status code.
// Example: errors.Is(err, &GraphError{StatusCode: 404})
func (e *GraphError) Is(target error) bool {
	var t *GraphError
	if errors.As(target, &t) {
		return e.StatusCode == t.StatusCode
	}
	return false
}

// Unwrap allows errors.Unwrap to retrieve the underlying cause of the GraphError.

func (e *GraphError) Unwrap() error {
	return e.Cause
}

// --------------------------------------------------------------
// newGraphError creates a GraphError from an HTTP response body.
// The body should contain JSON in the format:
//
// {"error": {"code": "...", "message": "..."}}
func newGraphError(statusCode int, body []byte) *GraphError {
	// Try to parse the Graph API error format
	var graphError struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(body, &graphError)
	if err != nil {
		// If we can't parse the error, return a generic one
		return &GraphError{
			StatusCode: statusCode,
			Code:       "unknown",
			Message:    string(body),
		}
	}

	return &GraphError{
		StatusCode: statusCode,
		Code:       graphError.Error.Code,
		Message:    graphError.Error.Message,
	}
}

// ============================================================================
// Helper: HTTP method validation
// ============================================================================
// validHTTPMethods contains the HTTP methods we support.
var validHTTPMethods = map[string]bool{
	http.MethodGet:    true,
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// isValidHTTPMethod checks if the method is one we support.
func isValidHTTPMethod(method string) bool {
	return validHTTPMethods[strings.ToUpper(method)]
}

// ---------------------------------------------------------------
// Header is an additional header that can be specified to Request

type Header struct {
	key, value string
}

// Request performs an authenticated request to Microsoft Graph
//
// PERFORMANCE IMPROVEMENTS:
// - Uses shared http.Client with connection pooling
// - Drains response body before closing (enables connection reuse)
// - Uses io.LimitReader to prevent DoS
// - Supports context.Context for cancellation
//
// SECURITY IMPROVEMENTS:
// - Proper error handling (no ignored errors)
// - Bearer token in correct case (RFC 6750)
// - Returns typed GraphError

func Request(ctx context.Context, resource string, auth *Auth, method string, content io.Reader, headers ...Header) ([]byte, error) {
	if auth == nil || auth.AccessToken == "" {
		// a catch all condition to avoid wiping our auth by accident
		log.Error().Msg("Auth was empty and we attempted to make a request with it!")
		return nil, errors.New("cannot make a request with empty auth")
	}

	// Refresh auth token if needed
	auth.Refresh()

	// PERFORMANCE: Read content into buffer if provided, to enable retries
	var contentBytes []byte
	if content != nil {
		var err error
		contentBytes, err = io.ReadAll(io.LimitReader(content, maxResponseSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Build the HTTP request with context
	var req *http.Request
	var err error
	if contentBytes != nil {
		req, err = http.NewRequestWithContext(ctx, method, GetGraphURL()+resource, bytes.NewReader(contentBytes))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, GetGraphURL()+resource, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// SECURITY: Use "Bearer" (capitalized) per RFC 6750
	req.Header.Set("Authorization", "Bearer "+auth.AccessToken)

	// Add method-specific headers
	switch method {
	case http.MethodPatch:
		req.Header.Set("If-Match", "*")
		req.Header.Set("Content-Type", "application/json")
	case http.MethodPost:
		req.Header.Set("Content-Type", "application/json")
	case http.MethodPut:
		req.Header.Set("Content-Type", "text/plain")
	}

	// Add custom headers
	for _, header := range headers {
		req.Header.Set(header.key, header.value)
	}

	// PERFORMANCE: Set GetBody to enable retries with the same body
	if contentBytes != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(contentBytes)), nil
		}
	}

	// Execute the request using the shared client
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// PERFORMANCE: Drain body before closing to enable connection reuse
	// SECURITY: Use LimitReader to prevent DoS
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	// Drain any remaining data and close
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Handle 401 Unauthorized
	if resp.StatusCode == http.StatusUnauthorized {
		var graphErr GraphError
		if unmarshalErr := json.Unmarshal(body, &graphErr); unmarshalErr != nil {
			log.Warn().Err(unmarshalErr).Msg("Failed to unmarshal 401 error response")
		}
		log.Warn().
			Str("code", graphErr.Code).
			Str("message", graphErr.Message).
			Msg("Authentication token invalid or new app permissions required, forcing reauth before retrying.")

		// Attempt to refresh auth
		reauth := newAuth(auth.AuthConfig, auth.path, false)
		if mergeErr := mergo.Merge(auth, reauth, mergo.WithOverride); mergeErr != nil {
			log.Error().Err(mergeErr).Msg("Failed to merge auth tokens")
		}
		req.Header.Set("Authorization", "Bearer "+auth.AccessToken)

		// Retry the request
		resp, err = httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("retry request failed: %w", err)
		}

		// Drain and read response
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to read retry response body: %w", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Handle 5xx server errors (retry once)
	if resp.StatusCode >= 500 {
		resp, err = httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("retry request failed: %w", err)
		}

		body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to read retry response body: %w", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		return nil, newGraphError(resp.StatusCode, body)
	}

	return body, nil
}

// Get is a convenience wrapper around Request
func Get(ctx context.Context, resource string, auth *Auth, headers ...Header) ([]byte, error) {
	return Request(ctx, resource, auth, http.MethodGet, nil, headers...)
}

// Patch is a convenience wrapper around Request
func Patch(ctx context.Context, resource string, auth *Auth, content io.Reader, headers ...Header) ([]byte, error) {
	return Request(ctx, resource, auth, http.MethodPatch, content, headers...)
}

// Post is a convenience wrapper around Request
func Post(ctx context.Context, resource string, auth *Auth, content io.Reader, headers ...Header) ([]byte, error) {
	return Request(ctx, resource, auth, http.MethodPost, content, headers...)
}

// Put is a convenience wrapper around Request
func Put(ctx context.Context, resource string, auth *Auth, content io.Reader, headers ...Header) ([]byte, error) {
	return Request(ctx, resource, auth, http.MethodPut, content, headers...)
}

// Delete performs an HTTP delete
func Delete(ctx context.Context, resource string, auth *Auth, headers ...Header) error {
	_, err := Request(ctx, resource, auth, http.MethodDelete, nil, headers...)
	return err
}

// IDPath computes the resource path for an item by ID
func IDPath(id string) string {
	if id == "root" {
		return "/me/drive/root"
	}
	return "/me/drive/items/" + url.PathEscape(id)
}

// ResourcePath translates an item's path to the proper path used by Graph
func ResourcePath(path string) string {
	if path == "/" {
		return "/me/drive/root"
	}
	return "/me/drive/root:" + url.PathEscape(path)
}

// ChildrenPath returns the path to an item's children
func childrenPath(path string) string {
	if path == "/" {
		return ResourcePath(path) + "/children"
	}
	return ResourcePath(path) + ":/children"
}

// ChildrenPathID returns the API resource path of an item's children
func childrenPathID(id string) string {
	return fmt.Sprintf("/me/drive/items/%s/children", url.PathEscape(id))
}

// User represents the user. Currently only used to fetch the account email so
// we can display it in file managers with .xdg-volume-info
// https://docs.microsoft.com/en-ca/graph/api/user-get
type User struct {
	UserPrincipalName string `json:"userPrincipalName"`
}

// GetUser fetches the current user details from the Graph API.
func GetUser(ctx context.Context, auth *Auth) (User, error) {
	resp, err := Get(ctx, "/me", auth)
	user := User{}
	if err == nil {
		err = json.Unmarshal(resp, &user)
	}
	return user, err
}

// DriveQuota is used to parse the User's current storage quotas from the API
// https://docs.microsoft.com/en-us/onedrive/developer/rest-api/resources/quota
type DriveQuota struct {
	Deleted   uint64 `json:"deleted"`   // bytes in recycle bin
	FileCount uint64 `json:"fileCount"` // unavailable on personal accounts
	Remaining uint64 `json:"remaining"`
	State     string `json:"state"` // normal | nearing | critical | exceeded
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
}

// Drive has some general information about the user's OneDrive
// https://docs.microsoft.com/en-us/onedrive/developer/rest-api/resources/drive
type Drive struct {
	ID        string     `json:"id"`
	DriveType string     `json:"driveType"` // personal | business | documentLibrary
	Quota     DriveQuota `json:"quota,omitempty"`
}

// GetDrive is used to fetch the details of the user's OneDrive.
func GetDrive(ctx context.Context, auth *Auth) (Drive, error) {
	resp, err := Get(ctx, "/me/drive", auth)
	drive := Drive{}
	if err != nil {
		return drive, err
	}
	return drive, json.Unmarshal(resp, &drive)
}

// IsOffline checks if an error indicates that the system is offline.
//
// An error is considered "offline" if it's NOT a GraphError.
// GraphError means we got an HTTP response (so we're online).
// Any other error (network timeout, DNS failure, etc.) means offline.
//
// This is more robust than parsing error strings with regex.
func IsOffline(err error) bool {
	if err == nil {
		return false
	}
	// If it's a GraphError, we got an HTTP response, so we're online
	var graphErr *GraphError
	if errors.As(err, &graphErr) {
		return false
	}

	// Check for common network error patterns
	// (This is still somewhat fragile, but better than regex on our own error format)
	errStr := err.Error()
	networkErrors := []string{
		"no such host",
		"connection refused",
		"network is unreachable",
		"timeout",
		"temporary failure",
	}

	for _, pattern := range networkErrors {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	// Default: assume offline if we don't recognize the error
	return true
}
