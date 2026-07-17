// Package mock provides a local HTTP server that simulates the Microsoft Graph API
// for testing onedriver without a real OneDrive account or internet connection.
//
// Usage:
//
//	srv := mock.NewServer()
//	defer srv.Close()
//	os.Setenv("ONEDRIVER_GRAPH_URL", srv.URL())
package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// These types mirror graph.DriveItem and friends so the mock package does not
// import the parent graph package (which would create an import cycle when
// imported from graph's own test files).

// ItemParent describes a DriveItem's parent.
type ItemParent struct {
	Path      string `json:"path,omitempty"`
	ID        string `json:"id,omitempty"`
	DriveID   string `json:"driveId,omitempty"`
	DriveType string `json:"driveType,omitempty"`
}

// Folder is a folder facet.
type Folder struct {
	ChildCount uint32 `json:"childCount,omitempty"`
}

// Hashes are integrity hashes.
type Hashes struct {
	SHA1Hash     string `json:"sha1Hash,omitempty"`
	QuickXorHash string `json:"quickXorHash,omitempty"`
}

// File is a file facet.
type File struct {
	Hashes Hashes `json:"hashes,omitempty"`
}

// Item is a minimal DriveItem used by the mock server.
type Item struct {
	ID               string      `json:"id,omitempty"`
	Name             string      `json:"name,omitempty"`
	Size             uint64      `json:"size,omitempty"`
	ModTime          *time.Time  `json:"lastModifiedDatetime,omitempty"`
	Parent           *ItemParent `json:"parentReference,omitempty"`
	Folder           *Folder     `json:"folder,omitempty"`
	File             *File       `json:"file,omitempty"`
	ConflictBehavior string      `json:"@microsoft.graph.conflictBehavior,omitempty"`
	ETag             string      `json:"eTag,omitempty"`
}

// Server is a mock Microsoft Graph API server.
type Server struct {
	http    *httptest.Server
	items   map[string]*Item
	content map[string][]byte
	nextID  int
	mu      sync.RWMutex
}

// NewServer creates and starts a mock Graph API server pre-populated with a root
// drive and a Documents folder.
func NewServer() *Server {
	now := time.Now()
	s := &Server{
		items:   make(map[string]*Item),
		content: make(map[string][]byte),
		nextID:  1,
	}

	root := &Item{
		ID:      "root",
		Name:    "root",
		Folder:  &Folder{ChildCount: 1},
		Parent:  &ItemParent{ID: "root"},
		ModTime: &now,
	}
	s.items["root"] = root

	docs := &Item{
		ID:      "mock-documents",
		Name:    "Documents",
		Folder:  &Folder{},
		Parent:  &ItemParent{ID: "root"},
		ModTime: &now,
		ETag:    "mock-etag-documents",
	}
	s.items["mock-documents"] = docs

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handler)
	s.http = httptest.NewServer(mux)
	return s
}

// URL returns the base URL of the mock server.
func (s *Server) URL() string { return s.http.URL }

// Close shuts down the mock server.
func (s *Server) Close() { s.http.Close() }

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/me" && method == http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]string{
			"userPrincipalName": "test@mock.local",
		})

	case path == "/me/drive" && method == http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]string{
			"driveType": "personal",
			"id":        "mock-drive-id",
		})

	case path == "/me/drive/root" && method == http.MethodGet:
		s.mu.RLock()
		item := s.items["root"]
		s.mu.RUnlock()
		s.writeJSON(w, http.StatusOK, item)

	case strings.HasPrefix(path, "/me/drive/root:/") && strings.HasSuffix(path, ":/children") && method == http.MethodGet:
		trimmed := strings.TrimPrefix(path, "/me/drive/root:")
		trimmed = strings.TrimSuffix(trimmed, ":/children")
		s.handleChildrenByPath(w, trimmed)

	case strings.HasPrefix(path, "/me/drive/root:/") && strings.HasSuffix(path, ":/content") && method == http.MethodPut:
		trimmed := strings.TrimPrefix(path, "/me/drive/root:")
		trimmed = strings.TrimSuffix(trimmed, ":/content")
		s.handlePutContentByPath(w, r, trimmed)

	case strings.HasPrefix(path, "/me/drive/root:/") && method == http.MethodGet:
		trimmed := strings.TrimPrefix(path, "/me/drive/root:")
		s.handleGetByPath(w, trimmed)

	case strings.HasPrefix(path, "/me/drive/items/") && strings.HasSuffix(path, "/content") && method == http.MethodGet:
		id := s.extractItemID(path, "/content")
		s.handleGetContent(w, id)

	case strings.HasPrefix(path, "/me/drive/items/") && strings.HasSuffix(path, "/content") && method == http.MethodPut:
		id := s.extractItemID(path, "/content")
		s.handlePutContent(w, r, id)

	case strings.HasPrefix(path, "/me/drive/items/") && strings.HasSuffix(path, "/children") && method == http.MethodGet:
		id := s.extractItemID(path, "/children")
		s.handleChildren(w, id)

	case strings.HasPrefix(path, "/me/drive/items/") && strings.HasSuffix(path, "/children") && method == http.MethodPost:
		id := s.extractItemID(path, "/children")
		s.handleCreate(w, r, id)

	case strings.HasPrefix(path, "/me/drive/items/") && strings.Contains(path, ":/") && method == http.MethodGet:
		parts := strings.SplitN(strings.TrimPrefix(path, "/me/drive/items/"), ":/", 2)
		if len(parts) == 2 {
			s.handleGetChild(w, parts[0], parts[1])
		} else {
			http.NotFound(w, r)
		}

	case strings.HasPrefix(path, "/me/drive/items/") && method == http.MethodGet:
		id := s.extractItemID(path, "")
		s.handleGetItem(w, id)

	case strings.HasPrefix(path, "/me/drive/items/") && method == http.MethodPatch:
		id := strings.TrimPrefix(path, "/me/drive/items/")
		s.handlePatch(w, r, id)

	case strings.HasPrefix(path, "/me/drive/items/") && method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/me/drive/items/")
		s.handleDelete(w, id)

	case strings.HasPrefix(path, "/me/drive/root/delta") && method == http.MethodGet:
		s.handleDelta(w)

	case path == "/token" && method == http.MethodPost:
		s.handleToken(w, r)

	default:
		http.NotFound(w, r)
	}
}

// extractItemID pulls the item ID from a path like /me/drive/items/ID/suffix.
func (s *Server) extractItemID(path, suffix string) string {
	trimmed := strings.TrimPrefix(path, "/me/drive/items/")
	if suffix != "" {
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	return trimmed
}

func (s *Server) handleGetByPath(w http.ResponseWriter, rawPath string) {
	decoded := rawPath
	if decoded == "/" || decoded == "" {
		s.mu.RLock()
		item := s.items["root"]
		s.mu.RUnlock()
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	parts := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	s.mu.RLock()
	defer s.mu.RUnlock()

	parentID := "root"
	for _, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for _, item := range s.items {
			if item.Parent != nil && item.Parent.ID == parentID && item.Name == part {
				parentID = item.ID
				found = true
				break
			}
		}
		if !found {
			s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "item not found"})
			return
		}
	}

	item := s.items[parentID]
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleGetItem(w http.ResponseWriter, id string) {
	s.mu.RLock()
	item, ok := s.items[id]
	s.mu.RUnlock()
	if !ok {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "item not found"})
		return
	}
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleGetChild(w http.ResponseWriter, parentID, name string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.items {
		if item.Parent != nil && item.Parent.ID == parentID && item.Name == name {
			s.writeJSON(w, http.StatusOK, item)
			return
		}
	}
	s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "child not found"})
}

func (s *Server) handleChildren(w http.ResponseWriter, parentID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	children := make([]*Item, 0)
	for _, item := range s.items {
		if item.Parent != nil && item.Parent.ID == parentID {
			children = append(children, item)
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"value": children,
	})
}

func (s *Server) handleChildrenByPath(w http.ResponseWriter, rawPath string) {
	decoded := rawPath
	if decoded == "/" || decoded == "" {
		s.handleChildren(w, "root")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	parentID := "root"
	if decoded != "/" {
		parts := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
		for _, part := range parts {
			if part == "" {
				continue
			}
			found := false
			for _, item := range s.items {
				if item.Parent != nil && item.Parent.ID == parentID && item.Name == part {
					parentID = item.ID
					found = true
					break
				}
			}
			if !found {
				s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "path not found"})
				return
			}
		}
	}

	children := make([]*Item, 0)
	for _, item := range s.items {
		if item.Parent != nil && item.Parent.ID == parentID {
			children = append(children, item)
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"value": children,
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, parentID string) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	var item Item
	if err := json.Unmarshal(body, &item); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	id := fmt.Sprintf("mock-%d", s.nextID)
	s.nextID++
	now := time.Now()
	item.ID = id
	item.ModTime = &now
	item.ETag = id + "-etag"
	item.Parent = &ItemParent{ID: parentID}
	s.items[id] = &item
	s.mu.Unlock()

	s.writeJSON(w, http.StatusCreated, &item)
}

func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request, id string) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	var update Item
	if err := json.Unmarshal(body, &update); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	item, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "item not found"})
		return
	}

	if update.Name != "" {
		item.Name = update.Name
	}
	if update.Parent != nil && update.Parent.ID != "" {
		item.Parent = update.Parent
	}
	now := time.Now()
	item.ModTime = &now
	s.mu.Unlock()

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDelete(w http.ResponseWriter, id string) {
	s.mu.Lock()
	item, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check if directory has children
	if item.Folder != nil {
		for _, child := range s.items {
			if child.Parent != nil && child.Parent.ID == id && child.ID != id {
				s.mu.Unlock()
				s.writeJSON(w, http.StatusConflict, map[string]string{
					"error": "directory is not empty",
				})
				return
			}
		}
	}

	delete(s.items, id)
	delete(s.content, id)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetContent(w http.ResponseWriter, id string) {
	s.mu.RLock()
	data, ok := s.content[id]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) handlePutContent(w http.ResponseWriter, r *http.Request, id string) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	s.content[id] = body
	now := time.Now()
	if item, ok := s.items[id]; ok {
		item.Size = uint64(len(body))
		item.ModTime = &now
	}
	s.mu.Unlock()

	s.writeJSON(w, http.StatusOK, s.items[id])
}

func (s *Server) handlePutContentByPath(w http.ResponseWriter, r *http.Request, rawPath string) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	decoded := rawPath
	s.mu.Lock()
	defer s.mu.Unlock()

	parts := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	parentID := "root"
	var item *Item
	name := parts[len(parts)-1]

	// Navigate to parent
	for i := 0; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		found := false
		for _, it := range s.items {
			if it.Parent != nil && it.Parent.ID == parentID && it.Name == part {
				parentID = it.ID
				found = true
				break
			}
		}
		if !found {
			s.mu.Unlock()
			s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "parent not found"})
			return
		}
	}

	// Find or create the file
	for _, it := range s.items {
		if it.Parent != nil && it.Parent.ID == parentID && it.Name == name {
			item = it
			break
		}
	}

	now := time.Now()
	if item == nil {
		id := fmt.Sprintf("mock-%d", s.nextID)
		s.nextID++
		item = &Item{
			ID:      id,
			Name:    name,
			File:    &File{},
			Parent:  &ItemParent{ID: parentID},
			ModTime: &now,
			ETag:    id + "-etag",
		}
		s.items[id] = item
	}

	s.content[item.ID] = body
	item.Size = uint64(len(body))
	item.ModTime = &now

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDelta(w http.ResponseWriter) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"value":            []*Item{},
		"@odata.deltaLink": s.URL() + "/me/drive/root/delta?token=mock-delta-token",
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  "mock-refreshed-token",
		"refresh_token": "mock-refreshed-refresh",
		"expires_in":    3600,
		"token_type":    "Bearer",
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
