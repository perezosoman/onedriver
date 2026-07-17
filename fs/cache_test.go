// these tests are independent of the mounted fs
package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootGet(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_root_get"))
	root, err := cache.GetPath("/", auth)
	require.NoError(t, err)
	assert.Equal(t, "/", root.Path(), "Root path did not resolve correctly.")
}

func TestRootChildrenUpdate(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_root_children_update"))
	children, err := cache.GetChildrenPath("/", auth)
	require.NoError(t, err)

	if _, exists := children["documents"]; !exists {
		t.Fatal("Could not find documents folder.")
	}
}

func TestSubdirGet(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_subdir_get"))
	documents, err := cache.GetPath("/Documents", auth)
	require.NoError(t, err)
	assert.Equal(t, "Documents", documents.Name(), "Failed to fetch \"/Documents\".")
}

func TestSubdirChildrenUpdate(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_subdir_children_update"))
	children, err := cache.GetChildrenPath("/Documents", auth)
	require.NoError(t, err)

	if _, exists := children["documents"]; exists {
		fmt.Println("Documents directory found inside itself. " +
			"Likely the cache did not traverse correctly.\n\nChildren:")
		for key := range children {
			fmt.Println(key)
		}
		t.FailNow()
	}
}

func TestSamePointer(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_same_pointer"))
	item, _ := cache.GetPath("/Documents", auth)
	item2, _ := cache.GetPath("/Documents", auth)
	if item != item2 {
		t.Fatalf("Pointers to cached items do not match: %p != %p\n", item, item2)
	}
	assert.NotNil(t, item)
}

// SetCacheMaxAge should store the configured max age.
func TestSetCacheMaxAge(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_cache_max_age"))
	assert.Equal(t, 5*time.Minute, cache.cacheMaxAge)

	cache.SetCacheMaxAge(2 * time.Hour)
	// Give the background goroutine a moment to start.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 2*time.Hour, cache.cacheMaxAge)
}

// SetCacheMaxAge with zero or negative should not start the cleanup loop.
func TestSetCacheMaxAgeZero(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_cache_max_age_zero"))
	cache.SetCacheMaxAge(0)
	assert.Equal(t, time.Duration(0), cache.cacheMaxAge)
	cache.SetCacheMaxAge(-1 * time.Hour)
	assert.Equal(t, -1*time.Hour, cache.cacheMaxAge)
}

// EvictExpired removes content files older than cacheMaxAge, skipping open files.
func TestEvictExpired(t *testing.T) {
	requireAuth(t)
	t.Parallel()
	cache := NewFilesystem(auth, filepath.Join(testDBLoc, "test_evict_expired"))
	cache.SetCacheMaxAge(1 * time.Hour)
	time.Sleep(50 * time.Millisecond) // let cleanup loop start

	// Create three content files with different ages.
	files := map[string]time.Duration{
		"old_file":    -2 * time.Hour,    // should be evicted
		"recent_file": -30 * time.Minute, // should stay
		"open_file":   -2 * time.Hour,    // should stay (will be opened)
	}
	for name, age := range files {
		cache.content.Insert(name, []byte("content-"+name))
		oldTime := time.Now().Add(age)
		os.Chtimes(filepath.Join(cache.content.directory, name), oldTime, oldTime)
	}

	// Open one file so it is skipped during eviction.
	fd, err := cache.content.Open("open_file")
	require.NoError(t, err)
	defer cache.content.Close("open_file")
	require.NotNil(t, fd)

	// Run eviction.
	cache.evictExpired()

	// Verify results.
	assert.False(t, cache.content.HasContent("old_file"),
		"old_file should have been evicted")
	assert.True(t, cache.content.HasContent("recent_file"),
		"recent_file should still be cached")
	assert.True(t, cache.content.HasContent("open_file"),
		"open_file should still be cached (was open)")
}
