package graph

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetItem(t *testing.T) {
	t.Parallel()
	if !AuthAvailable {
		t.Skip("OneDrive credentials not available")
	}
	var auth Auth
	auth.FromFile(authTokenPath)
	item, err := GetItemPath(context.Background(), "/", &auth)
	assert.NoError(t, err)
	assert.Equal(t, "root", item.Name, "Failed to fetch directory root.")

	_, err = GetItemPath(context.Background(), "/lkjfsdlfjdwjkfl", &auth)
	assert.Error(t, err, "We didn't return an error for a non-existent item!")
}
