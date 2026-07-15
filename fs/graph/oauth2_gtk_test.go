//go:build linux && cgo
// +build linux,cgo

package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURIGetHost(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{"empty string", "", ""},
		{"plain text no scheme", "this won't work", ""},
		{"https with path", "https://account.live.com/test/index.html", "account.live.com"},
		{"http without path", "http://account.live.com", "account.live.com"},
		{"with port", "https://account.live.com:443/test", "account.live.com"},
		{"with query string", "https://account.live.com?code=abc123", "account.live.com"},
		{"with fragment", "https://account.live.com#section", "account.live.com"},
		{"subdomain", "https://sub.domain.example.com/path", "sub.domain.example.com"},
		{"IPv4 address", "https://192.168.1.1/path", "192.168.1.1"},
		{"oauth redirect URL", "https://login.live.com/oauth20_desktop.srf?code=M.R3_BAY.abc123", "login.live.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, uriGetHost(tt.uri))
		})
	}
}
