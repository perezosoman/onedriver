//go:build linux
// +build linux

package graph

import (
	"errors"
	"time"

	"github.com/zalando/go-keyring"
)

var errKeyringTimeout = errors.New("keyring timeout")

// keyringGetImpl attempts to read a keyring secret with a timeout to avoid
// hangs when dbus is not available (e.g. headless CI).
func keyringGetImpl(path string) (string, error) {
	type result struct {
		token string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		token, err := keyring.Get("onedriver", path)
		ch <- result{token, err}
	}()
	select {
	case r := <-ch:
		return r.token, r.err
	case <-time.After(3 * time.Second):
		return "", errKeyringTimeout
	}
}
