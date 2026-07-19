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

// keyringSetImpl attempts to write a keyring secret with a timeout to avoid
// hangs when dbus is not available. ToFile() invokes this on every save
// (e.g. after a successful refresh), so without the wrapper a blackholed
// dbus would block the entire token-persistence path indefinitely.
func keyringSetImpl(path, secret string) error {
	ch := make(chan error, 1)
	go func() {
		ch <- keyring.Set("onedriver", path, secret)
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		return errKeyringTimeout
	}
}
