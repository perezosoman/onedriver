//go:build !linux
// +build !linux

package graph

import "errors"

var errKeyringTimeout = errors.New("keyring timeout")

func keyringGetImpl(path string) (string, error) {
	return "", errors.New("keyring not available on this platform")
}
