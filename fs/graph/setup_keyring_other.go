//go:build !linux
// +build !linux

package graph

import "errors"

var errKeyringTimeout = errors.New("keyring timeout")

func keyringGetImpl(path string) (string, error) {
	return "", errors.New("keyring not available on this platform")
}

// keyringSetImpl does not exist on non-linux platforms; all writes will
// surface the same error so ToFile() falls back to disk persistence.
func keyringSetImpl(path, secret string) error {
	return errors.New("keyring not available on this platform")
}
