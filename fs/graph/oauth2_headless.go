//go:build !linux || !cgo
// +build !linux !cgo

package graph

// getAuthCode delegates to the headless implementation for builds without CGo.
// The accountName parameter is present for signature compatibility with the GTK version.
func getAuthCode(config AuthConfig, accountName string) (string, error) {
	return getAuthCodeHeadless(config, accountName)
}
