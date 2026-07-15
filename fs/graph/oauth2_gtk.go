//go:build linux && cgo
// +build linux,cgo

package graph

/*
#cgo linux pkg-config: webkit2gtk-4.1
#include "stdlib.h"
#include "oauth2_gtk.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Fetch the auth code required as the first part of oauth2 authentication. Uses
// webkit2gtk to create a popup browser.
func getAuthCode(a AuthConfig, accountName string) (string, error) {
	cAuthURL := C.CString(getAuthURL(a))
	if cAuthURL == nil {
		return "", fmt.Errorf("failed to allocate auth URL string")
	}
	defer C.free(unsafe.Pointer(cAuthURL))

	cAccountName := C.CString(accountName)
	if cAccountName == nil {
		return "", fmt.Errorf("failed to allocate account name string")
	}
	defer C.free(unsafe.Pointer(cAccountName))

	cResponse := C.webkit_auth_window(cAuthURL, cAccountName)
	if cResponse == nil {
		return "", fmt.Errorf("authentication window failed to return a response")
	}
	defer C.free(unsafe.Pointer(cResponse))

	response := C.GoString(cResponse)

	code, err := parseAuthCode(response)
	if err != nil {
		return "", fmt.Errorf("no validation code returned, or code was invalid: %w", err)
	}
	return code, nil
}

// uriGetHost is exclusively here for testing because we cannot use CGo in tests,
// but can use functions that invoke CGo in tests.
func uriGetHost(uri string) string {
	input := C.CString(uri)
	defer C.free(unsafe.Pointer(input))

	host := C.uri_get_host(input)
	defer C.free(unsafe.Pointer(host))
	if host == nil {
		return ""
	}
	return C.GoString(host)
}
