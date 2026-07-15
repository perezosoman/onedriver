#!/usr/bin/env bash
# Verify webkit2gtk-4.1 development headers are available.
# webkit2gtk-4.1 is the only supported version; there is no fallback to 4.0.

if [ -n "$CGO_ENABLED" ] && [ "$CGO_ENABLED" -eq 0 ]; then
    exit 0
fi

if ! pkg-config webkit2gtk-4.1; then
    echo "webkit2gtk-4.1 development headers must be installed"
    exit 1
fi
