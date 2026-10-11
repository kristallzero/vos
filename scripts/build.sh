#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
# GOOS/GOARCH may be supplied by the caller; the build does not need a C compiler.
name="vos-${GOOS:-$(go env GOOS)}-${GOARCH:-$(go env GOARCH)}"
if [[ ${GOOS:-$(go env GOOS)} == windows ]]; then name+=.exe; fi
CGO_ENABLED=0 go build -mod=readonly -trimpath -tags with_gvisor -o "bin/$name" ./cmd/vos
echo "bin/$name"
