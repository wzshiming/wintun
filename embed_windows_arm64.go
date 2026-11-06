package wintun

import _ "embed"

//go:embed embedded/bin/arm64/wintun.dll
var dll []byte
