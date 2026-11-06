package wintun

import _ "embed"

//go:embed embedded/bin/amd64/wintun.dll
var dll []byte
