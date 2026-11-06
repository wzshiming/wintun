package wintun

import _ "embed"

//go:embed embedded/bin/x86/wintun.dll
var dll []byte
