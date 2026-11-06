//go:build !windows

package wintun

import (
	"errors"
	"fmt"
	"runtime"
)

func load() error {
	return fmt.Errorf("wintun: wintun.dll cannot load on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
