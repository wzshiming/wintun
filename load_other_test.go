//go:build !windows

package wintun

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadIsUnsupportedOutsideWindows(t *testing.T) {
	if err := Load(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Load = %v, want errors.ErrUnsupported", err)
	}
}

func TestLoadErrorOutsideWindowsStartsWithThePrefix(t *testing.T) {
	err := Load()
	if err == nil || !strings.HasPrefix(err.Error(), "wintun: ") {
		t.Errorf("Load = %v, want an error starting with \"wintun: \"", err)
	}
}
