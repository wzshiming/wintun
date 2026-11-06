//go:build !windows

package wintun

import "testing"

func TestEmbeddedIsFalseOutsideWindows(t *testing.T) {
	if Embedded {
		t.Error("Embedded is true outside Windows")
	}
}
