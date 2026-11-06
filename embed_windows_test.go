package wintun

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEmbeddedIsTrueOnWindows(t *testing.T) {
	if !Embedded {
		t.Error("Embedded is false on Windows")
	}
}

func TestDLLIsTheMirroredDLLOfThisPort(t *testing.T) {
	dir, ok := map[string]string{"386": "x86", "amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if !ok {
		t.Fatalf("no release directory for GOARCH %s", runtime.GOARCH)
	}
	want, err := os.ReadFile(filepath.Join("embedded", "bin", dir, "wintun.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dll, want) {
		t.Errorf("dll is %d bytes that differ from the %d of embedded/bin/%s/wintun.dll", len(dll), len(want), dir)
	}
}
