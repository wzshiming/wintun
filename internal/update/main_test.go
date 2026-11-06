package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/format"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ttRelease is the layout of a release zip from https://www.wintun.net/builds.
var ttRelease = map[string]string{
	"wintun/LICENSE.txt":          "license",
	"wintun/README.md":            "readme",
	"wintun/include/wintun.h":     "header",
	"wintun/bin/x86/wintun.dll":   "x86 dll",
	"wintun/bin/amd64/wintun.dll": "amd64 dll",
	"wintun/bin/arm/wintun.dll":   "arm dll",
	"wintun/bin/arm64/wintun.dll": "arm64 dll",
}

// ttZip returns a zip holding files, by name, and its SHA-256.
func ttZip(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err == nil {
			_, err = w.Write([]byte(content))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// ttServe serves data at /wintun-9.9.zip and returns its URL.
func ttServe(t *testing.T, data []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wintun-9.9.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/wintun-9.9.zip"
}

// ttTree returns the files below root, by slash-separated path.
func ttTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func ttWantNothingWritten(t *testing.T, root string) {
	t.Helper()
	if got := ttTree(t, root); len(got) != 0 {
		t.Errorf("wrote %q, want nothing", slices.Sorted(maps.Keys(got)))
	}
}

func TestRunMirrorsTheReleasesLicenseAndDLLsAndWritesVersion(t *testing.T) {
	data, sum := ttZip(t, ttRelease)
	root := t.TempDir()
	if err := run(root, ttServe(t, data), "9.9", sum); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := ttTree(t, root)
	version := got["version.go"]
	delete(got, "version.go")
	want := map[string]string{
		"embedded/LICENSE.txt":          "license",
		"embedded/bin/x86/wintun.dll":   "x86 dll",
		"embedded/bin/amd64/wintun.dll": "amd64 dll",
		"embedded/bin/arm64/wintun.dll": "arm64 dll",
		"embedded/bin/arm/wintun.dll":   "arm dll",
	}
	if !maps.Equal(got, want) {
		t.Errorf("wrote %q, want %q", got, want)
	}
	if !strings.HasPrefix(version, "// Code generated ") || !strings.Contains(version, `const version = "9.9"`) {
		t.Errorf("version.go = %q, want generated code declaring the unexported version 9.9", version)
	}
	if formatted, err := format.Source([]byte(version)); err != nil || string(formatted) != version {
		t.Errorf("version.go is not gofmt-formatted: %v", err)
	}
}

func TestRunRemovesOtherFilesFromEmbedded(t *testing.T) {
	data, sum := ttZip(t, ttRelease)
	root := t.TempDir()
	stale := filepath.Join(root, "embedded", "bin", "amd64", "stale.dll")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, ttServe(t, data), "9.9", sum); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stat %s: %v, want it removed", stale, err)
	}
}

func TestRunWritesNothingForAZipWithAnotherSum(t *testing.T) {
	data, _ := ttZip(t, ttRelease)
	root := t.TempDir()
	if err := run(root, ttServe(t, data), "9.9", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("run = %v, want a SHA-256 mismatch", err)
	}
	ttWantNothingWritten(t, root)
}

func TestRunWritesNothingForAZipMissingADLL(t *testing.T) {
	for _, dir := range []string{"x86", "amd64", "arm64", "arm"} {
		t.Run(dir, func(t *testing.T) {
			name := "wintun/bin/" + dir + "/wintun.dll"
			release := maps.Clone(ttRelease)
			delete(release, name)
			data, sum := ttZip(t, release)
			root := t.TempDir()
			if err := run(root, ttServe(t, data), "9.9", sum); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("run = %v, want an error naming %s", err, name)
			}
			ttWantNothingWritten(t, root)
		})
	}
}

func TestRunFailsWhenTheDownloadFails(t *testing.T) {
	url := strings.Replace(ttServe(t, nil), "9.9", "0.0", 1)
	root := t.TempDir()
	if err := run(root, url, "0.0", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("run = %v, want the 404", err)
	}
	ttWantNothingWritten(t, root)
}

func TestFlagPatternsAcceptOnlyAVersionAndAHexSum(t *testing.T) {
	for _, v := range []string{"1.2.3", "1.0", "1.2.3.4"} {
		if !versionPattern.MatchString(v) {
			t.Errorf("version %q refused", v)
		}
	}
	for _, v := range []string{"", "1", "1.2.3/../x", "1.2.3?", "v1.2.3"} {
		if versionPattern.MatchString(v) {
			t.Errorf("version %q accepted", v)
		}
	}
	if sum := strings.Repeat("0a", 32); !sumPattern.MatchString(sum) {
		t.Errorf("SHA-256 %q refused", sum)
	}
	for _, s := range []string{strings.Repeat("0A", 32), strings.Repeat("0", 63), strings.Repeat("0", 65)} {
		if sumPattern.MatchString(s) {
			t.Errorf("SHA-256 %q accepted", s)
		}
	}
}
