package wintun

import (
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// ttWintunUse returns a loader that extracts below cache, which stands for the user cache, and fakes LoadLibrary; it also returns where wintun.dll goes and the paths the loader loads.
func ttWintunUse(t *testing.T, cache string) (*loader, string, *[]string) {
	t.Helper()
	loaded := new([]string)
	l := &loader{
		cacheDir: func() (string, error) { return filepath.Join(cache, "wintun"), nil },
		// load calls this under l.mu.
		loadLibrary: func(path string) (windows.Handle, error) {
			*loaded = append(*loaded, path)
			return windows.Handle(len(*loaded)), nil
		},
		beforeOpen: func(string) {},
	}
	return l, filepath.Join(append(append([]string{cache}, ttWintunSubdirs()...), "wintun.dll")...), loaded
}

// ttWintunSubdirs are the directories Load creates below the user cache.
func ttWintunSubdirs() []string {
	_, sub := location(filepath.Join("cache", "wintun"), runtime.GOARCH, dll)
	return sub
}

// ttWintunWantLoaded wants exactly one load, of the \\?\ final path of the file at path.
func ttWintunWantLoaded(t *testing.T, loaded []string, path string) {
	t.Helper()
	if len(loaded) != 1 {
		t.Fatalf("loaded %q, want one path", loaded)
	}
	got := loaded[0]
	if !strings.HasPrefix(got, `\\?\`) {
		t.Errorf("loaded %q, want a \\\\?\\ final path", got)
	}
	gotFi, err1 := os.Stat(got)
	wantFi, err2 := os.Stat(path)
	if err1 != nil || err2 != nil || !os.SameFile(gotFi, wantFi) {
		t.Errorf("loaded %q, want the file at %s (%v, %v)", got, path, err1, err2)
	}
}

// ttWintunJunction makes link a directory junction to target, which needs no privilege.
func ttWintunJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command(os.Getenv("ComSpec"), "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v\n%s", link, target, err, out)
	}
	t.Cleanup(func() { os.Remove(link) })
}

func ttWintunWantRefused(t *testing.T, l *loader, err error, target string, loaded []string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("Load = %v, want an error naming a reparse point", err)
	}
	if l.module != 0 || len(loaded) != 0 {
		t.Errorf("Load loaded %q through a junction", loaded)
	}
	if names := ttWintunReadDir(t, target); len(names) != 0 {
		t.Errorf("junction target %s holds %q, want nothing written into it", target, names)
	}
}

func ttWintunWantEmbedded(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if sha256.Sum256(got) != sha256.Sum256(dll) {
		t.Errorf("%s differs from the embedded wintun.dll", path)
	}
}

func TestLoadWritesTheEmbeddedDLLAndLoadsIt(t *testing.T) {
	l, path, loaded := ttWintunUse(t, t.TempDir())
	if err := l.load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
	if l.module == 0 {
		t.Error("Load kept no module")
	}
}

func TestLoadReplacesAWrongDLL(t *testing.T) {
	l, path, loaded := ttWintunUse(t, t.TempDir())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not wintun"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadAgainKeepsTheFile(t *testing.T) {
	l, path, loaded := ttWintunUse(t, t.TempDir())
	if err := l.load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if len(*loaded) != 1 {
		t.Errorf("loaded %q, want the second Load to reuse the module", *loaded)
	}
	// A loader without a module, as in a new process, provisions and loads again, now over the extracted file.
	fresh := &loader{cacheDir: l.cacheDir, loadLibrary: l.loadLibrary, beforeOpen: l.beforeOpen}
	if err := fresh.load(); err != nil {
		t.Fatalf("Load after forgetting the module: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime went from %v to %v, want wintun.dll left as extracted", before.ModTime(), after.ModTime())
	}
}

func TestLoadRefusesAFileChangedBeforeVerification(t *testing.T) {
	l, path, loaded := ttWintunUse(t, t.TempDir())
	l.beforeOpen = func(path string) {
		if err := os.WriteFile(path, []byte("swapped"), 0o644); err != nil {
			t.Errorf("swap %s: %v", path, err)
		}
	}
	err := l.load()
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("Load = %v, want an error saying the file differs", err)
	}
	if l.module != 0 || len(*loaded) != 0 {
		t.Fatalf("Load loaded %q from a file that failed verification", *loaded)
	}
	l.beforeOpen = func(string) {}
	if err := l.load(); err != nil {
		t.Fatalf("Load retried after a failure: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadRefusesAJunctionAtAnOwnedDirectory(t *testing.T) {
	for i, name := range ttWintunSubdirs() {
		t.Run(name, func(t *testing.T) {
			cache, target := t.TempDir(), t.TempDir()
			l, _, loaded := ttWintunUse(t, cache)
			parent := filepath.Join(append([]string{cache}, ttWintunSubdirs()[:i]...)...)
			if err := os.MkdirAll(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			ttWintunJunction(t, filepath.Join(parent, name), target)
			err := l.load()
			ttWintunWantRefused(t, l, err, target, *loaded)
		})
	}
}

func TestLoadRefusesAJunctionAtTheDLL(t *testing.T) {
	cache, target := t.TempDir(), t.TempDir()
	l, path, loaded := ttWintunUse(t, cache)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ttWintunJunction(t, path, target)
	err := l.load()
	ttWintunWantRefused(t, l, err, target, *loaded)
}

func TestLoadAcceptsARedirectedUserCache(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	l, path, loaded := ttWintunUse(t, cache)
	if err := l.load(); err != nil {
		t.Fatalf("Load under a redirected cache: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadLoadsTheFinalPathOfTheVerifiedFile(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	l, path, loaded := ttWintunUse(t, cache)
	fake := l.loadLibrary
	l.loadLibrary = func(p string) (windows.Handle, error) {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Errorf("%s opened for writing while being loaded, want the verifying handle still denying it", p)
		}
		return fake(p)
	}
	if err := l.load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantLoaded(t, *loaded, path)
	if strings.Contains((*loaded)[0], "redirected-cache") {
		t.Errorf("loaded %q, want the junction resolved", (*loaded)[0])
	}
}

func TestLoadConcurrentCallsAllSucceed(t *testing.T) {
	l, path, loaded := ttWintunUse(t, t.TempDir())
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { errs[i] = l.load() })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Errorf("concurrent Load: %v", err)
	}
	ttWintunWantLoaded(t, *loaded, path)
}
