package wintun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// loader extracts, verifies and loads wintun.dll once; Load uses defaultLoader, while tests build their own.
type loader struct {
	// cacheDir returns the directory below which wintun.dll is extracted.
	cacheDir func() (string, error)
	// loadLibrary loads the DLL at an absolute path.
	loadLibrary func(path string) (windows.Handle, error)
	// beforeOpen runs between extracting wintun.dll and opening it for verification; tests swap the file there.
	beforeOpen func(path string)

	mu sync.Mutex
	// module is the loaded wintun.dll, which golang.zx2c4.com/wintun then finds by its base name.
	module windows.Handle
}

// defaultLoader reads CacheDir on each call, so a program may replace it before Load.
var defaultLoader = &loader{
	cacheDir: func() (string, error) { return CacheDir() },
	// Resolve the DLL's own imports from System32 only.
	loadLibrary: func(path string) (windows.Handle, error) {
		return windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	},
	beforeOpen: func(string) {},
}

// Load extracts the embedded wintun.dll and loads it once per process.
func Load() error {
	return defaultLoader.load()
}

func (l *loader) load() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.module != 0 {
		return nil
	}
	cache, err := l.cacheDir()
	if err != nil {
		return fmt.Errorf("wintun: wintun.dll directory: %w", err)
	}
	root, sub := location(cache, runtime.GOARCH, dll)
	path, err := provisionFile(root, sub, "wintun.dll", dll, rejectReparsePoint)
	if err != nil {
		return fmt.Errorf("wintun: extract wintun.dll: %w", err)
	}
	l.beforeOpen(path)
	h, err := l.loadVerified(path, dll)
	if err != nil {
		return fmt.Errorf("wintun: load %s: %w", path, err)
	}
	l.module = h
	return nil
}

// loadVerified loads the DLL at path if it holds want, keeping the file open without write or delete sharing from the check until it is loaded.
func (l *loader) loadVerified(path string, want []byte) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	have, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	if sha256.Sum256(have) != sha256.Sum256(want) {
		return 0, errors.New("content differs from the embedded wintun.dll")
	}
	// Load what the handle verified: path itself can be re-pointed through a user-writable junction.
	final, err := finalPath(h)
	if err != nil {
		return 0, err
	}
	return l.loadLibrary(final)
}

// GetFinalPathNameByHandle flags golang.org/x/sys/windows does not define.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// finalPath returns the normalized \\?\ path of the file h is open on.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:min(n, uint32(len(buf)))]), nil
}
