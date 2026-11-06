package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	zxwintun "golang.zx2c4.com/wintun"

	"github.com/wzshiming/wintun"
)

// ttExports are the functions wintun.h declares.
var ttExports = []string{
	"WintunCreateAdapter", "WintunOpenAdapter", "WintunCloseAdapter", "WintunDeleteDriver", "WintunGetAdapterLUID",
	"WintunGetRunningDriverVersion", "WintunSetLogger", "WintunStartSession", "WintunEndSession", "WintunGetReadWaitEvent",
	"WintunReceivePacket", "WintunReleaseReceivePacket", "WintunAllocateSendPacket", "WintunSendPacket",
}

// ttGate skips the test unless WINTUN_E2E=1 and this build embeds a wintun.dll.
func ttGate(t *testing.T) {
	t.Helper()
	if os.Getenv("WINTUN_E2E") != "1" {
		t.Skip("loads the real wintun.dll; set WINTUN_E2E=1 to run")
	}
	if !wintun.Embedded {
		t.Skipf("this build embeds no wintun.dll for %s", runtime.GOARCH)
	}
}

// ttLoad loads wintun.dll through Load, which runs once per process, and returns the module and the path it was loaded from.
func ttLoad(t *testing.T) (windows.Handle, string) {
	t.Helper()
	if err := wintun.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	name, err := windows.UTF16PtrFromString("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	var module windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &module); err != nil {
		t.Fatalf("wintun.dll is not loaded after Load: %v", err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(module, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetModuleFileName: %v", err)
	}
	return module, windows.UTF16ToString(buf[:n])
}

func TestE2ELoad(t *testing.T) {
	ttGate(t)
	module, path := ttLoad(t)
	t.Logf("wintun.dll loaded from %s", path)
	for _, name := range ttExports {
		if _, err := windows.GetProcAddress(module, name); err != nil {
			t.Errorf("%s does not resolve in the loaded wintun.dll: %v", name, err)
		}
	}

	got, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := wintun.CacheDir()
	if err != nil {
		t.Fatalf("CacheDir: %v", err)
	}
	// The loaded path is the final one, which may spell the cache directory differently, such as without 8.3 short names.
	pattern := filepath.Join(cache, runtime.GOARCH+"-*", "wintun.dll")
	candidates, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(candidates, func(c string) bool {
		want, err := os.Stat(c)
		return err == nil && os.SameFile(got, want)
	}) {
		t.Errorf("loaded %s, want the file %s", path, pattern)
	}

	// golang.zx2c4.com/wintun reads the version resource of the module it finds by base name.
	if got := zxwintun.Version(); got != wintun.Version {
		t.Errorf("golang.zx2c4.com/wintun finds wintun.dll %s, want %s", got, wintun.Version)
	}
}

func TestE2ESignature(t *testing.T) {
	ttGate(t)
	_, path := ttLoad(t)
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: file,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	if err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data); err != nil {
		t.Errorf("WinVerifyTrust close: %v", err)
	}
	if verifyErr != nil {
		t.Errorf("WinVerifyTrust(%s) = %v, want its Authenticode signature trusted", path, verifyErr)
	}
}
