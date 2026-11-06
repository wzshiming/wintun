package wintun

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The exported API of golang.zx2c4.com/wintun, pinned at compile time.
var (
	_ func(string, string, *windows.GUID) (*Adapter, error) = CreateAdapter
	_ func(string) (*Adapter, error)                        = OpenAdapter
	_ func(*Adapter) error                                  = (*Adapter).Close
	_ func(*Adapter) uint64                                 = (*Adapter).LUID
	_ func(*Adapter, uint32) (Session, error)               = (*Adapter).StartSession
	_ func() error                                          = Uninstall
	_ func() (uint32, error)                                = RunningVersion
	_ func() string                                         = Version
	_ func(Session)                                         = Session.End
	_ func(Session) windows.Handle                          = Session.ReadWaitEvent
	_ func(Session) ([]byte, error)                         = Session.ReceivePacket
	_ func(Session, []byte)                                 = Session.ReleaseReceivePacket
	_ func(Session, int) ([]byte, error)                    = Session.AllocateSendPacket
	_ func(Session, []byte)                                 = Session.SendPacket
	_ interface {
		WriteWithTimestamp(p []byte, ts int64) (n int, err error)
	} = TimestampedWriter(nil)
	_ = Packet{Next: (*Packet)(nil), Size: uint32(0), Data: (*[PacketSizeMax]byte)(nil)}
)

func TestConstantsAreUpstreams(t *testing.T) {
	got := []int{AdapterNameMax, PacketSizeMax, RingCapacityMin, RingCapacityMax}
	if want := []int{128, 0xffff, 0x20000, 0x4000000}; !slices.Equal(got, want) {
		t.Errorf("AdapterNameMax, PacketSizeMax, RingCapacityMin, RingCapacityMax = %#x, want %#x", got, want)
	}
}

// ttHelperEnv makes the test binary run a helper test in a process of its own, where no other test has loaded the DLL.
const ttHelperEnv = "WINTUN_TEST_LAZY_HELPER"

// ttRunHelper runs the helper test name in a process of its own and fails t unless it passes.
func ttRunHelper(t *testing.T, name string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), ttHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: "+name+" ")) {
		t.Errorf("%s did not pass:\n%s", name, out)
	}
}

func TestLazyHelper(t *testing.T) {
	if os.Getenv(ttHelperEnv) != "1" {
		t.Skip("run by TestPackageInitAndVersionLoadNothing")
	}
	if modwintun.module.Load() != nil {
		t.Fatal("wintun.dll is loaded at package init")
	}
	if got := Version(); got != version {
		t.Errorf("Version() = %q, want %q", got, version)
	}
	if modwintun.module.Load() != nil {
		t.Error("Version loaded wintun.dll")
	}
}

func TestPackageInitAndVersionLoadNothing(t *testing.T) {
	ttRunHelper(t, "TestLazyHelper")
}

func TestRunningVersionResolvesFromAModuleOutsideTheLoaderList(t *testing.T) {
	v, err := RunningVersion()
	if err := procWintunGetRunningDriverVersion.Find(); err != nil {
		t.Fatalf("WintunGetRunningDriverVersion does not resolve: %v", err)
	}
	// No driver need be installed: then the DLL itself reports a Windows error.
	if _, ok := err.(windows.Errno); err != nil && !ok {
		t.Errorf("RunningVersion() = %d, %v (%T), want a version or a Windows error", v, err, err)
	}
	t.Logf("RunningVersion() = %#x, %v", v, err)
	var h windows.Handle
	name, _ := windows.UTF16PtrFromString("wintun.dll")
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &h); err == nil {
		t.Errorf("the OS loader has wintun.dll at %#x, want it loaded only in memory", h)
	}
}

// ttResourceVersion formats the VERSIONINFO resource of module as golang.zx2c4.com/wintun's Version does.
func ttResourceVersion(t *testing.T, module windows.Handle) string {
	t.Helper()
	resInfo, err := windows.FindResource(module, windows.ResourceID(1), windows.RT_VERSION)
	if err != nil {
		t.Fatalf("FindResource: %v", err)
	}
	data, err := windows.LoadResourceData(module, resInfo)
	if err != nil {
		t.Fatalf("LoadResourceData: %v", err)
	}
	var fixedInfo *windows.VS_FIXEDFILEINFO
	fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
	if err := windows.VerQueryValue(unsafe.Pointer(&data[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen); err != nil {
		t.Fatalf("VerQueryValue: %v", err)
	}
	version := fmt.Sprintf("%d.%d", (fixedInfo.FileVersionMS>>16)&0xff, (fixedInfo.FileVersionMS>>0)&0xff)
	if nextNibble := (fixedInfo.FileVersionLS >> 16) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}
	if nextNibble := (fixedInfo.FileVersionLS >> 0) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}
	return version
}

func TestVersionIsTheResourceVersionOfTheInMemoryModule(t *testing.T) {
	if err := modwintun.Load(); err != nil {
		t.Fatal(err)
	}
	if got, want := ttResourceVersion(t, modwintun.base()), Version(); got != want {
		t.Errorf("the in-memory wintun.dll is version %s, Version() = %s", got, want)
	}
}

func TestEmbeddedDLLIsTrustedAndSignedByWireGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(path, dll, 0o644); err != nil {
		t.Fatal(err)
	}
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
	// WinVerifyTrust checked the first signer, which ttSigner reads.
	f, err := pe.NewFile(bytes.NewReader(dll))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if signer := ttSigner(t, f, dll); !slices.Contains(signer.Subject.Organization, "WireGuard LLC") {
		t.Errorf("signed by %s, want WireGuard LLC", signer.Subject)
	}
}
