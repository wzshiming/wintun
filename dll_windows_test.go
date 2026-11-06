package wintun

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

// MEMORY_BASIC_INFORMATION State and Type values x/sys/windows does not define.
const (
	memFree    = 0x10000
	memPrivate = 0x20000
)

// memoryBasicInformation is MEMORY_BASIC_INFORMATION on every Windows port: x/sys/windows'
// MemoryBasicInformation always has the 64-bit PartitionId, which 32-bit Windows lacks.
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       [unsafe.Sizeof(uintptr(0))/4 - 1]uint16 // one WORD on 64-bit Windows, none on 32-bit
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var procVirtualQuery = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualQuery")

func TestMemoryBasicInformationIsWhatVirtualQueryWrites(t *testing.T) {
	want := uintptr(48)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 28
	}
	if got := unsafe.Sizeof(memoryBasicInformation{}); got != want {
		t.Errorf("memoryBasicInformation is %d bytes, want MEMORY_BASIC_INFORMATION's %d", got, want)
	}
	var local byte
	queryMemory(t, uintptr(unsafe.Pointer(&local)))
}

// queryMemory fails the test unless VirtualQuery fills exactly a memoryBasicInformation.
func queryMemory(t *testing.T, addr uintptr) memoryBasicInformation {
	t.Helper()
	var mbi memoryBasicInformation
	n, _, err := procVirtualQuery.Call(addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if n == 0 {
		t.Fatalf("VirtualQuery(%#x): %v", addr, err)
	}
	if n != unsafe.Sizeof(mbi) {
		t.Fatalf("VirtualQuery(%#x) wrote %d bytes, but memoryBasicInformation is %d: its layout does not match MEMORY_BASIC_INFORMATION", addr, n, unsafe.Sizeof(mbi))
	}
	return mbi
}

// sectionTableSpan returns the first and last byte memmod's Sections converts: a 0xffff-entry section table.
func sectionTableSpan(image []byte) (first, last uintptr) {
	dos := (*memmod.IMAGE_DOS_HEADER)(unsafe.Pointer(&image[0]))
	nt := (*memmod.IMAGE_NT_HEADERS)(unsafe.Pointer(&image[dos.E_lfanew]))
	first = uintptr(unsafe.Pointer(nt)) + unsafe.Offsetof(nt.OptionalHeader) + uintptr(nt.FileHeader.SizeOfOptionalHeader)
	return first, first + 0xffff*unsafe.Sizeof(memmod.IMAGE_SECTION_HEADER{}) - 1
}

func TestStagedImageSectionTableStaysInOneAllocationGoDoesNotManage(t *testing.T) {
	err := withStagedImage(dll, func(image []byte) error {
		if !bytes.Equal(image, dll) {
			t.Fatal("the staged image differs from the embedded DLL")
		}
		base := uintptr(unsafe.Pointer(&image[0]))
		first, last := sectionTableSpan(image)
		// Any image memmod accepts has its section table start inside the image, so this bounds every input.
		worstLast := base + uintptr(len(image)) - 1 + 0xffff*unsafe.Sizeof(memmod.IMAGE_SECTION_HEADER{})
		for _, addr := range []uintptr{base, first, last, worstLast} {
			mbi := queryMemory(t, addr)
			if mbi.AllocationBase != base || mbi.Type != memPrivate || mbi.State != windows.MEM_COMMIT {
				t.Errorf("byte %#x: allocation base %#x, type %#x, state %#x; want base %#x of a committed private allocation",
					addr, mbi.AllocationBase, mbi.Type, mbi.State, base)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStagedImageIsReleasedAfterUse(t *testing.T) {
	var base uintptr
	if err := withStagedImage(dll, func(image []byte) error {
		base = uintptr(unsafe.Pointer(&image[0]))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if mbi := queryMemory(t, base); mbi.State != memFree {
		t.Errorf("staging memory at %#x has state %#x after use, want free", base, mbi.State)
	}
}

func TestStagedImageIsReleasedAndItsErrorReturnedWhenUseFails(t *testing.T) {
	want := errors.New("use failed")
	var base uintptr
	err := withStagedImage(dll, func(image []byte) error {
		base = uintptr(unsafe.Pointer(&image[0]))
		return want
	})
	if !errors.Is(err, want) {
		t.Errorf("withStagedImage = %v, want %v", err, want)
	}
	if mbi := queryMemory(t, base); mbi.State != memFree {
		t.Errorf("staging memory at %#x has state %#x after a failed use, want free", base, mbi.State)
	}
}

func TestNewLazyDLLLoadsNothing(t *testing.T) {
	d := newLazyDLL("wintun.dll", dll, nil)
	p := d.NewProc("WintunGetRunningDriverVersion")
	if d.module.Load() != nil || d.Base != 0 || p.addr.Load() != 0 {
		t.Errorf("constructing a lazy DLL and proc loaded the module at %#x", d.Base)
	}
}

func TestLazyProcFindReturnsAnErrorForAnInvalidImage(t *testing.T) {
	d := newLazyDLL("wintun.dll", []byte("not a PE image"), nil)
	p := d.NewProc("WintunGetRunningDriverVersion")
	for i := range 2 {
		if err := p.Find(); err == nil {
			t.Fatalf("Find #%d of an invalid image = nil, want an error", i+1)
		}
	}
	if d.module.Load() != nil {
		t.Error("an invalid image left a module behind")
	}
}

func TestLazyDLLLoadReturnsAnErrorForAnInvalidImage(t *testing.T) {
	d := newLazyDLL("wintun.dll", []byte("not a PE image"), nil)
	if err := d.Load(); err == nil {
		t.Error("Load of an invalid image = nil, want an error")
	}
}

func TestLazyDLLLoadReturnsTheErrorOfOnLoadForAMissingExport(t *testing.T) {
	d := newLazyDLL("wintun.dll", dll, func(m *memmod.Module) error {
		_, err := m.ProcAddressByName("WintunNoSuchExport")
		return err
	})
	if err := d.NewProc("WintunGetRunningDriverVersion").Find(); err == nil {
		t.Error("Find = nil though onLoad failed, want its error")
	}
	if d.module.Load() != nil || d.Base != 0 {
		t.Error("a failed onLoad left the module loaded")
	}
}
