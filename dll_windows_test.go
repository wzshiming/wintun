package wintun

import (
	"testing"

	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

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
