package wintun

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"maps"
	"slices"
	"strings"
	"testing"
)

// ttImports are the libraries each embedded DLL imports, by release directory: memmod resolves them from System32 only.
var ttImports = map[string][]string{
	"x86":   {"kernel32.dll", "ntdll.dll"},
	"amd64": {"kernel32.dll", "ntdll.dll"},
	"arm64": {"kernel32.dll", "ntdll.dll"},
}

// ttDelayImports are the libraries each embedded DLL delay-loads, by release directory.
var ttDelayImports = map[string][]string{
	"x86": {"advapi32.dll", "api-ms-win-devices-query-l1-1-0.dll", "api-ms-win-devices-swdevice-l1-1-0.dll", "cfgmgr32.dll",
		"iphlpapi.dll", "nci.dll", "ole32.dll", "setupapi.dll", "shell32.dll", "shlwapi.dll", "version.dll"},
	"amd64": {"advapi32.dll", "api-ms-win-devices-query-l1-1-0.dll", "api-ms-win-devices-swdevice-l1-1-0.dll", "cfgmgr32.dll",
		"iphlpapi.dll", "nci.dll", "ole32.dll", "setupapi.dll", "shell32.dll", "shlwapi.dll", "version.dll"},
	"arm64": {"advapi32.dll", "api-ms-win-devices-query-l1-1-0.dll", "api-ms-win-devices-swdevice-l1-1-0.dll", "cfgmgr32.dll",
		"iphlpapi.dll", "nci.dll", "ole32.dll", "setupapi.dll", "shlwapi.dll", "version.dll"},
}

// ttDelayImportedLibraries returns the DLL names of f's delay-load import directory, which debug/pe does not parse.
func ttDelayImportedLibraries(t *testing.T, f *pe.File) []string {
	t.Helper()
	const imageDirectoryEntryDelayImport = 13
	var dir pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[imageDirectoryEntryDelayImport]
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[imageDirectoryEntryDelayImport]
	}
	// at returns the image's bytes from the relative virtual address rva to the end of its section.
	at := func(rva uint32) []byte {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
				data, err := s.Data()
				if err != nil {
					t.Fatal(err)
				}
				if off := rva - s.VirtualAddress; off < uint32(len(data)) {
					return data[off:]
				}
			}
		}
		t.Fatalf("RVA %#x is in no section", rva)
		return nil
	}
	var libs []string
	if dir.Size == 0 {
		return libs
	}
	// Each 32-byte IMAGE_DELAYLOAD_DESCRIPTOR holds the RVA of its DLL name at offset 4; a zeroed one ends the table.
	table := at(dir.VirtualAddress)
	for i := 0; i+32 <= len(table); i += 32 {
		nameRVA := binary.LittleEndian.Uint32(table[i+4:])
		if nameRVA == 0 {
			break
		}
		name, _, _ := bytes.Cut(at(nameRVA), []byte{0})
		libs = append(libs, string(name))
	}
	return libs
}

func TestEmbeddedDLLsImportOnlyTheseSystemLibraries(t *testing.T) {
	for _, dir := range []string{"x86", "amd64", "arm64"} {
		t.Run(dir, func(t *testing.T) {
			f, err := pe.NewFile(bytes.NewReader(ttEmbeddedFile(t, "bin/"+dir+"/wintun.dll")))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// debug/pe returns imports as "symbol:library"; ImportedLibraries returns nothing for PE files.
			symbols, err := f.ImportedSymbols()
			if err != nil {
				t.Fatal(err)
			}
			libs := make(map[string]bool)
			for _, s := range symbols {
				_, lib, _ := strings.Cut(s, ":")
				libs[strings.ToLower(lib)] = true
			}
			if got := slices.Sorted(maps.Keys(libs)); !slices.Equal(got, ttImports[dir]) {
				t.Errorf("imports %q, want %q", got, ttImports[dir])
			}
			delayed := make(map[string]bool)
			for _, lib := range ttDelayImportedLibraries(t, f) {
				delayed[strings.ToLower(lib)] = true
			}
			if got := slices.Sorted(maps.Keys(delayed)); !slices.Equal(got, ttDelayImports[dir]) {
				t.Errorf("delay-loads %q, want %q", got, ttDelayImports[dir])
			}
		})
	}
}
