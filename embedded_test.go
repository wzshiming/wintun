package wintun

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ttMachines are the PE machine types of the DLLs under embedded/bin, by the release's directory name.
var ttMachines = map[string]uint16{
	"x86":   pe.IMAGE_FILE_MACHINE_I386,
	"amd64": pe.IMAGE_FILE_MACHINE_AMD64,
	"arm64": pe.IMAGE_FILE_MACHINE_ARM64,
	"arm":   pe.IMAGE_FILE_MACHINE_ARMNT,
}

func ttEmbeddedFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("embedded", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// ttSigner returns the certificate of the first signer of the Authenticode signature of the PE file f, whose bytes are data.
func ttSigner(t *testing.T, f *pe.File, data []byte) *x509.Certificate {
	t.Helper()
	var dir pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	}
	// The security directory gives the file offset of a WIN_CERTIFICATE: length, revision, type, then the signature.
	end := uint64(dir.VirtualAddress) + uint64(dir.Size)
	if dir.Size < 8 || end > uint64(len(data)) {
		t.Fatalf("no Authenticode signature: security directory %+v in %d bytes", dir, len(data))
	}
	cert := data[dir.VirtualAddress:end]
	size := binary.LittleEndian.Uint32(cert)
	const winCertTypePKCSSignedData = 2
	if size < 8 || size > dir.Size || binary.LittleEndian.Uint16(cert[6:]) != winCertTypePKCSSignedData {
		t.Fatalf("WIN_CERTIFICATE header %x holds no PKCS #7 SignedData", cert[:8])
	}
	var info struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(cert[8:size], &info); err != nil {
		t.Fatalf("ContentInfo: %v", err)
	}
	// SignedData is version, digest algorithms, content, optional [0] certificates and [1] CRLs, then signer infos.
	var signedData []asn1.RawValue
	if _, err := asn1.Unmarshal(info.Content.Bytes, &signedData); err != nil || len(signedData) < 4 {
		t.Fatalf("SignedData of %d elements: %v", len(signedData), err)
	}
	var certs []*x509.Certificate
	for _, e := range signedData {
		if e.Class == asn1.ClassContextSpecific && e.Tag == 0 {
			var err error
			if certs, err = x509.ParseCertificates(e.Bytes); err != nil {
				t.Fatalf("certificates: %v", err)
			}
		}
	}
	var signerInfos []asn1.RawValue
	if _, err := asn1.UnmarshalWithParams(signedData[len(signedData)-1].FullBytes, &signerInfos, "set"); err != nil || len(signerInfos) == 0 {
		t.Fatalf("%d signer infos: %v", len(signerInfos), err)
	}
	var signer struct {
		Version int
		ID      struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
	}
	if _, err := asn1.Unmarshal(signerInfos[0].FullBytes, &signer); err != nil {
		t.Fatalf("signer info: %v", err)
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, signer.ID.Issuer.FullBytes) && c.SerialNumber.Cmp(signer.ID.Serial) == 0 {
			return c
		}
	}
	t.Fatalf("none of the %d certificates is the signer's", len(certs))
	return nil
}

func TestEmbeddedHoldsOnlyTheLicenseAndADLLPerReleaseDirectory(t *testing.T) {
	var got []string
	err := filepath.WalkDir("embedded", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel("embedded", path)
			got = append(got, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"LICENSE.txt"}
	for dir := range ttMachines {
		want = append(want, "bin/"+dir+"/wintun.dll")
	}
	slices.Sort(got)
	if slices.Sort(want); !slices.Equal(got, want) {
		t.Errorf("embedded holds %q, want %q", got, want)
	}
}

func TestEmbeddedDLLsAreSignedByWireGuardForTheirArchitecture(t *testing.T) {
	for dir, machine := range ttMachines {
		t.Run(dir, func(t *testing.T) {
			data := ttEmbeddedFile(t, "bin/"+dir+"/wintun.dll")
			f, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if f.Machine != machine || f.Characteristics&pe.IMAGE_FILE_DLL == 0 {
				t.Errorf("machine %#x, characteristics %#x; want a DLL for machine %#x", f.Machine, f.Characteristics, machine)
			}
			if signer := ttSigner(t, f, data); !slices.Contains(signer.Subject.Organization, "WireGuard LLC") {
				t.Errorf("signed by %s, want WireGuard LLC", signer.Subject)
			}
		})
	}
}

func TestREADMEDocumentsTheEmbeddedFilesAndVersion(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Wintun " + Version + ",", "wintun-" + Version + ".zip"} {
		if !bytes.Contains(readme, []byte(s)) {
			t.Errorf("README.md lacks %q", s)
		}
	}
	names := []string{"LICENSE.txt"}
	for dir := range ttMachines {
		names = append(names, "bin/"+dir+"/wintun.dll")
	}
	lines := strings.Split(string(readme), "\n")
	for _, name := range names {
		sum := sha256.Sum256(ttEmbeddedFile(t, name))
		row := "| [embedded/" + name + "](embedded/" + name + ") |"
		if !slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, row) && strings.Contains(l, "`"+hex.EncodeToString(sum[:])+"`")
		}) {
			t.Errorf("README.md has no table row for embedded/%s with its SHA-256 %x", name, sum)
		}
	}
}
