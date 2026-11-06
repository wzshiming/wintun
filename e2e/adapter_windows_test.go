package e2e

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/wzshiming/wintun"
)

// ttAdapterName names the test's adapter and its tunnel type.
const ttAdapterName = "WintunE2E"

// ttAdapterGUID fixes the adapter's GUID, so runs share one network profile.
var ttAdapterGUID = windows.GUID{Data1: 0x6b2a4b1e, Data2: 0x3f0d, Data3: 0x4c8e, Data4: [8]byte{0x9a, 0x51, 0x7e, 0x2c, 0x14, 0xd3, 0x60, 0xb7}}

// The adapter's address and the peer behind it, in the benchmarking range; port 9 is discard.
var (
	ttLocal = netip.MustParsePrefix("198.18.0.5/30")
	ttPeer  = netip.AddrPortFrom(netip.MustParseAddr("198.18.0.6"), 9)
)

var (
	modiphlpapi                         = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procConvertInterfaceLuidToIndex     = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceLuidToGuid      = modiphlpapi.NewProc("ConvertInterfaceLuidToGuid")
)

// ttUnicastRow is MIB_UNICASTIPADDRESS_ROW, whose NET_LUID is 8-byte aligned on 386 too, unlike in windows.MibUnicastIpAddressRow.
type ttUnicastRow struct {
	Address            windows.RawSockaddrInet6
	_                  [4]byte
	InterfaceLuid      uint64
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  int64
}

// Fail the build unless ttUnicastRow has the 80 bytes of MIB_UNICASTIPADDRESS_ROW.
var (
	_ [unsafe.Sizeof(ttUnicastRow{}) - 80]byte
	_ [80 - unsafe.Sizeof(ttUnicastRow{})]byte
)

// ttAddAddress assigns prefix to the interface luid without duplicate address detection, until the interface goes away.
func ttAddAddress(luid uint64, prefix netip.Prefix) error {
	var row ttUnicastRow
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	sa.Family = windows.AF_INET
	sa.Addr = prefix.Addr().As4()
	row.InterfaceLuid = luid
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.DadState = windows.IpDadStatePreferred
	if r, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// ttLUIDIndex returns the index of the interface luid, failing once the interface is gone.
func ttLUIDIndex(luid uint64) (uint32, error) {
	var index uint32
	if r, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index))); r != 0 {
		return 0, syscall.Errno(r)
	}
	return index, nil
}

func ttLUIDGUID(luid uint64) (windows.GUID, error) {
	var guid windows.GUID
	if r, _, _ := procConvertInterfaceLuidToGuid.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid))); r != 0 {
		return guid, syscall.Errno(r)
	}
	return guid, nil
}

// ttWaitFor polls cond every 200ms and fails t unless it holds within timeout.
func ttWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", timeout, msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ttUDPPacket builds an IPv4 datagram from src to dst carrying payload, with a zero UDP checksum, which IPv4 takes as none.
func ttUDPPacket(src, dst netip.AddrPort, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45 // version 4, 20-byte header
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64 // TTL
	p[9] = syscall.IPPROTO_UDP
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[10:], ttChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], src.Port())
	binary.BigEndian.PutUint16(p[22:], dst.Port())
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// ttChecksum is the Internet checksum of b, whose length is even.
func ttChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ttParseUDP returns the addresses and payload of packet if it is an IPv4 UDP datagram.
func ttParseUDP(packet []byte) (src, dst netip.AddrPort, payload []byte, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != syscall.IPPROTO_UDP {
		return
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 {
		return
	}
	udp := packet[ihl:]
	n := int(binary.BigEndian.Uint16(udp[4:]))
	if n < 8 || n > len(udp) {
		return
	}
	src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[12:16])), binary.BigEndian.Uint16(udp[0:]))
	dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[16:20])), binary.BigEndian.Uint16(udp[2:]))
	return src, dst, udp[8:n], true
}

// ttReceive reads the session's packets for up to a second and reports whether one was a UDP datagram from src to dst carrying payload.
func ttReceive(t *testing.T, session wintun.Session, src, dst netip.AddrPort, payload []byte) bool {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		packet, err := session.ReceivePacket()
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			windows.WaitForSingleObject(session.ReadWaitEvent(), 100)
			continue
		}
		if err != nil {
			t.Fatalf("ReceivePacket: %v", err)
		}
		gotSrc, gotDst, gotPayload, ok := ttParseUDP(packet)
		match := ok && gotSrc == src && gotDst == dst && bytes.Equal(gotPayload, payload)
		session.ReleaseReceivePacket(packet)
		if match {
			return true
		}
	}
	return false
}

// ttSend writes packet into the adapter through session, as if the peer had sent it.
func ttSend(t *testing.T, session wintun.Session, packet []byte) {
	t.Helper()
	buf, err := session.AllocateSendPacket(len(packet))
	if err != nil {
		t.Fatalf("AllocateSendPacket: %v", err)
	}
	copy(buf, packet)
	session.SendPacket(buf)
}

// ttEmulatedOnARM64 reports whether this is an amd64 process under emulation on arm64 Windows.
func ttEmulatedOnARM64(t *testing.T) bool {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		return false
	}
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		t.Fatalf("IsWow64Process2: %v", err)
	}
	return native == pe.IMAGE_FILE_MACHINE_ARM64
}

// TestE2EAdapter creates an adapter through the DLL the package loads from memory, sends a UDP datagram out through it
// and one back in, and removes it.
func TestE2EAdapter(t *testing.T) {
	if os.Getenv("WINTUN_E2E") != "1" {
		t.Skip("installs the Wintun driver and creates an adapter; set WINTUN_E2E=1 to run")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating an adapter needs an elevated process")
	}
	adapter, err := wintun.CreateAdapter(ttAdapterName, ttAdapterName, &ttAdapterGUID)
	if err != nil {
		t.Fatalf("CreateAdapter: %v", err)
	}
	open := true
	t.Cleanup(func() {
		if open {
			adapter.Close()
		}
	})

	var major, minor uint32
	if _, err := fmt.Sscanf(wintun.Version(), "%d.%d", &major, &minor); err != nil {
		t.Fatalf("Version %q: %v", wintun.Version(), err)
	}
	// The driver the DLL installs carries the DLL's major and minor version.
	if got, err := wintun.RunningVersion(); err != nil || got != major<<16|minor {
		t.Errorf("RunningVersion = %d.%d, %v; want the %d.%d driver of Wintun %s", got>>16, got&0xffff, err, major, minor, wintun.Version())
	}
	luid := adapter.LUID()
	if luid == 0 {
		t.Fatal("LUID = 0, want the adapter's")
	}
	index, err := ttLUIDIndex(luid)
	if err != nil {
		t.Fatalf("no interface has the adapter's LUID %#x: %v", luid, err)
	}
	if guid, err := ttLUIDGUID(luid); err != nil || guid != ttAdapterGUID {
		t.Errorf("adapter GUID = %v, %v; want the requested %v", guid, err, ttAdapterGUID)
	}
	if iface, err := net.InterfaceByIndex(int(index)); err != nil || iface.Name != ttAdapterName {
		t.Errorf("interface %d = %+v, %v; want it named %s", index, iface, err, ttAdapterName)
	}

	session, err := adapter.StartSession(0x400000)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	running := true
	t.Cleanup(func() {
		if running {
			session.End()
		}
	})
	if event := session.ReadWaitEvent(); event == 0 {
		t.Fatal("ReadWaitEvent = 0, want the session's event")
	}
	if err := ttAddAddress(luid, ttLocal); err != nil {
		t.Fatalf("assign %s: %v", ttLocal, err)
	}

	// The host routes a datagram for the peer out through the adapter, where the session reads it.
	var conn *net.UDPConn
	ttWaitFor(t, 10*time.Second, func() bool {
		conn, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ttLocal.Addr(), 0)), net.UDPAddrFromAddrPort(ttPeer))
		return err == nil
	}, "a UDP socket on "+ttLocal.Addr().String())
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	request := []byte("wintun e2e request")
	ttWaitFor(t, 10*time.Second, func() bool {
		if _, err := conn.Write(request); err != nil {
			t.Logf("send to %s: %v", ttPeer, err)
			return false
		}
		return ttReceive(t, session, local, ttPeer, request)
	}, "the session to read the datagram sent to "+ttPeer.String())

	// A datagram the session writes reaches the socket as the peer's reply.
	reply := []byte("wintun e2e reply")
	buf := make([]byte, 64)
	ttWaitFor(t, 10*time.Second, func() bool {
		ttSend(t, session, ttUDPPacket(ttPeer, local, reply))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		return err == nil && bytes.Equal(buf[:n], reply)
	}, "the socket to read the datagram the session wrote")

	session.End()
	running = false
	// WintunCloseAdapter returns nothing, so the error Close derives from it means nothing.
	adapter.Close()
	open = false
	if ttEmulatedOnARM64(t) {
		// The embedded Wintun Version removes it through %WINDIR%\Sysnative\rundll32.exe, which only WOW64 processes have.
		t.Log("an amd64 process on arm64 Windows cannot remove its adapter; not waiting for it to go away")
		return
	}
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := ttLUIDIndex(luid)
		return err != nil
	}, "the adapter to go away")
}
