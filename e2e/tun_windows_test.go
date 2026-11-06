package e2e

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/wzshiming/wintun/tun"
)

const ttTUNName = "WintunE2ETUN"

var ttTUNGUID = windows.GUID{Data1: 0x3c9e7d42, Data2: 0x81a5, Data3: 0x4f6b, Data4: [8]byte{0xb0, 0x2d, 0x5e, 0x97, 0x1a, 0x4c, 0x08, 0xe3}}

// A /30 apart from TestE2EAdapter's, so the two tests never share a route.
var (
	ttTUNLocal = netip.MustParsePrefix("198.18.0.9/30")
	ttTUNPeer  = netip.AddrPortFrom(netip.MustParseAddr("198.18.0.10"), 9)
)

// ttTUNOffset is the headroom wireguard-go leaves before each packet in its buffers.
const ttTUNOffset = 16

// TestE2ETUN creates a wireguard-go tun.Device through the tun subpackage, reads a UDP datagram the host sends through
// it, writes one back that a host socket receives, and closes it.
func TestE2ETUN(t *testing.T) {
	if os.Getenv("WINTUN_E2E") != "1" {
		t.Skip("installs the Wintun driver and creates an adapter; set WINTUN_E2E=1 to run")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating an adapter needs an elevated process")
	}
	guid := ttTUNGUID
	dev, err := tun.CreateTUNWithRequestedGUID(ttTUNName, &guid, 0)
	if err != nil {
		t.Fatalf("CreateTUNWithRequestedGUID: %v", err)
	}
	open := true
	t.Cleanup(func() {
		if open {
			dev.Close()
		}
	})
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		t.Fatalf("CreateTUNWithRequestedGUID returned a %T, want a *tun.NativeTun", dev)
	}

	if name, err := dev.Name(); err != nil || name != ttTUNName {
		t.Errorf("Name = %q, %v; want %q", name, err, ttTUNName)
	}
	luid := native.LUID()
	if luid == 0 {
		t.Fatal("LUID = 0, want the adapter's")
	}
	if _, err := winipcfg.LUID(luid).Interface(); err != nil {
		t.Fatalf("no interface has the device's LUID %#x: %v", luid, err)
	}
	if got, err := winipcfg.LUID(luid).GUID(); err != nil || *got != ttTUNGUID {
		t.Errorf("interface GUID = %v, %v; want the requested %v", got, err, ttTUNGUID)
	}
	if err := winipcfg.LUID(luid).AddIPAddress(ttTUNLocal); err != nil {
		t.Fatalf("assign %s: %v", ttTUNLocal, err)
	}

	// Read blocks until a packet comes or the device closes, so a goroutine feeds the packets to the test's deadlines.
	packets := make(chan []byte, 16)
	readDone := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, ttTUNOffset+1500)}
		sizes := make([]int, 1)
		for {
			n, err := dev.Read(bufs, sizes, ttTUNOffset)
			if err != nil {
				readDone <- err
				return
			}
			if n == 1 {
				// Dropping when full keeps the goroutine reading, so it sees Close.
				select {
				case packets <- bytes.Clone(bufs[0][ttTUNOffset : ttTUNOffset+sizes[0]]):
				default:
				}
			}
		}
	}()

	// The host routes a datagram for the peer out through the device, where Read returns it.
	var conn *net.UDPConn
	ttWaitFor(t, 10*time.Second, func() bool {
		conn, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ttTUNLocal.Addr(), 0)), net.UDPAddrFromAddrPort(ttTUNPeer))
		return err == nil
	}, "a UDP socket on "+ttTUNLocal.Addr().String())
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	request := []byte("wintun tun e2e request")
	ttWaitFor(t, 10*time.Second, func() bool {
		if _, err := conn.Write(request); err != nil {
			t.Logf("send to %s: %v", ttTUNPeer, err)
			return false
		}
		timeout := time.After(time.Second)
		for {
			select {
			case packet := <-packets:
				if src, dst, payload, ok := ttParseUDP(packet); ok && src == local && dst == ttTUNPeer && bytes.Equal(payload, request) {
					return true
				}
			case err := <-readDone:
				t.Fatalf("Read: %v", err)
			case <-timeout:
				return false
			}
		}
	}, "Read to return the datagram sent to "+ttTUNPeer.String())

	// A datagram Write takes in reaches the socket as the peer's reply.
	reply := []byte("wintun tun e2e reply")
	buf := make([]byte, 64)
	ttWaitFor(t, 10*time.Second, func() bool {
		packet := append(make([]byte, ttTUNOffset), ttUDPPacket(ttTUNPeer, local, reply)...)
		if n, err := dev.Write([][]byte{packet}, ttTUNOffset); n != 1 || err != nil {
			t.Fatalf("Write = %d, %v; want 1, nil", n, err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		return err == nil && bytes.Equal(buf[:n], reply)
	}, "the socket to read the datagram Write took in")

	if err := dev.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	open = false
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("Read after Close = %v, want %v", err, os.ErrClosed)
		}
	case <-time.After(10 * time.Second):
		t.Error("Read still blocks 10s after Close")
	}
	if ttEmulatedOnARM64(t) {
		// The embedded Wintun removes it through %WINDIR%\Sysnative\rundll32.exe, which only WOW64 processes have.
		t.Log("an amd64 process on arm64 Windows cannot remove its adapter; not waiting for it to go away")
		return
	}
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := ttLUIDIndex(luid)
		return err != nil
	}, "the interface to go away")
}
