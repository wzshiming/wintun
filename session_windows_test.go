package wintun

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

// ttClosedAdapter fails t unless adapter behaves as closed.
func ttClosedAdapter(t *testing.T, name string, adapter *Adapter) {
	t.Helper()
	for i := range 2 {
		if err := adapter.Close(); err != nil {
			t.Errorf("%s adapter: Close #%d = %v, want nil", name, i+1, err)
		}
	}
	if luid := adapter.LUID(); luid != 0 {
		t.Errorf("%s adapter: LUID = %#x, want 0", name, luid)
	}
	if session, err := adapter.StartSession(RingCapacityMin); session != nil || !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Errorf("%s adapter: StartSession = %v, %v; want nil, ERROR_INVALID_HANDLE", name, session, err)
	}
}

// ttEndedSession fails t unless session behaves as ended.
func ttEndedSession(t *testing.T, name string, session *Session) {
	t.Helper()
	session.End()
	if event := session.ReadWaitEvent(); event != 0 {
		t.Errorf("%s session: ReadWaitEvent = %#x, want 0", name, event)
	}
	if packet, err := session.ReceivePacket(); packet != nil || !errors.Is(err, windows.ERROR_HANDLE_EOF) {
		t.Errorf("%s session: ReceivePacket = %v, %v; want nil, ERROR_HANDLE_EOF", name, packet, err)
	}
	if packet, err := session.AllocateSendPacket(1); packet != nil || !errors.Is(err, windows.ERROR_HANDLE_EOF) {
		t.Errorf("%s session: AllocateSendPacket = %v, %v; want nil, ERROR_HANDLE_EOF", name, packet, err)
	}
	session.ReleaseReceivePacket(make([]byte, 1))
	session.SendPacket(make([]byte, 1))
	session.ReleaseReceivePacket(nil)
	session.SendPacket(nil)
}

// ttCount makes each of procs, DLL functions of two arguments, count its calls in n until the test ends.
func ttCount(t *testing.T, n *atomic.Int32, procs ...*lazyProc) {
	t.Helper()
	count := func(_, _ uintptr) uintptr {
		n.Add(1)
		return 0
	}
	for _, p := range procs {
		ttStub(t, p, count)
	}
}

func TestPacketsHandBackTheAddressTheDLLReturned(t *testing.T) {
	ring, err := windows.VirtualAlloc(0, PacketSizeMax, windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.VirtualFree(ring, 0, windows.MEM_RELEASE)
	var size uint32
	var allocated, released, sent uintptr
	ttStub(t, procWintunReceivePacket, func(_ uintptr, packetSize *uint32) uintptr {
		*packetSize = size
		return ring
	})
	ttStub(t, procWintunAllocateSendPacket, func(_, packetSize uintptr) uintptr {
		allocated = packetSize
		return ring
	})
	ttStub(t, procWintunReleaseReceivePacket, func(_, packet uintptr) uintptr {
		released = packet
		return 0
	})
	ttStub(t, procWintunSendPacket, func(_, packet uintptr) uintptr {
		sent = packet
		return 0
	})
	session := ttSession(1)
	for _, n := range []int{0, PacketSizeMax} {
		size, released, sent = uint32(n), 0, 0
		packet, err := session.ReceivePacket()
		if err != nil || len(packet) != n {
			t.Fatalf("ReceivePacket of %d bytes = %d bytes, %v", n, len(packet), err)
		}
		session.ReleaseReceivePacket(packet)
		if released != ring {
			t.Errorf("ReleaseReceivePacket of %d bytes handed %#x to the DLL, want %#x", n, released, ring)
		}
		packet, err = session.AllocateSendPacket(n)
		if err != nil || len(packet) != n || allocated != uintptr(n) {
			t.Fatalf("AllocateSendPacket(%d) = %d bytes, %v, asking the DLL for %d", n, len(packet), err, allocated)
		}
		session.SendPacket(packet)
		if sent != ring {
			t.Errorf("SendPacket of %d bytes handed %#x to the DLL, want %#x", n, sent, ring)
		}
	}
}

func TestConcurrentClosesHandTheHandleToTheDLLOnce(t *testing.T) {
	var closed atomic.Uintptr
	ttStub(t, procWintunCloseAdapter, func(handle uintptr) uintptr {
		closed.Add(handle)
		return 0
	})
	var deadUse atomic.Int32
	ttCount(t, &deadUse, procWintunGetAdapterLUID, procWintunStartSession)
	adapter := ttAdapter(1)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = adapter.Close()
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Close #%d = %v, want nil", i+1, err)
		}
	}
	ttClosedAdapter(t, "closed", adapter)
	if got := closed.Load(); got != 1 {
		t.Errorf("WintunCloseAdapter got handles summing to %d, want the handle once", got)
	}
	if n := deadUse.Load(); n != 0 {
		t.Errorf("a closed adapter's handle reached the DLL %d times", n)
	}
}

func TestConcurrentEndsHandTheHandleToTheDLLOnce(t *testing.T) {
	var ended atomic.Uintptr
	ttStub(t, procWintunEndSession, func(handle uintptr) uintptr {
		ended.Add(handle)
		return 0
	})
	var deadUse atomic.Int32
	ttStub(t, procWintunGetReadWaitEvent, func(uintptr) uintptr {
		deadUse.Add(1)
		return 0
	})
	ttCount(t, &deadUse, procWintunReceivePacket, procWintunReleaseReceivePacket, procWintunAllocateSendPacket, procWintunSendPacket)
	session := ttSession(1)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.End()
		}()
	}
	wg.Wait()
	ttEndedSession(t, "ended", session)
	if got := ended.Load(); got != 1 {
		t.Errorf("WintunEndSession got handles summing to %d, want the handle once", got)
	}
	if n := deadUse.Load(); n != 0 {
		t.Errorf("an ended session's handle reached the DLL %d times", n)
	}
}
