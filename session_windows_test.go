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
