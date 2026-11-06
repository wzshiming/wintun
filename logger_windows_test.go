package wintun

import (
	"bytes"
	"log"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The exported logging API, pinned at compile time.
var (
	_ func(Logger)                      = SetLogger
	_ func(LogLevel, time.Time, string) = Logger(nil)
	_ [3]LogLevel                       = [...]LogLevel{LogInfo, LogWarn, LogErr}
)

// ttFiletime is 2021-02-03T04:05:06.789Z as a FILETIME, 100-ns intervals since 1601-01-01 UTC.
var ttFiletime uint64 = 132567987067890000

var ttFiletimeUTC = time.Date(2021, 2, 3, 4, 5, 6, 789000000, time.UTC)

// ttUTF16 returns s as the NUL-terminated UTF-16 string the DLL passes.
func ttUTF16(t *testing.T, s string) *uint16 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ttStdLogger points the standard logger at w with prefix and no flags until the test ends.
func ttStdLogger(t *testing.T, w interface{ Write([]byte) (int, error) }, prefix string) {
	t.Helper()
	out, oldPrefix, flags := log.Writer(), log.Prefix(), log.Flags()
	log.SetOutput(w)
	log.SetPrefix(prefix)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(out)
		log.SetPrefix(oldPrefix)
		log.SetFlags(flags)
	})
}

type ttLogEntry struct {
	level     LogLevel
	timestamp time.Time
	message   string
}

// ttRecord installs a Logger recording what it receives until the test ends, then restores the default.
func ttRecord(t *testing.T) func() []ttLogEntry {
	t.Helper()
	var mu sync.Mutex
	var entries []ttLogEntry
	SetLogger(func(level LogLevel, timestamp time.Time, message string) {
		mu.Lock()
		defer mu.Unlock()
		entries = append(entries, ttLogEntry{level, timestamp, message})
	})
	t.Cleanup(func() { SetLogger(nil) })
	return func() []ttLogEntry {
		mu.Lock()
		defer mu.Unlock()
		return append([]ttLogEntry(nil), entries...)
	}
}

// ttTimestampedWriter is unsynchronised on purpose: under -race it pins that logMessage serialises its writes.
type ttTimestampedWriter struct {
	p  []byte
	ts int64
}

func (w *ttTimestampedWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *ttTimestampedWriter) WriteWithTimestamp(p []byte, ts int64) (int, error) {
	w.p, w.ts = append([]byte(nil), p...), ts
	return len(p), nil
}

func TestDefaultLogPrintsTheMessageToAPlainWriter(t *testing.T) {
	var buf bytes.Buffer
	ttStdLogger(t, &buf, "wintun: ")
	logMessage(LogInfo, ttFiletime, ttUTF16(t, "Creating adapter"))
	if got, want := buf.String(), "wintun: Creating adapter\n"; got != want {
		t.Errorf("standard logger got %q, want %q", got, want)
	}
}

func TestDefaultLogHandsATimestampedWriterThePrefixedMessageAndUnixNanoseconds(t *testing.T) {
	var w ttTimestampedWriter
	ttStdLogger(t, &w, "wintun: ")
	logMessage(LogInfo, ttFiletime, ttUTF16(t, "Creating adapter"))
	if got, want := string(w.p), "wintun: Creating adapter"; got != want {
		t.Errorf("WriteWithTimestamp got %q, want %q", got, want)
	}
	if want := ttFiletimeUTC.UnixNano(); w.ts != want {
		t.Errorf("WriteWithTimestamp got timestamp %d, want %d", w.ts, want)
	}
}

func TestSetLoggerReceivesEveryLevel(t *testing.T) {
	entries := ttRecord(t)
	for _, level := range []LogLevel{LogInfo, LogWarn, LogErr} {
		logMessage(level, ttFiletime, ttUTF16(t, "m"))
	}
	var got []LogLevel
	for _, e := range entries() {
		got = append(got, e.level)
	}
	if want := []LogLevel{LogInfo, LogWarn, LogErr}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("Logger got levels %v, want %v", got, want)
	}
}

func TestLogLevelsAreWintunsLoggerLevels(t *testing.T) {
	if LogInfo != 0 || LogWarn != 1 || LogErr != 2 {
		t.Errorf("LogInfo, LogWarn, LogErr = %d, %d, %d; want WINTUN_LOG_INFO, WARN, ERR = 0, 1, 2", LogInfo, LogWarn, LogErr)
	}
}

func TestLoggerGetsTheFiletimeAsUTCTime(t *testing.T) {
	entries := ttRecord(t)
	logMessage(LogInfo, ttFiletime, ttUTF16(t, "m"))
	got := entries()
	if len(got) != 1 || !got[0].timestamp.Equal(ttFiletimeUTC) || got[0].timestamp.Location() != time.UTC {
		t.Errorf("Logger got %+v, want one entry at %v", got, ttFiletimeUTC)
	}
}

func TestLoggerGetsTheMessageDecodedFromUTF16(t *testing.T) {
	entries := ttRecord(t)
	const message = "Adapter \u201cwg0\u201d: \u00e9t\u00e9 \U0001F600"
	logMessage(LogWarn, ttFiletime, ttUTF16(t, message))
	if got := entries(); len(got) != 1 || got[0].message != message {
		t.Errorf("Logger got %+v, want message %q", got, message)
	}
}

func TestAPanickingLoggerDropsTheMessageAndLaterOnesStillArrive(t *testing.T) {
	SetLogger(func(LogLevel, time.Time, string) { panic("consumer logger") })
	t.Cleanup(func() { SetLogger(nil) })
	if r := logMessage(LogErr, ttFiletime, ttUTF16(t, "dropped")); r != 0 {
		t.Errorf("logMessage = %d after a panicking Logger, want 0", r)
	}
	entries := ttRecord(t)
	logMessage(LogInfo, ttFiletime, ttUTF16(t, "kept"))
	if got := entries(); len(got) != 1 || got[0].message != "kept" {
		t.Errorf("Logger got %+v after a panic, want the next message", got)
	}
}

func TestSetLoggerIsSafeConcurrentlyWithTheCallback(t *testing.T) {
	t.Cleanup(func() { SetLogger(nil) })
	ttStdLogger(t, &ttTimestampedWriter{}, "")
	msg := ttUTF16(t, "m")
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				if i%2 == 0 {
					SetLogger(func(LogLevel, time.Time, string) {})
				} else {
					SetLogger(nil)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				logMessage(LogInfo, ttFiletime, msg)
			}
		}()
	}
	wg.Wait()
}

func TestSetLoggerNilRestoresTheDefault(t *testing.T) {
	var buf bytes.Buffer
	ttStdLogger(t, &buf, "")
	entries := ttRecord(t)
	SetLogger(nil)
	logMessage(LogInfo, ttFiletime, ttUTF16(t, "default"))
	if got := entries(); len(got) != 0 {
		t.Errorf("Logger got %+v after SetLogger(nil), want nothing", got)
	}
	if got, want := buf.String(), "default\n"; got != want {
		t.Errorf("standard logger got %q after SetLogger(nil), want %q", got, want)
	}
}

// TestLoggerCallbackTakesWintunsCallingConvention calls the callback handed to WintunSetLogger as the DLL does: on 386
// the DWORD64 timestamp takes two 32-bit stack slots, on amd64 and arm64 one register.
func TestLoggerCallbackTakesWintunsCallingConvention(t *testing.T) {
	entries := ttRecord(t)
	msg := ttUTF16(t, "abi")
	callback := loggerCallback()
	if callback == 0 {
		t.Fatal("loggerCallback = 0, want a callback")
	}
	if runtime.GOARCH == "386" {
		syscall.SyscallN(callback, uintptr(LogWarn), uintptr(uint32(ttFiletime)), uintptr(ttFiletime>>32), uintptr(unsafe.Pointer(msg)))
	} else {
		syscall.SyscallN(callback, uintptr(LogWarn), uintptr(ttFiletime), uintptr(unsafe.Pointer(msg)))
	}
	runtime.KeepAlive(msg)
	got := entries()
	if len(got) != 1 || got[0].level != LogWarn || !got[0].timestamp.Equal(ttFiletimeUTC) || got[0].message != "abi" {
		t.Errorf("Logger got %+v through the callback, want one LogWarn %q at %v", got, "abi", ttFiletimeUTC)
	}
}

// ttLoggerAdapterGUID differs from TestE2EAdapter's adapter, so the two tests never share one.
var ttLoggerAdapterGUID = windows.GUID{Data1: 0x1f6c3a92, Data2: 0x7d40, Data3: 0x4b15, Data4: [8]byte{0x8e, 0x27, 0xc3, 0x5a, 0x90, 0x4d, 0x16, 0xe8}}

// TestE2ELogger has the DLL log through a Logger while it creates and closes an adapter and fails to open a missing
// one, which runs the callback with the DLL's own calling convention.
func TestE2ELogger(t *testing.T) {
	if os.Getenv("WINTUN_E2E") != "1" {
		t.Skip("installs the Wintun driver and creates an adapter; set WINTUN_E2E=1 to run")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating an adapter needs an elevated process")
	}
	entries := ttRecord(t)
	adapter, err := CreateAdapter("WintunE2ELogger", "WintunE2ELogger", &ttLoggerAdapterGUID)
	if err != nil {
		t.Fatalf("CreateAdapter: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if missing, err := OpenAdapter("WintunE2ELoggerMissing"); err == nil {
		missing.Close()
		t.Error("OpenAdapter of a missing adapter succeeded")
	}
	now := time.Now()
	got := entries()
	if len(got) == 0 {
		t.Fatal("the DLL logged nothing through the Logger")
	}
	for _, e := range got {
		t.Logf("%d %v %s", e.level, e.timestamp, e.message)
		if e.level != LogInfo && e.level != LogWarn && e.level != LogErr {
			t.Errorf("level %d of %q, want LogInfo, LogWarn or LogErr", e.level, e.message)
		}
		if d := now.Sub(e.timestamp); d < -5*time.Minute || d > 5*time.Minute {
			t.Errorf("timestamp %v of %q is %v from now, want within 5 minutes", e.timestamp, e.message, d)
		}
		if e.message == "" {
			t.Errorf("empty message at level %d", e.level)
		}
	}
}
