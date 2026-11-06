/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"log"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

// LogLevel is the severity of a message the Wintun DLL logs, its WINTUN_LOGGER_LEVEL.
type LogLevel int

const (
	LogInfo LogLevel = iota // WINTUN_LOG_INFO: informational
	LogWarn                 // WINTUN_LOG_WARN: warning
	LogErr                  // WINTUN_LOG_ERR: error
)

// Logger receives each message the Wintun DLL logs, with its level and its time in UTC. The DLL calls it on its own
// threads, possibly concurrently; a panic in it is recovered and drops the message.
type Logger func(level LogLevel, timestamp time.Time, message string)

// TimestampedWriter is a writer of the standard logger that takes the DLL's messages with their time, in nanoseconds
// since the Unix epoch, when no Logger is set.
type TimestampedWriter interface {
	WriteWithTimestamp(p []byte, ts int64) (n int, err error)
}

var logger atomic.Pointer[Logger]

// SetLogger routes the DLL's log messages to l, before or after the DLL loads. A nil l restores the default: the
// standard logger's TimestampedWriter if its writer is one, log.Println otherwise.
func SetLogger(l Logger) {
	if l == nil {
		logger.Store(nil)
		return
	}
	logger.Store(&l)
}

// logMessage is the WINTUN_LOGGER_CALLBACK; timestamp is a FILETIME.
func logMessage(level LogLevel, timestamp uint64, msg *uint16) int {
	// A panic must not unwind into the DLL's thread.
	defer func() { recover() }()
	message := windows.UTF16PtrToString(msg)
	if l := logger.Load(); l != nil {
		ft := windows.Filetime{LowDateTime: uint32(timestamp), HighDateTime: uint32(timestamp >> 32)}
		(*l)(level, time.Unix(0, ft.Nanoseconds()).UTC(), message)
		return 0
	}
	if tw, ok := log.Default().Writer().(TimestampedWriter); ok {
		tw.WriteWithTimestamp([]byte(log.Default().Prefix()+message), (int64(timestamp)-116444736000000000)*100)
	} else {
		log.Println(message)
	}
	return 0
}

// loggerCallback returns logMessage as a WINTUN_LOGGER_CALLBACK for the windows/386, amd64 and arm64 builds, the only
// ones that embed a DLL: 386 passes the DWORD64 timestamp as two 32-bit halves, amd64 and arm64 as one 64-bit value.
func loggerCallback() uintptr {
	if runtime.GOARCH == "386" {
		return windows.NewCallback(func(level LogLevel, timestampLow, timestampHigh uint32, msg *uint16) int {
			return logMessage(level, uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	}
	return windows.NewCallback(logMessage)
}

func setupLogger(module *memmod.Module) error {
	setLogger, err := module.ProcAddressByName("WintunSetLogger")
	if err != nil {
		return err
	}
	syscall.Syscall(setLogger, 1, loggerCallback(), 0, 0)
	return nil
}
