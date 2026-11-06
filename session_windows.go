/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Session is a session on an Adapter; it keeps that adapter alive, and End does not close it.
type Session struct {
	handle  atomic.Uintptr
	adapter *Adapter
}

// live returns the session's handle, or 0 for an ended, zero or nil Session.
func (session *Session) live() uintptr {
	if session == nil {
		return 0
	}
	return session.handle.Load()
}

const (
	PacketSizeMax   = 0xffff    // Maximum packet size
	RingCapacityMin = 0x20000   // Minimum ring capacity (128 kiB)
	RingCapacityMax = 0x4000000 // Maximum ring capacity (64 MiB)
)

// Packet with data
type Packet struct {
	Next *Packet              // Pointer to next packet in queue
	Size uint32               // Size of packet (max WINTUN_MAX_IP_PACKET_SIZE)
	Data *[PacketSizeMax]byte // Pointer to layer 3 IPv4 or IPv6 packet
}

var (
	procWintunAllocateSendPacket   = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession           = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket           = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession         = modwintun.NewProc("WintunStartSession")
)

// ringPointer returns the address r, returned by the DLL into its ring, as a pointer; go vet flags converting it directly.
func ringPointer(r uintptr) *byte {
	return *(**byte)(unsafe.Pointer(&r))
}

// StartSession starts a session on the adapter; for a closed, zero or nil Adapter it returns windows.ERROR_INVALID_HANDLE.
func (wintun *Adapter) StartSession(capacity uint32) (*Session, error) {
	handle := wintun.live()
	if handle == 0 {
		return nil, windows.ERROR_INVALID_HANDLE
	}
	addr, err := procWintunStartSession.address()
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.Syscall(addr, 2, handle, uintptr(capacity), 0)
	runtime.KeepAlive(wintun)
	if r0 == 0 {
		return nil, errnoErr(e1)
	}
	session := &Session{adapter: wintun}
	session.handle.Store(r0)
	return session, nil
}

// End ends the session, handing its handle to the DLL once; it does nothing for an ended, zero or nil Session.
// Readers must be stopped first, by setting ReadWaitEvent's event and waiting for them.
func (session *Session) End() {
	if session.live() == 0 {
		return
	}
	addr, err := procWintunEndSession.address()
	if err != nil {
		return
	}
	if handle := session.handle.Swap(0); handle != 0 {
		syscall.Syscall(addr, 1, handle, 0, 0)
		runtime.KeepAlive(session)
	}
}

// ReadWaitEvent returns the event signalled when packets can be received, or 0 for an ended, zero or nil Session.
func (session *Session) ReadWaitEvent() (handle windows.Handle) {
	live := session.live()
	if live == 0 {
		return 0
	}
	addr, err := procWintunGetReadWaitEvent.address()
	if err != nil {
		return 0
	}
	r0, _, _ := syscall.Syscall(addr, 1, live, 0, 0)
	runtime.KeepAlive(session)
	handle = windows.Handle(r0)
	return
}

// ReceivePacket returns the next received packet; for an ended, zero or nil Session it returns windows.ERROR_HANDLE_EOF.
func (session *Session) ReceivePacket() (packet []byte, err error) {
	handle := session.live()
	if handle == 0 {
		return nil, windows.ERROR_HANDLE_EOF
	}
	addr, err := procWintunReceivePacket.address()
	if err != nil {
		return nil, err
	}
	var packetSize uint32
	r0, _, e1 := syscall.Syscall(addr, 2, handle, uintptr(unsafe.Pointer(&packetSize)), 0)
	runtime.KeepAlive(session)
	if r0 == 0 {
		err = errnoErr(e1)
		return
	}
	packet = unsafe.Slice(ringPointer(r0), packetSize)
	return
}

// ReleaseReceivePacket releases a packet ReceivePacket returned; it does nothing for a nil packet or an ended, zero or
// nil Session.
func (session *Session) ReleaseReceivePacket(packet []byte) {
	handle := session.live()
	if packet == nil || handle == 0 {
		return
	}
	if addr, err := procWintunReleaseReceivePacket.address(); err == nil {
		// gc keeps the DLL's address in the data word of a 0-byte packet too, which SliceData returns.
		syscall.Syscall(addr, 2, handle, uintptr(unsafe.Pointer(unsafe.SliceData(packet))), 0)
		runtime.KeepAlive(session)
	}
}

// AllocateSendPacket returns packetSize bytes of the send ring; it returns windows.ERROR_INVALID_PARAMETER for a
// packetSize outside 0 to PacketSizeMax, and windows.ERROR_HANDLE_EOF for an ended, zero or nil Session.
func (session *Session) AllocateSendPacket(packetSize int) (packet []byte, err error) {
	if packetSize < 0 || packetSize > PacketSizeMax {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	handle := session.live()
	if handle == 0 {
		return nil, windows.ERROR_HANDLE_EOF
	}
	addr, err := procWintunAllocateSendPacket.address()
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.Syscall(addr, 2, handle, uintptr(packetSize), 0)
	runtime.KeepAlive(session)
	if r0 == 0 {
		err = errnoErr(e1)
		return
	}
	packet = unsafe.Slice(ringPointer(r0), packetSize)
	return
}

// SendPacket sends a packet AllocateSendPacket returned; it does nothing for a nil packet or an ended, zero or nil
// Session.
func (session *Session) SendPacket(packet []byte) {
	handle := session.live()
	if packet == nil || handle == 0 {
		return
	}
	if addr, err := procWintunSendPacket.address(); err == nil {
		syscall.Syscall(addr, 2, handle, uintptr(unsafe.Pointer(unsafe.SliceData(packet))), 0)
		runtime.KeepAlive(session)
	}
}
