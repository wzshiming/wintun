/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	handle uintptr
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

func (wintun *Adapter) StartSession(capacity uint32) (session Session, err error) {
	addr, err := procWintunStartSession.address()
	if err != nil {
		return Session{}, err
	}
	r0, _, e1 := syscall.Syscall(addr, 2, uintptr(wintun.handle), uintptr(capacity), 0)
	if r0 == 0 {
		err = errnoErr(e1)
	} else {
		session = Session{r0}
	}
	return
}

func (session Session) End() {
	if addr, err := procWintunEndSession.address(); err == nil {
		syscall.Syscall(addr, 1, session.handle, 0, 0)
	}
}

func (session Session) ReadWaitEvent() (handle windows.Handle) {
	addr, err := procWintunGetReadWaitEvent.address()
	if err != nil {
		return 0
	}
	r0, _, _ := syscall.Syscall(addr, 1, session.handle, 0, 0)
	handle = windows.Handle(r0)
	return
}

func (session Session) ReceivePacket() (packet []byte, err error) {
	addr, err := procWintunReceivePacket.address()
	if err != nil {
		return nil, err
	}
	var packetSize uint32
	r0, _, e1 := syscall.Syscall(addr, 2, session.handle, uintptr(unsafe.Pointer(&packetSize)), 0)
	if r0 == 0 {
		err = errnoErr(e1)
		return
	}
	packet = unsafe.Slice(ringPointer(r0), packetSize)
	return
}

func (session Session) ReleaseReceivePacket(packet []byte) {
	if addr, err := procWintunReleaseReceivePacket.address(); err == nil {
		syscall.Syscall(addr, 2, session.handle, uintptr(unsafe.Pointer(&packet[0])), 0)
	}
}

func (session Session) AllocateSendPacket(packetSize int) (packet []byte, err error) {
	addr, err := procWintunAllocateSendPacket.address()
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.Syscall(addr, 2, session.handle, uintptr(packetSize), 0)
	if r0 == 0 {
		err = errnoErr(e1)
		return
	}
	packet = unsafe.Slice(ringPointer(r0), packetSize)
	return
}

func (session Session) SendPacket(packet []byte) {
	if addr, err := procWintunSendPacket.address(); err == nil {
		syscall.Syscall(addr, 2, session.handle, uintptr(unsafe.Pointer(&packet[0])), 0)
	}
}
