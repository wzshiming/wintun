/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

func newLazyDLL(name string, data []byte, onLoad func(m *memmod.Module) error) *lazyDLL {
	return &lazyDLL{Name: name, data: data, onLoad: onLoad}
}

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr atomic.Uintptr
}

func (p *lazyProc) Find() error {
	if p.addr.Load() != 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr.Load() != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("Error loading %v DLL: %w", p.dll.Name, err)
	}
	addr, err := p.dll.module.Load().ProcAddressByName(p.Name)
	if err != nil {
		return fmt.Errorf("Error getting %v address: %w", p.Name, err)
	}

	p.addr.Store(addr)
	return nil
}

// Addr panics if Find fails; only functions that return no error use it, once a successful Find made them reachable.
func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr.Load()
}

// lazyDLL loads the DLL image data from memory with memmod on first use and never frees it.
type lazyDLL struct {
	Name   string
	Base   windows.Handle
	data   []byte
	mu     sync.Mutex
	module atomic.Pointer[memmod.Module]
	// onLoad runs before the module is published; on its error the module is freed and Load fails.
	onLoad func(m *memmod.Module) error
}

func (d *lazyDLL) Load() error {
	if d.module.Load() != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module.Load() != nil {
		return nil
	}

	module, err := memmod.LoadLibrary(d.data)
	if err != nil {
		return fmt.Errorf("Unable to load library: %w", err)
	}
	if d.onLoad != nil {
		if err := d.onLoad(module); err != nil {
			module.Free()
			return err
		}
	}
	d.Base = windows.Handle(module.BaseAddr())

	d.module.Store(module)
	return nil
}
