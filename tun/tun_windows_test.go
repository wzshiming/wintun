package tun

import (
	"testing"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Fail the build unless the exports keep wireguard-go's tun_windows.go names and signatures.
var (
	_ wgtun.Device                                           = (*NativeTun)(nil)
	_ func(string, int) (wgtun.Device, error)                = CreateTUN
	_ func(string, *windows.GUID, int) (wgtun.Device, error) = CreateTUNWithRequestedGUID
	_ *string                                                = &WintunTunnelType
	_ **windows.GUID                                         = &WintunStaticRequestedGUID
	_ func(*NativeTun) uint64                                = (*NativeTun).LUID
	_ func(*NativeTun) (uint32, error)                       = (*NativeTun).RunningVersion
	_ func(*NativeTun, int)                                  = (*NativeTun).ForceMTU
	_ func(*NativeTun) (string, error)                       = (*NativeTun).Name
	_ func(*NativeTun, [][]byte, []int, int) (int, error)    = (*NativeTun).Read
	_ func(*NativeTun, [][]byte, int) (int, error)           = (*NativeTun).Write
)

func TestWintunTunnelTypeDefaultsToWireGuard(t *testing.T) {
	if WintunTunnelType != "WireGuard" {
		t.Errorf("WintunTunnelType = %q, want wireguard-go's default %q", WintunTunnelType, "WireGuard")
	}
	if WintunStaticRequestedGUID != nil {
		t.Errorf("WintunStaticRequestedGUID = %v, want nil", WintunStaticRequestedGUID)
	}
}
