// Package tun ports wireguard-go's Windows tun.NativeTun onto github.com/wzshiming/wintun, so CreateTUN returns a
// golang.zx2c4.com/wireguard/tun.Device backed by the wintun.dll loaded from memory. It exports nothing outside Windows.
package tun
