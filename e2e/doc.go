// Package e2e holds the end-to-end tests, which create Wintun adapters with the embedded wintun.dll loaded from memory
// and carry UDP through them: TestE2EAdapter through the root package's Adapter and Session, TestE2ETUN through the
// tun subpackage's wireguard-go tun.Device.
//
// Both skip unless WINTUN_E2E=1 and the process is elevated, as they install the Wintun driver when missing and create
// adapters, which Wintun removes once the test closes them or the process exits.
package e2e
