# wintun

`github.com/wzshiming/wintun` is a [Wintun](https://www.wintun.net) binding for Go with the API of [`golang.zx2c4.com/wintun`](https://pkg.go.dev/golang.zx2c4.com/wintun) that embeds the signed `wintun.dll` for every Windows architecture Go supports and loads it straight from memory, as wireguard-windows' `load_wgnt_from_rsrc` build does: a program needs no `wintun.dll` beside its executable, and nothing is written to disk.

## Install

```sh
go get github.com/wzshiming/wintun
```

## Usage

```go
func echo() error {
	adapter, err := wintun.CreateAdapter("wg0", "Wintun", nil)
	if err != nil {
		return err
	}
	defer adapter.Close()
	session, err := adapter.StartSession(wintun.RingCapacityMin)
	if err != nil {
		return err
	}
	defer session.End()
	for {
		packet, err := session.ReceivePacket()
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			windows.WaitForSingleObject(session.ReadWaitEvent(), windows.INFINITE)
			continue
		} else if err != nil {
			return err
		}
		reply, err := session.AllocateSendPacket(len(packet))
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			session.ReleaseReceivePacket(packet) // the send ring is full: drop the packet
			continue
		} else if err != nil {
			session.ReleaseReceivePacket(packet)
			return err
		}
		copy(reply, packet)
		session.SendPacket(reply)
		session.ReleaseReceivePacket(packet)
	}
}
```

The first call of any Wintun function loads the embedded DLL once, with [memmod](https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/driver/memmod), and keeps it for the life of the process; memmod resolves its imports from System32 only. Creating an adapter or removing the driver needs an elevated process.

The deferred `End` and `Close` are safe even if they already ran: both may be called more than once, also concurrently, and hand their handle to the DLL once. After `End`, `ReceivePacket` and `AllocateSendPacket` return `windows.ERROR_HANDLE_EOF`, the code the driver itself uses for an ended session, so a receive loop needs one check. As the driver requires, stop readers before `End`: set the `ReadWaitEvent` event and wait for them.

The in-memory module is not in the Windows loader's list, so another binding in the same process that loads `wintun.dll` by name, such as `golang.zx2c4.com/wintun`, cannot find it: it still looks for a `wintun.dll` file.

## API

The package exports nothing outside Windows. On Windows it exports the API of `golang.zx2c4.com/wintun` v0.0.0-20230126152724-0fa3db229ce2, with the same names and signatures, except that `StartSession` returns a `*Session` and `Session`'s methods have pointer receivers:

- `type Adapter`, `const AdapterNameMax`, `func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (*Adapter, error)`, `func OpenAdapter(name string) (*Adapter, error)`, and the methods `Close() error`, `LUID() uint64` and `StartSession(capacity uint32) (*Session, error)`.
- `type Session` with `End()`, `ReadWaitEvent() windows.Handle`, `ReceivePacket() ([]byte, error)`, `ReleaseReceivePacket([]byte)`, `AllocateSendPacket(int) ([]byte, error)` and `SendPacket([]byte)`; `type Packet`, `const PacketSizeMax`, `RingCapacityMin` and `RingCapacityMax`.
- `func Uninstall() error`, `func RunningVersion() (uint32, error)`, and `type TimestampedWriter`, which the DLL's log messages go to when it is the writer of the standard logger.
- `func Version() string` returns the Wintun version of the embedded DLL, 0.14.1, without loading it.

Unlike `golang.zx2c4.com/wintun`, which panics when the DLL cannot load or lacks an export, nothing here panics: every function with an error result returns that failure, a zero or nil receiver gets the closed results below without loading the DLL, and a DLL call that fails without a last error returns `syscall.EINVAL`; when the DLL cannot load, `LUID` returns 0 and `ReadWaitEvent` 0. A dead handle never reaches the DLL:

- A closed, zero or nil `Adapter`'s `Close` returns nil, `LUID` 0 and `StartSession` `windows.ERROR_INVALID_HANDLE`.
- An ended, zero or nil `Session`'s `ReceivePacket` and `AllocateSendPacket` return `windows.ERROR_HANDLE_EOF`, `ReadWaitEvent` 0, and `ReleaseReceivePacket` and `SendPacket` do nothing, as they do for a nil packet.
- `AllocateSendPacket` returns `windows.ERROR_INVALID_PARAMETER` for a size outside 0 to `PacketSizeMax` without calling the DLL, and a packet of exactly that size otherwise.

## Embedded DLLs

[`embedded/`](embedded) mirrors the `wintun/` directory of the release zip, keeping only its license and DLLs: the unmodified builds of Wintun 0.14.1, signed by WireGuard LLC, from <https://www.wintun.net/builds/wintun-0.14.1.zip>, checked against the SHA-256 that wintun.net publishes, which [generate.go](generate.go) records.

| GOARCH | File | From the zip | SHA-256 |
| --- | --- | --- | --- |
| `386` | [embedded/bin/x86/wintun.dll](embedded/bin/x86/wintun.dll) | `wintun/bin/x86/wintun.dll` | `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931` |
| `amd64` | [embedded/bin/amd64/wintun.dll](embedded/bin/amd64/wintun.dll) | `wintun/bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| `arm64` | [embedded/bin/arm64/wintun.dll](embedded/bin/arm64/wintun.dll) | `wintun/bin/arm64/wintun.dll` | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |
| | [embedded/bin/arm/wintun.dll](embedded/bin/arm/wintun.dll) | `wintun/bin/arm/wintun.dll` | `daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9` |
| | [embedded/LICENSE.txt](embedded/LICENSE.txt) | `wintun/LICENSE.txt` | `183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2` |

- Each DLL carries the Wintun 0.14 driver for every Windows it can run on: the 386 DLL for x86, amd64 and arm64 Windows, the amd64 DLL for amd64 and arm64 Windows, the arm64 DLL for arm64 Windows. Under WOW64 or x64 emulation it removes adapters through the native DLL it also carries, run with `%WINDIR%\Sysnative\rundll32.exe`.
- Only WOW64 processes have `Sysnative`, so an amd64 build on arm64 Windows creates and uses adapters but cannot remove them; build for arm64, or 386, there.
- Only the 386, amd64 and arm64 DLLs are embedded, one per build of that GOARCH. Go has no `windows/arm` port, so the arm DLL is only mirrored from the zip and embedded in no build. The zip's `wintun/include/wintun.h` and `wintun/README.md` are left out, as this package's own binding loads the DLL from memory and binds its exports by name.
- `go test` checks that `embedded/` holds just these files, that each DLL is a PE DLL for its directory's architecture whose Authenticode signer is WireGuard LLC, and that this table holds their hashes and this section the version. CI's `dlls` job runs `go generate` again and fails on any difference, so the committed files are those of the release.

### Updating

1. Take the new version and the SHA-256 of its zip from <https://www.wintun.net>.
2. Put both on the `//go:generate` line in [generate.go](generate.go) and run `go generate`. It downloads the zip, checks its SHA-256, replaces `embedded/` with the zip's license and DLLs, writes [version.go](version.go), and prints the SHA-256 of each file it wrote.
3. Update this section with the version and the hashes; `go test` fails until they match.
4. Read the new `embedded/LICENSE.txt` for changed terms; CI then runs the end-to-end tests with each new DLL.

## End-to-end tests

`TestE2EAdapter`, in the root package, creates a real adapter on Windows through this package's API, with the embedded `wintun.dll` loaded from memory. Run it from an elevated prompt with `WINTUN_E2E=1` in the repository root, or it skips.

```sh
WINTUN_E2E=1 go test -v -run '^TestE2EAdapter$' .
```

It creates an adapter with the requested name and GUID, checks its LUID names an interface with that GUID and name and that the running driver is the DLL's version, `Version()`, starts a session and checks its read-wait event, assigns it 198.18.0.5/30, has the session read a UDP datagram the host sends to 198.18.0.6 and send back one that the sending socket receives, ends the session, and closes the adapter, then waits for it to go away, except for amd64 on arm64 Windows, which cannot remove it.

The DLL's Authenticode signature is checked by the root package's `TestEmbeddedDLLIsTrustedAndSignedByWireGuard`, which needs no privileges.

CI fails unless `TestE2EAdapter` passes on `windows-latest` with amd64 (`-race`) and 386 under WOW64, and on `windows-11-arm` with arm64 and with amd64 and 386 under emulation, so each DLL runs on every Windows it supports.

## License

The Go code is under the MIT license, see [LICENSE](LICENSE). The DLLs belong to WireGuard LLC and are under the prebuilt binaries license in [embedded/LICENSE.txt](embedded/LICENSE.txt), which allows distributing them unmodified alongside software that uses them only through the API of `wintun.h`.
