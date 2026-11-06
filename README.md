# wintun

`github.com/wzshiming/wintun` embeds the signed [Wintun](https://www.wintun.net) DLL for every Windows architecture Go supports and loads it, so a program needs no `wintun.dll` beside its executable. [`golang.zx2c4.com/wintun`](https://pkg.go.dev/golang.zx2c4.com/wintun) and [`golang.zx2c4.com/wireguard/tun`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun) then use the DLL it loaded.

## Install

```sh
go get github.com/wzshiming/wintun
```

## Usage

```go
func open() (tun.Device, error) { // golang.zx2c4.com/wireguard/tun
	// Load before golang.zx2c4.com/wintun first looks for wintun.dll.
	if err := wintun.Load(); err != nil {
		return nil, err
	}
	return tun.CreateTUN("wg0", 1420)
}
```

`Load` needs no privileges; creating an adapter needs an elevated process.

## API

- `const Version = "0.14.1"` — the Wintun version of the embedded DLLs.
- `const Embedded bool` — Windows only: whether this build carries a `wintun.dll`; true on 386, amd64 and arm64.
- `var CacheDir func() (string, error)` — the directory the embedded `wintun.dll` is extracted into on Windows, as `<GOARCH>-<hash>/wintun.dll` (default `os.UserCacheDir()/wintun`); programs may replace it.
- `func Load() error` — Windows only: extracts the embedded `wintun.dll` under `CacheDir()`, verifies it and loads it once per process; wraps `errors.ErrUnsupported` when none is embedded.

`Load` writes the DLL to `CacheDir()/<GOARCH>-<first 16 hex digits of its SHA-256>/wintun.dll` through a temporary file, unless that file already holds it. It refuses a junction, symbolic link or other reparse point at `CacheDir()`, below it or at the DLL, which another process of the same user could aim elsewhere, while the parent of `CacheDir()` may be redirected. It then opens the file without write or delete sharing, compares it with the embedded bytes and, still holding it open, loads the final path of that handle, resolving the DLL's own imports from System32 only. `golang.zx2c4.com/wintun` loads `wintun.dll` by its base name, which Windows resolves to that module.

## Embedded DLLs

The DLLs are the unmodified builds of Wintun 0.14.1, signed by WireGuard LLC, from <https://www.wintun.net/builds/wintun-0.14.1.zip>, whose SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` is the one wintun.net publishes.

| GOARCH | File | From the zip | SHA-256 |
| --- | --- | --- | --- |
| `386` | [bin/386/wintun.dll](bin/386/wintun.dll) | `wintun/bin/x86/wintun.dll` | `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931` |
| `amd64` | [bin/amd64/wintun.dll](bin/amd64/wintun.dll) | `wintun/bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| `arm64` | [bin/arm64/wintun.dll](bin/arm64/wintun.dll) | `wintun/bin/arm64/wintun.dll` | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |
| | [bin/LICENSE.txt](bin/LICENSE.txt) | `wintun/LICENSE.txt` | `183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2` |

- Each DLL carries the Wintun 0.14 driver for every Windows it can run on: the 386 DLL for x86, amd64 and arm64 Windows, the amd64 DLL for amd64 and arm64 Windows, the arm64 DLL for arm64 Windows. Under WOW64 or x64 emulation it hands adapter creation to the native DLL it also carries, run through `rundll32`.
- The zip's `wintun/bin/arm/wintun.dll` is left out, as Go removed `windows/arm` in Go 1.26, and so are `wintun/include/wintun.h` and `wintun/README.md`, as `golang.zx2c4.com/wintun` binds the DLL's exports by name.
- `go test` checks that each DLL is a PE DLL for its GOARCH whose Authenticode signer is WireGuard LLC, and that this table holds the DLLs' hashes. CI's `dlls` job runs `go generate` again and fails on any difference, so the committed files are those of the release.

### Updating

1. Take the new version and the SHA-256 of its zip from <https://www.wintun.net>.
2. Put both on the `//go:generate` line in [generate.go](generate.go) and run `go generate`. It downloads the zip, checks its SHA-256, writes the DLLs, `bin/LICENSE.txt` and [version.go](version.go), and prints the SHA-256 of each file it wrote.
3. Update this section with the version and the hashes; `go test` fails until the table matches the DLLs.
4. Read the new `bin/LICENSE.txt` for changed terms.

## License

The Go code is under the MIT license, see [LICENSE](LICENSE). The DLLs belong to WireGuard LLC and are under the prebuilt binaries license in [bin/LICENSE.txt](bin/LICENSE.txt), which allows distributing them unmodified alongside software that uses them only through the API of `wintun.h`.
