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
- The arm DLL is kept with the release but embedded in no build, as Go has no `windows/arm` port. The zip's `wintun/include/wintun.h` and `wintun/README.md` are left out, as `golang.zx2c4.com/wintun` binds the DLL's exports by name.
- `go test` checks that `embedded/` holds just these files, that each DLL is a PE DLL for its directory's architecture whose Authenticode signer is WireGuard LLC, and that this table holds their hashes and this section the version. CI's `dlls` job runs `go generate` again and fails on any difference, so the committed files are those of the release.

### Updating

1. Take the new version and the SHA-256 of its zip from <https://www.wintun.net>.
2. Put both on the `//go:generate` line in [generate.go](generate.go) and run `go generate`. It downloads the zip, checks its SHA-256, replaces `embedded/` with the zip's license and DLLs, writes [version.go](version.go), and prints the SHA-256 of each file it wrote.
3. Update this section with the version and the hashes; `go test` fails until they match.
4. Read the new `embedded/LICENSE.txt` for changed terms; CI then runs the end-to-end tests with each new DLL.

## End-to-end tests

The end-to-end tests in [`./e2e`](e2e) load the real `wintun.dll` on Windows. They are a module of their own, which replaces `github.com/wzshiming/wintun` with `../`, so only they require `golang.zx2c4.com/wintun`; run them from the `e2e` directory. Every test skips unless `WINTUN_E2E=1`.

```sh
WINTUN_E2E=1 go test -C e2e -v .
```

For an IDE that should see both modules at once, a local `go work init . ./e2e` is ignored by git and not committed.

- `TestE2ELoad`: `Load` loads the DLL from under `CacheDir()`, every function of `wintun.h` resolves in it, and `golang.zx2c4.com/wintun` finds it by its base name and reads its version, `Version`.
- `TestE2ESignature`: `WinVerifyTrust` trusts the Authenticode signature of the extracted DLL.
- `TestE2EAdapter` needs an elevated process: it creates an adapter with the requested name and GUID, checks the running driver is the DLL's, assigns it 198.18.0.5/30, has the session read a UDP datagram the host sends to 198.18.0.6 and write back one that the sending socket receives, and removes the adapter, except for amd64 on arm64 Windows, which cannot.

CI fails unless all three pass on `windows-latest` with amd64 (`-race`) and 386 under WOW64, and on `windows-11-arm` with arm64 and with amd64 and 386 under emulation, so each DLL runs on every Windows it supports.

## License

The Go code is under the MIT license, see [LICENSE](LICENSE). The DLLs belong to WireGuard LLC and are under the prebuilt binaries license in [embedded/LICENSE.txt](embedded/LICENSE.txt), which allows distributing them unmodified alongside software that uses them only through the API of `wintun.h`.
