# wintun

`github.com/wzshiming/wintun` embeds the [Wintun](https://www.wintun.net) DLL and, on Windows, loads a verified copy of it from the cache directory. It was imported from `github.com/wzshiming/tun/wintun`.

## Install

```sh
go get github.com/wzshiming/wintun
```

## API

- `const Embedded bool` — Windows only: whether this build carries a `wintun.dll` (amd64 and arm64).
- `var CacheDir func() (string, error)` — where the embedded `wintun.dll` is extracted on Windows; programs may replace it.
- `func Load() error` — Windows only: extracts the embedded `wintun.dll` under `CacheDir()`, verifies it and loads it once per process; wraps `errors.ErrUnsupported` when none is embedded.

## License

MIT, see [LICENSE](LICENSE). The embedded Wintun DLLs are covered by [bin/LICENSE.txt](bin/LICENSE.txt).
