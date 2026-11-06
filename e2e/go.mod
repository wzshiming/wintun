module github.com/wzshiming/wintun/e2e

go 1.27.3

replace github.com/wzshiming/wintun => ../

require (
	github.com/wzshiming/wintun v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.48.0
)

require golang.zx2c4.com/wireguard/windows v1.1.1 // indirect
