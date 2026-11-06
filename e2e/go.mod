module github.com/wzshiming/wintun/e2e

go 1.27.3

replace github.com/wzshiming/wintun => ../

require (
	github.com/wzshiming/wintun v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wireguard/windows v1.1.1
)

require (
	golang.org/x/net v0.53.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee // indirect
)
