module golang.zx2c4.com/wireguard

go 1.25.0

require (
	github.com/emmansun/gmsm v0.0.0
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

replace github.com/emmansun/gmsm => ../gmsm

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/time v0.7.0 // indirect
)
