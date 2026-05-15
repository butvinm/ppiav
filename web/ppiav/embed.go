// Package ppiav exposes the compiled WASM blob for embedding into Go
// services (currently VAgent). `make wasm` (web/ppiav/Makefile) must run
// before any binary that imports this package, because //go:embed requires
// the asset to exist at `go build` time.
package ppiav

import _ "embed"

//go:embed ppiav.wasm
var WASM []byte
