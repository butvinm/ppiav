// Package ppiav exposes the compiled WASM blob for embedding into Go
// services (currently VAgent). `make wasm` (repo-root Makefile) must run
// before any binary that imports this package, because //go:embed requires
// the asset to exist at `go build` time. The wasm output is .gitignored
// (12+ MiB binary), so a fresh checkout sees `pattern ppiav.wasm: no
// matching files found` until `make wasm` produces it.
package ppiav

import _ "embed"

//go:embed ppiav.wasm
var WASM []byte
