// Package vclient exposes the VClient SPA assets (HTML + compiled TS
// bundle + Go/WASM shim) as an embed.FS for serving from VAgent. The TS
// build (`npm run build`) and the wasm_exec.js copy must run before any
// binary that imports this package.
package vclient

import "embed"

//go:embed index.html dist wasm_exec.js styles.css
var FS embed.FS
