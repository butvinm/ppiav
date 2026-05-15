// Package rclient exposes the RClient SPA assets (HTML + compiled TS
// bundle) as an embed.FS for serving from RService. The TS build
// (`npm run build`) must run before any binary that imports this package.
package rclient

import "embed"

//go:embed index.html dist
var FS embed.FS
