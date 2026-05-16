//go:build js && wasm

package main

import (
	"github.com/butvinm/ppiav/web/ppiav/bridge/lattigo"
	"github.com/butvinm/ppiav/web/ppiav/bridge/ppiav"
)

func main() {
	lattigo.RegisterJS()
	ppiav.RegisterJS()
	select {}
}
