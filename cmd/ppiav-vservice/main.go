// Command ppiav-vservice runs the VService HTTP server. It exposes the
// `/params`, `/sessions`, and `/sessions/:sid/eval-keys` routes consumed
// by VAgent — see docs/DESIGN.md §`Protocol` and the Phase-3 plan.
//
// Flags mirror `cmd/ppiav-cli`'s --orion semantics: when `--orion` is
// set, the service runs the compiled Orion circuit; otherwise it runs the
// Phase-1 synthetic `x²` path.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vservice"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	orionDir := flag.String("orion", "", "directory holding a compiled Orion model.orion (Phase 2)")
	flag.Parse()

	params, err := protocol.Defaults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vservice: build params: %v\n", err)
		os.Exit(1)
	}

	var svc *vservice.Service
	if *orionDir != "" {
		svc, err = vservice.NewWithOrion(params, *orionDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ppiav-vservice: load Orion model: %v\n", err)
			os.Exit(1)
		}
	} else {
		svc = vservice.New(params)
	}

	srv := vservice.NewServer(svc, *addr)
	log.Printf("ppiav-vservice listening on %s (orion=%q)", *addr, *orionDir)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vservice: %v\n", err)
		os.Exit(1)
	}
}
