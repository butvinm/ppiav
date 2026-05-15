// Command ppiav-rservice runs the RService HTTP server. It exposes the
// `/protected` cookie-gated stub and `/api/callback/:sid` verdict
// receiver — see docs/DESIGN.md §`Protocol` and the Phase-3 plan.
//
// Task-3 scope: bring up the binary against the existing Task-2 handlers.
// The Stage-1 server-to-server redirect to VAgent is implemented in
// Task 18; the `--vagent-url` flag is wired up front to keep the flag
// surface stable.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/butvinm/ppiav/internal/rservice"
)

func main() {
	addr := flag.String("addr", ":8082", "HTTP listen address")
	vagentURL := flag.String("vagent-url", "http://localhost:8081", "VAgent base URL (used by Stage-1 redirect, Task 18)")
	flag.Parse()

	svc := rservice.New()
	srv := rservice.NewServer(svc, *vagentURL, *addr)
	log.Printf("ppiav-rservice listening on %s (vagent=%s)", *addr, *vagentURL)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-rservice: %v\n", err)
		os.Exit(1)
	}
}
