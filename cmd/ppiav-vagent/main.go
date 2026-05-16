// Command ppiav-vagent runs the VAgent HTTP server. When `--orion` is set
// params are derived from the compiled Orion model so VAgent agrees with
// VService on the CKKS profile (agent does not touch the model itself).
// See docs/DESIGN.md §`Protocol`.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
	"github.com/butvinm/ppiav/internal/vservice"
)

func main() {
	addr := flag.String("addr", ":8081", "HTTP listen address")
	vserviceURL := flag.String("vservice-url", "http://localhost:8080", "VService base URL (e.g., http://localhost:8080)")
	rserviceURL := flag.String("rservice-url", "http://localhost:8082", "RService base URL for server-to-server verdict callback (e.g. http://rservice:8082 inside Docker)")
	rservicePublicURL := flag.String("rservice-public-url", "", "Browser-visible RService URL returned in Stage-4b redirect JSON (defaults to --rservice-url; set to host-reachable URL when --rservice-url is internal-only, e.g. http://localhost:8082 with Docker)")
	orionDir := flag.String("orion", "", "directory holding a compiled Orion model.orion")
	flag.Parse()

	if *vserviceURL == "" {
		fmt.Fprintln(os.Stderr, "ppiav-vagent: --vservice-url is required")
		os.Exit(2)
	}

	params, err := protocol.Defaults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: build params: %v\n", err)
		os.Exit(1)
	}
	if *orionDir != "" {
		// vservice.NewWithOrion is the single source of truth that aligns
		// params across services; we discard the *Service it returns.
		svc, err := vservice.NewWithOrion(params, *orionDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ppiav-vagent: load Orion params: %v\n", err)
			os.Exit(1)
		}
		params = svc.Params()
	}

	agent, err := vagent.New(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: build agent: %v\n", err)
		os.Exit(1)
	}

	srv := vagent.NewServer(agent, *vserviceURL, *rserviceURL, *rservicePublicURL)
	log.Printf("ppiav-vagent listening on %s (vservice=%s, rservice=%s, rservice-public=%s, orion=%q)",
		*addr, *vserviceURL, *rserviceURL, *rservicePublicURL, *orionDir)
	if err := srv.ListenAndServe(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: %v\n", err)
		os.Exit(1)
	}
}
