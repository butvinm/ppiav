// Command ppiav-vagent runs the VAgent HTTP server. It exposes the
// Stage-1 `POST /sessions`, the proxy `GET /sessions/:sid/params`, the
// per-stage keygen routes (`pk-share`, `rlk/round1`, `rlk/round2`,
// `gks-shares`), and the Stage-3/4 image/result/partial-decryption
// routes added in Tasks 6 and 7. See docs/DESIGN.md §`Protocol` and the
// Phase-3 plan.
//
// Flags mirror `cmd/ppiav-vservice`'s --orion semantics: when `--orion`
// is set, params are derived from the compiled Orion model so VAgent
// agrees with VService on the CKKS profile. The agent itself does not
// touch the Orion model — it only needs matching `protocol.Params`.
//
// `--rservice-url` is wired now for the verdict callback implemented in
// Task 7; Task 5's keygen routes do not use it but the flag surface is
// stable.
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
	rserviceURL := flag.String("rservice-url", "http://localhost:8082", "RService base URL (used by Stage-4b verdict callback, Task 7)")
	orionDir := flag.String("orion", "", "directory holding a compiled Orion model.orion (Phase 2)")
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
		// VAgent only consumes Params (CKKS, Authenticator, InputLevel,
		// ExtraRotationIndices) — we don't need the Orion model itself.
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

	// Stage-1 sid allocation happens dynamically per request: RService
	// → VAgent `POST /sessions` → VService `POST /sessions`. No initial
	// session is opened here.
	srv := vagent.NewServer(agent, *vserviceURL, *rserviceURL, *addr)
	log.Printf("ppiav-vagent listening on %s (vservice=%s, rservice=%s, orion=%q)",
		*addr, *vserviceURL, *rserviceURL, *orionDir)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: %v\n", err)
		os.Exit(1)
	}
}
