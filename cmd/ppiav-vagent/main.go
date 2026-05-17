// Command ppiav-vagent runs the VAgent HTTP server. CKKS params come from
// VService via the Manifest endpoint (/params) — VAgent retries on
// startup until VService publishes one. See docs/DESIGN.md §`Protocol`.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vagent"
)

func main() {
	addr := flag.String("addr", ":8081", "HTTP listen address")
	vserviceURL := flag.String("vservice-url", "http://localhost:8080", "VService base URL (e.g., http://localhost:8080)")
	rserviceURL := flag.String("rservice-url", "http://localhost:8082", "RService base URL for server-to-server verdict callback (e.g. http://rservice:8082 inside Docker)")
	rservicePublicURL := flag.String("rservice-public-url", "", "Browser-visible RService URL returned in Stage-4b redirect JSON (defaults to --rservice-url; set to host-reachable URL when --rservice-url is internal-only, e.g. http://localhost:8082 with Docker)")
	flag.Parse()

	if *vserviceURL == "" {
		fmt.Fprintln(os.Stderr, "ppiav-vagent: --vservice-url is required")
		os.Exit(2)
	}

	params, err := fetchManifestParams(strings.TrimRight(*vserviceURL, "/") + "/params")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: fetch manifest from vservice: %v\n", err)
		os.Exit(1)
	}

	agent, err := vagent.New(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: build agent: %v\n", err)
		os.Exit(1)
	}

	srv := vagent.NewServer(agent, *vserviceURL, *rserviceURL, *rservicePublicURL)
	log.Printf("ppiav-vagent listening on %s (vservice=%s, rservice=%s, rservice-public=%s)",
		*addr, *vserviceURL, *rserviceURL, *rservicePublicURL)
	if err := srv.ListenAndServe(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "ppiav-vagent: %v\n", err)
		os.Exit(1)
	}
}

// fetchManifestParams polls VService's /params until it answers with a
// parseable Manifest. Required because docker-compose starts vagent
// concurrently with vservice and vagent needs the CKKS profile before it
// can build its Agent state.
func fetchManifestParams(url string) (protocol.Params, error) {
	const (
		attemptTimeout = 10 * time.Second
		retryEvery     = 2 * time.Second
		giveUpAfter    = 15 * time.Minute
	)
	client := &http.Client{Timeout: attemptTimeout}
	deadline := time.Now().Add(giveUpAfter)
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				params, parseErr := protocol.ParseManifestJSON(body)
				if parseErr == nil {
					return params, nil
				}
				lastErr = fmt.Errorf("parse manifest: %w", parseErr)
			} else {
				lastErr = fmt.Errorf("read manifest body: %w", readErr)
			}
		} else if err != nil {
			lastErr = err
		} else {
			resp.Body.Close()
			lastErr = fmt.Errorf("vservice /params returned HTTP %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			return protocol.Params{}, fmt.Errorf("waited %v: %w", giveUpAfter, lastErr)
		}
		log.Printf("ppiav-vagent: waiting for vservice manifest at %s (%v)", url, lastErr)
		time.Sleep(retryEvery)
	}
}
