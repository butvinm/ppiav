package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
)

// dumpHeapIfRequested writes a heap profile to $PPIAV_MEMPROFILE_DIR/<step>.pprof
// if the env var is set. Forces GC first so the profile reflects live objects.
// Errors are returned for callers that want to fail; they may also ignore them.
func dumpHeapIfRequested(step string) error {
	dir := os.Getenv("PPIAV_MEMPROFILE_DIR")
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("memprofile mkdir: %w", err)
	}
	runtime.GC()
	path := filepath.Join(dir, step+".pprof")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("memprofile create: %w", err)
	}
	defer f.Close()
	if err := pprof.Lookup("heap").WriteTo(f, 0); err != nil {
		return fmt.Errorf("memprofile write: %w", err)
	}
	fmt.Fprintf(os.Stderr, "ppiav-cli: heap profile written to %s\n", path)
	return nil
}
