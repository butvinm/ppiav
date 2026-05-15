// Package bench provides a measurement harness for benchmarking
// crypto operations: wall time, heap, GC, optional artifact size.
// Aggregation lives in the Python bench/ project.
package bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Sample struct {
	Name       string        `json:"name"`
	Iter       int           `json:"iter"`
	Wall       time.Duration `json:"wall"`
	HeapAlloc  uint64        `json:"heap_alloc"`
	HeapInuse  uint64        `json:"heap_inuse"`
	Sys        uint64        `json:"sys"`
	AllocDelta uint64        `json:"alloc_delta"`
	NumGC      uint32        `json:"num_gc"`
	PauseNs    uint64        `json:"pause_ns"`
	VmHWM      uint64        `json:"vm_hwm"`
	Bytes      uint64        `json:"bytes"`
}

type Run struct {
	Name      string         `json:"name"`
	Phase     string         `json:"phase"`
	Started   time.Time      `json:"started"`
	GoVersion string         `json:"go_version"`
	GOOS      string         `json:"goos"`
	GOARCH    string         `json:"goarch"`
	NumCPU    int            `json:"num_cpu"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Samples   []Sample       `json:"samples"`
}

func NewRun(name, phase string) *Run {
	return &Run{
		Name:      name,
		Phase:     phase,
		Started:   time.Now().UTC(),
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		Metadata:  map[string]any{},
		Samples:   []Sample{},
	}
}

func (r *Run) Append(s ...Sample) {
	r.Samples = append(r.Samples, s...)
}

// WriteJSON serialises the run to path atomically: write a sibling
// tmp file then rename, so a partially-written file never lands in
// results/.
func (r *Run) WriteJSON(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("bench: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("bench: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("bench: encode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("bench: close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("bench: rename tmp -> %s: %w", path, err)
	}
	return nil
}

// Measure runs fn once, collecting wall time and memory deltas. The
// reading uses runtime.GC() + a steady-state ReadMemStats on both
// sides so accounting is stable across cycles.
func Measure(name string, fn func() error) (Sample, error) {
	return measure(name, 0, func() (uint64, error) {
		return 0, fn()
	})
}

// MeasureWithSize is like Measure but lets fn report an artifact
// size (e.g. serialised wire-message length) into Sample.Bytes.
func MeasureWithSize(name string, fn func() (size uint64, err error)) (Sample, error) {
	return measure(name, 0, fn)
}

func measure(name string, iter int, fn func() (uint64, error)) (Sample, error) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	start := time.Now()
	size, err := fn()
	wall := time.Since(start)

	runtime.ReadMemStats(&after)

	s := Sample{
		Name:      name,
		Iter:      iter,
		Wall:      wall,
		HeapAlloc: after.HeapAlloc,
		HeapInuse: after.HeapInuse,
		Sys:       after.Sys,
		NumGC:     after.NumGC - before.NumGC,
		Bytes:     size,
	}
	if after.TotalAlloc >= before.TotalAlloc {
		s.AllocDelta = after.TotalAlloc - before.TotalAlloc
	}
	if after.PauseTotalNs >= before.PauseTotalNs {
		s.PauseNs = after.PauseTotalNs - before.PauseTotalNs
	}
	s.VmHWM = readVmHWM()
	return s, err
}

// Repeat calls fn n times. The returned slice has length min(n, k)
// where k is the index at which fn first errored; the error is
// propagated. Iter is set to the 0-based call index.
func Repeat(n int, name string, fn func() error) ([]Sample, error) {
	return RepeatWithWarmup(n, 0, name, fn)
}

// RepeatWithWarmup runs warmup iterations whose samples are
// discarded, then n measured iterations. Errors during warmup or
// measurement propagate immediately.
func RepeatWithWarmup(n, warmup int, name string, fn func() error) ([]Sample, error) {
	for i := 0; i < warmup; i++ {
		if _, err := measure(name, i, func() (uint64, error) { return 0, fn() }); err != nil {
			return nil, fmt.Errorf("bench: warmup iter %d: %w", i, err)
		}
	}
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		s, err := measure(name, i, func() (uint64, error) { return 0, fn() })
		if err != nil {
			out = append(out, s)
			return out, fmt.Errorf("bench: iter %d: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// readVmHWM returns the process's high-water-mark resident set size
// in bytes by parsing /proc/self/status. Returns 0 on non-Linux or
// on any read error — VmHWM is a diagnostic, not load-bearing.
func readVmHWM() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		// /proc/self/status reports VmHWM in kB.
		return kb * 1024
	}
	return 0
}
