//go:build ignore

// Generator for cmd/ppiav-cli/testdata/synthetic.bin — a 12288-float64
// fixture used by Phase-1 manual verification. Content is irrelevant for
// `x²` correctness (any constant works); we pick 0.5 so the squared logit
// is a clean 0.25 in slot 0.
//
// Run: go run cmd/ppiav-cli/testdata/synthetic.gen.go
package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

const imageLen = 3 * 64 * 64

func main() {
	out := "cmd/ppiav-cli/testdata/synthetic.bin"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", out, err)
		os.Exit(1)
	}
	defer f.Close()

	buf := make([]byte, 8)
	for i := 0; i < imageLen; i++ {
		binary.LittleEndian.PutUint64(buf, math.Float64bits(0.5))
		if _, err := f.Write(buf); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("wrote %s (%d float64)\n", out, imageLen)
}
