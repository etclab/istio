package main

import (
	"fmt"
	"os"
	"time"

	"github.com/etclab/rbe"
	"istio.io/istio/pkg/config/constants"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
)

func main() {
	maxUsers := constants.MaxUsers
	fmt.Printf("Generating RBE public params with MaxUsers=%d\n", maxUsers)

	start := time.Now()
	pp := rbe.NewPublicParams(maxUsers)
	fmt.Printf("Generated public params in %s (BlockSize=%d, NumBlocks=%d)\n",
		time.Since(start), pp.BlockSize, pp.NumBlocks)

	// Ensure the output directory exists.
	if err := os.MkdirAll("/tmp/rbe-pp", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	outDir := "/tmp/rbe-pp"
	if err := keycurator.SaveRbeParams(pp, outDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save RBE params: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully wrote RBE param files to %s/\n", outDir)
}
