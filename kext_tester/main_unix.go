//go:build !windows

package main

import (
	"fmt"
	"os"
)

// Off Windows there is no kernel driver to load, so the agent only runs in
// simulation mode, against the userspace fake driver (see sim.go).
func main() {
	pipeName := os.Getenv("ZF_SIM_PIPE")
	if pipeName == "" {
		fmt.Fprintln(os.Stderr, "production mode is Windows-only; set ZF_SIM_PIPE to run against the simulated driver (see `just sim-run`)")
		os.Exit(2)
	}
	os.Exit(runSimulation(pipeName))
}
