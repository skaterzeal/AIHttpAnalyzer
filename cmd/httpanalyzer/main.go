// Command httpanalyzer is an AI-augmented HTTP response triage tool. It ingests
// HTTP traffic from many sources, runs deterministic detectors as ground truth,
// correlates versions to CVEs, and emits a deduplicated, prioritized attack
// surface that pipes cleanly into the rest of a recon workflow.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set via -ldflags "-X main.version=..." at release time.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "httpanalyzer",
		Short:         "AI-augmented HTTP response triage and attack-surface mapping",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(newAnalyzeCmd())
	root.AddCommand(newRequestCmd())
	root.AddCommand(newMapCmd())
	root.AddCommand(newProxyCmd())
	root.AddCommand(newAskCmd())
	return root
}
