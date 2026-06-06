package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/proxy"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func newProxyCmd() *cobra.Command {
	var (
		addr        string
		caCert      string
		caKey       string
		outputFile  string
		minSeverity string
		patternsDir string
		cveDB       string
		verbose     bool
	)
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a live MITM proxy that analyzes responses in real time",
		Long: "Starts an HTTP/HTTPS intercepting proxy. Point your browser or Burp at it,\n" +
			"trust the generated CA, and findings stream out as JSONL.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if caCert == "" || caKey == "" {
				caCert, caKey = proxy.DefaultCAPaths()
			}
			ca, err := proxy.EnsureCA(caCert, caKey)
			if err != nil {
				return fmt.Errorf("CA setup: %w", err)
			}

			engine, err := extract.NewEngineWithConfig(extract.Config{
				PatternsDir: patternsDir,
				CVEDBPath:   cveDB,
			})
			if err != nil {
				return err
			}

			var out io.Writer = os.Stdout
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return err
				}
				defer f.Close()
				out = f
			}

			fmt.Fprintf(os.Stderr, "proxy listening on %s (CA: %s)\n", addr, caCert)
			return proxy.Run(proxy.Options{
				Addr:        addr,
				Engine:      engine,
				CA:          ca,
				Out:         out,
				MinSeverity: asset.ParseSeverity(minSeverity),
				Verbose:     verbose,
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&addr, "addr", "127.0.0.1:8080", "proxy listen address")
	f.StringVar(&caCert, "ca-cert", "", "CA certificate path (default: user config dir)")
	f.StringVar(&caKey, "ca-key", "", "CA private key path (default: user config dir)")
	f.StringVar(&outputFile, "output-file", "", "write findings JSONL to file instead of stdout")
	f.StringVar(&minSeverity, "min-severity", "info", "minimum severity to emit")
	f.StringVar(&patternsDir, "patterns", "", "external pattern pack directory")
	f.StringVar(&cveDB, "cve-db", "", "external CVE database JSON file")
	f.BoolVar(&verbose, "verbose", false, "verbose proxy logging")
	return cmd
}
