package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/correlate"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/ingest"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/output"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func newMapCmd() *cobra.Command {
	var (
		burp        string
		dir         string
		stdin       bool
		outFormat   string
		outputFile  string
		concurrency int
		timeout     int
		patternsDir string
		cveDB       string
	)
	cmd := &cobra.Command{
		Use:   "map",
		Short: "Aggregate many responses into a cross-asset attack surface map",
		RunE: func(cmd *cobra.Command, args []string) error {
			if burp == "" && dir == "" && !stdin {
				return errors.New("specify a source: --burp, --dir, or --stdin")
			}

			var (
				responses []*asset.HTTPResponse
				err       error
			)
			switch {
			case stdin:
				assets, e := ingest.ReadAssets(os.Stdin)
				if e != nil {
					return e
				}
				fetcher := ingest.NewFetcher(time.Duration(timeout)*time.Second, nil)
				responses = ingest.FetchAssets(context.Background(), fetcher, assets, concurrency)
			case burp != "":
				responses, err = ingest.ParseBurpFile(burp)
			case dir != "":
				responses, err = ingest.LoadDir(dir)
			}
			if err != nil {
				return err
			}

			engine, err := extract.NewEngineWithConfig(extract.Config{
				PatternsDir: patternsDir,
				CVEDBPath:   cveDB,
			})
			if err != nil {
				return err
			}
			results := make([]asset.AnalyzedResponse, 0, len(responses))
			for _, r := range responses {
				results = append(results, engine.Analyze(r))
			}
			m := correlate.BuildMap(results)

			var w io.Writer = os.Stdout
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			if outFormat == "json" {
				return output.WriteAttackSurfaceJSON(w, m)
			}
			return output.WriteAttackSurfaceMarkdown(w, m)
		},
	}
	f := cmd.Flags()
	f.StringVar(&burp, "burp", "", "Burp Suite XML export (use - for stdin)")
	f.StringVar(&dir, "dir", "", "directory of .http files")
	f.BoolVar(&stdin, "stdin", false, "read targets (JSONL/host lines) from stdin and fetch them")
	f.StringVarP(&outFormat, "output", "o", "markdown", "output format: markdown|json")
	f.StringVar(&outputFile, "output-file", "", "write output to file instead of stdout")
	f.IntVar(&concurrency, "concurrency", 20, "concurrent fetches in --stdin mode")
	f.IntVar(&timeout, "timeout", 10, "per-request timeout in seconds (--stdin mode)")
	f.StringVar(&patternsDir, "patterns", "", "external pattern pack directory (overrides embedded packs)")
	f.StringVar(&cveDB, "cve-db", "", "external CVE database JSON file (overrides embedded DB)")
	return cmd
}
