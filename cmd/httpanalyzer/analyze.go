package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/ai"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/ingest"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/output"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// analyzeOptions holds the resolved flags for the analyze command.
type analyzeOptions struct {
	file        string
	burp        string
	dir         string
	stdin       bool
	output      string
	outputFile  string
	minSeverity string
	concurrency int
	timeout     int
	ai          bool
	llmProvider string
	model       string
	apiKey      string
	patternsDir string
	cveDB       string
}

func newAnalyzeCmd() *cobra.Command {
	opts := &analyzeOptions{}
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze HTTP responses from a file, directory, or Burp export",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.file, "file", "", "single .http response file")
	f.StringVar(&opts.burp, "burp", "", "Burp Suite XML export (use - for stdin)")
	f.StringVar(&opts.dir, "dir", "", "directory of .http files")
	f.BoolVar(&opts.stdin, "stdin", false, "read targets (JSONL assets or host/URL lines) from stdin and fetch them")
	f.StringVarP(&opts.output, "output", "o", "jsonl", "output format: jsonl|sarif|markdown|html")
	f.StringVar(&opts.outputFile, "output-file", "", "write output to file instead of stdout")
	f.StringVar(&opts.minSeverity, "min-severity", "info", "minimum severity: info|low|medium|high|critical")
	f.IntVar(&opts.concurrency, "concurrency", 20, "concurrent fetches in --stdin mode")
	f.IntVar(&opts.timeout, "timeout", 10, "per-request timeout in seconds (--stdin mode)")
	f.BoolVar(&opts.ai, "ai", false, "enable advisory AI triage (does not change severities)")
	f.StringVar(&opts.llmProvider, "llm-provider", "ollama", "LLM provider: ollama|openai|anthropic")
	f.StringVar(&opts.model, "model", "", "LLM model (provider default if empty)")
	f.StringVar(&opts.apiKey, "api-key", "", "LLM API key (or set via env in your shell)")
	f.StringVar(&opts.patternsDir, "patterns", "", "external pattern pack directory (overrides embedded packs)")
	f.StringVar(&opts.cveDB, "cve-db", "", "external CVE database JSON file (overrides embedded DB)")
	return cmd
}

func runAnalyze(opts *analyzeOptions) error {
	if opts.file == "" && opts.burp == "" && opts.dir == "" && !opts.stdin {
		return errors.New("specify a source: --file, --burp, --dir, or --stdin")
	}
	minSev := asset.ParseSeverity(opts.minSeverity)

	responses, err := loadResponses(opts)
	if err != nil {
		return err
	}
	if len(responses) == 0 {
		fmt.Fprintln(os.Stderr, "no responses found in input")
		return nil
	}

	engine, err := extract.NewEngineWithConfig(extract.Config{
		PatternsDir: opts.patternsDir,
		CVEDBPath:   opts.cveDB,
	})
	if err != nil {
		return err
	}
	results := make([]asset.AnalyzedResponse, 0, len(responses))
	for _, r := range responses {
		results = append(results, engine.Analyze(r))
	}

	if opts.ai {
		if err := runAITriage(opts, results); err != nil {
			return err
		}
	}

	return writeOutput(opts, results, minSev)
}

// runAITriage adds advisory AI triage to each result. Failures on individual
// responses are logged and skipped so the deterministic report always succeeds.
func runAITriage(opts *analyzeOptions, results []asset.AnalyzedResponse) error {
	provider, err := ai.NewProvider(ai.Config{
		Provider: opts.llmProvider,
		Model:    opts.model,
		APIKey:   opts.apiKey,
	})
	if err != nil {
		return err
	}
	triager := ai.NewTriager(provider)
	ctx := context.Background()
	for i := range results {
		tr, err := triager.Triage(ctx, results[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ai triage failed for %s: %v\n", results[i].Response.AssetID(), err)
			continue
		}
		results[i].AITriage = tr
	}
	return nil
}

// loadResponses dispatches to the configured ingestion source.
func loadResponses(opts *analyzeOptions) ([]*asset.HTTPResponse, error) {
	switch {
	case opts.stdin:
		assets, err := ingest.ReadAssets(os.Stdin)
		if err != nil {
			return nil, err
		}
		fetcher := ingest.NewFetcher(time.Duration(opts.timeout)*time.Second, nil)
		return ingest.FetchAssets(context.Background(), fetcher, assets, opts.concurrency), nil
	case opts.burp != "":
		return ingest.ParseBurpFile(opts.burp)
	case opts.dir != "":
		return ingest.LoadDir(opts.dir)
	default:
		r, err := ingest.LoadFile(opts.file)
		if err != nil {
			return nil, err
		}
		return []*asset.HTTPResponse{r}, nil
	}
}

// writeOutput renders results in the requested format to stdout or a file.
func writeOutput(opts *analyzeOptions, results []asset.AnalyzedResponse, minSev asset.Severity) error {
	var w io.Writer = os.Stdout
	if opts.outputFile != "" {
		f, err := os.Create(opts.outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch opts.output {
	case "jsonl":
		return output.WriteJSONL(w, results, minSev)
	case "sarif":
		return output.WriteSARIF(w, results, minSev, version)
	case "markdown":
		return output.WriteMarkdown(w, results, minSev)
	case "html":
		return output.WriteHTML(w, results, minSev)
	default:
		return fmt.Errorf("unknown output format %q (use jsonl|sarif|markdown|html)", opts.output)
	}
}
