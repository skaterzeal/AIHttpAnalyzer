package main

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/ingest"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/output"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func newRequestCmd() *cobra.Command {
	var (
		method      string
		headers     []string
		outFormat   string
		minSeverity string
		timeout     int
	)
	cmd := &cobra.Command{
		Use:   "request <url>",
		Short: "Fetch a single URL and analyze the response",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hdr := parseHeaders(headers)
			fetcher := ingest.NewFetcher(time.Duration(timeout)*time.Second, hdr)
			resp, err := fetcher.Fetch(context.Background(), strings.ToUpper(method), args[0])
			if err != nil {
				return err
			}
			engine, err := extract.NewEngine()
			if err != nil {
				return err
			}
			results := []asset.AnalyzedResponse{engine.Analyze(resp)}
			return output.WriteJSONL(cmd.OutOrStdout(), results, asset.ParseSeverity(minSeverity))
		},
	}
	f := cmd.Flags()
	f.StringVarP(&method, "method", "X", "GET", "HTTP method")
	f.StringArrayVarP(&headers, "header", "H", nil, "extra request header (repeatable), e.g. -H 'Authorization: Bearer x'")
	f.StringVarP(&outFormat, "output", "o", "jsonl", "output format: jsonl")
	f.StringVar(&minSeverity, "min-severity", "info", "minimum severity")
	f.IntVar(&timeout, "timeout", 10, "request timeout in seconds")
	return cmd
}

// parseHeaders turns "Key: Value" strings into a map.
func parseHeaders(in []string) map[string]string {
	out := make(map[string]string, len(in))
	for _, h := range in {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
