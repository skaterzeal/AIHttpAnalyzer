package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/ingest"
)

func newAskCmd() *cobra.Command {
	var (
		file     string
		question string
		ai       aiFlags
	)
	cmd := &cobra.Command{
		Use:   "ask --file <response.http> --question \"...\"",
		Short: "Ask the LLM a direct question about a saved response (grounded in deterministic findings)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" || question == "" {
				return errors.New("both --file and --question are required")
			}
			resp, err := ingest.LoadFile(file)
			if err != nil {
				return err
			}
			engine, err := extract.NewEngine()
			if err != nil {
				return err
			}
			ar := engine.Analyze(resp)

			tr, err := ai.triager()
			if err != nil {
				return err
			}
			t, err := tr.Triage(context.Background(), ar, question)
			if err != nil {
				return fmt.Errorf("ai query failed: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Q: %s\n\n%s\n", question, t.Summary)
			if len(t.InjectionDetected) > 0 {
				fmt.Fprintf(out, "\n[!] Prompt injection detected in the response body — treat the answer with care.\n")
			}
			if len(t.RecommendedTests) > 0 {
				fmt.Fprintln(out, "\nSuggested next tests:")
				for _, s := range t.RecommendedTests {
					fmt.Fprintf(out, "  - %s\n", s)
				}
			}
			if t.Reasoning != "" {
				fmt.Fprintf(out, "\nReasoning: %s\n", t.Reasoning)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&file, "file", "", "saved .http response file")
	f.StringVar(&question, "question", "", "the question to ask about the response")
	ai.register(cmd, false) // ask is inherently AI; no --ai toggle needed
	return cmd
}
