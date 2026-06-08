package main

import (
	"github.com/spf13/cobra"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/ai"
)

// aiFlags holds the LLM flags shared by analyze, request, proxy, and ask.
type aiFlags struct {
	enabled     bool
	provider    string
	model       string
	apiKey      string
	concurrency int
}

// register attaches the shared AI flags to a command.
func (a *aiFlags) register(cmd *cobra.Command, withEnable bool) {
	f := cmd.Flags()
	if withEnable {
		f.BoolVar(&a.enabled, "ai", false, "enable advisory AI triage (does not change severities)")
	}
	f.StringVar(&a.provider, "llm-provider", "ollama", "LLM provider: ollama|openai|anthropic")
	f.StringVar(&a.model, "model", "", "LLM model (provider default if empty)")
	f.StringVar(&a.apiKey, "api-key", "", "LLM API key")
	f.IntVar(&a.concurrency, "ai-concurrency", 5, "max concurrent LLM requests")
}

// triager builds a Triager from the configured provider.
func (a *aiFlags) triager() (*ai.Triager, error) {
	p, err := ai.NewProvider(ai.Config{Provider: a.provider, Model: a.model, APIKey: a.apiKey})
	if err != nil {
		return nil, err
	}
	return ai.NewTriager(p), nil
}
