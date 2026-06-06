// Package ai implements the trustworthy triage layer. Its defining constraint:
// the LLM never assigns severity and never invents verified facts. Deterministic
// detections and CVE correlation remain ground truth; the AI only explains,
// prioritizes, and suggests follow-up tests. Response bodies (attacker-
// controllable) are treated strictly as untrusted data and are injection-hardened
// before ever reaching the model.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Provider is a minimal LLM completion backend. Keeping the surface this small
// lets us support local (ollama) and hosted (OpenAI, Anthropic) models with no
// third-party SDKs — and makes the triager trivially testable with a fake.
type Provider interface {
	Complete(ctx context.Context, prompt string) (string, error)
	Name() string
}

// Config selects and configures a provider.
type Config struct {
	Provider string // ollama | openai | anthropic
	Model    string
	APIKey   string
	BaseURL  string // optional override (e.g. ollama host, OpenAI-compatible gateway)
	Timeout  time.Duration
}

// NewProvider builds a Provider from config.
func NewProvider(c Config) (Provider, error) {
	if c.Timeout == 0 {
		c.Timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: c.Timeout}
	switch c.Provider {
	case "", "ollama":
		base := c.BaseURL
		if base == "" {
			base = "http://localhost:11434"
		}
		model := c.Model
		if model == "" {
			model = "llama3.2"
		}
		return &ollamaProvider{client: client, base: base, model: model}, nil
	case "openai":
		base := c.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		model := c.Model
		if model == "" {
			model = "gpt-4o-mini"
		}
		return &openaiProvider{client: client, base: base, model: model, apiKey: c.APIKey}, nil
	case "anthropic":
		model := c.Model
		if model == "" {
			model = "claude-3-5-haiku-latest"
		}
		return &anthropicProvider{client: client, model: model, apiKey: c.APIKey}, nil
	default:
		return nil, fmt.Errorf("unsupported provider %q (use ollama|openai|anthropic)", c.Provider)
	}
}

func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", url, resp.StatusCode, truncateErr(data))
	}
	return data, nil
}

func truncateErr(b []byte) string {
	const n = 300
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

// --- ollama ---

type ollamaProvider struct {
	client *http.Client
	base   string
	model  string
}

func (p *ollamaProvider) Name() string { return "ollama/" + p.model }

func (p *ollamaProvider) Complete(ctx context.Context, prompt string) (string, error) {
	data, err := postJSON(ctx, p.client, p.base+"/api/generate", nil, map[string]any{
		"model":  p.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]any{
			"temperature": 0.2,
		},
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.Response, nil
}

// --- openai (chat completions) ---

type openaiProvider struct {
	client *http.Client
	base   string
	model  string
	apiKey string
}

func (p *openaiProvider) Name() string { return "openai/" + p.model }

func (p *openaiProvider) Complete(ctx context.Context, prompt string) (string, error) {
	data, err := postJSON(ctx, p.client, p.base+"/chat/completions",
		map[string]string{"Authorization": "Bearer " + p.apiKey},
		map[string]any{
			"model":       p.model,
			"temperature": 0.2,
			"messages":    []map[string]string{{"role": "user", "content": prompt}},
		})
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

// --- anthropic (messages) ---

type anthropicProvider struct {
	client *http.Client
	model  string
	apiKey string
}

func (p *anthropicProvider) Name() string { return "anthropic/" + p.model }

func (p *anthropicProvider) Complete(ctx context.Context, prompt string) (string, error) {
	data, err := postJSON(ctx, p.client, "https://api.anthropic.com/v1/messages",
		map[string]string{
			"x-api-key":         p.apiKey,
			"anthropic-version": "2023-06-01",
		},
		map[string]any{
			"model":      p.model,
			"max_tokens": 2000,
			"messages":   []map[string]string{{"role": "user", "content": prompt}},
		})
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if len(out.Content) == 0 {
		return "", fmt.Errorf("anthropic: empty response")
	}
	return out.Content[0].Text, nil
}
