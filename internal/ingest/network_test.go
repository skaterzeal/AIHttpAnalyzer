package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestReadAssets(t *testing.T) {
	in := strings.NewReader(`{"url":"https://a.example.com/x","source":"dnsrecon"}
b.example.com
https://c.example.com/y

  # not stripped as comment, treated as host
`)
	assets, err := ReadAssets(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets, got %d: %+v", len(assets), assets)
	}
	if assets[0].URL != "https://a.example.com/x" || assets[0].Source != "dnsrecon" {
		t.Errorf("JSONL asset not parsed: %+v", assets[0])
	}
	if got := AssetURL(assets[1]); got != "https://b.example.com" {
		t.Errorf("bare host should default to https, got %q", got)
	}
}

func TestFetchAndFetchAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	f := NewFetcher(5*time.Second, map[string]string{"X-Test": "1"})
	resp, err := f.Fetch(context.Background(), "GET", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Headers["server"] != "nginx/1.18.0" {
		t.Errorf("server header = %q", resp.Headers["server"])
	}
	if resp.Request == nil || resp.Request.Headers["x-test"] != "1" {
		t.Errorf("request headers not recorded: %+v", resp.Request)
	}

	assets := []asset.Asset{{URL: srv.URL}}
	resps := FetchAssets(context.Background(), f, assets, 4)
	if len(resps) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resps))
	}
}
