package proxy

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestAnalyzableContentTypes(t *testing.T) {
	for _, ct := range []string{"application/json", "text/html; charset=utf-8", "application/xml"} {
		if !analyzable(ct) {
			t.Errorf("%q should be analyzable", ct)
		}
	}
	for _, ct := range []string{"image/png", "font/woff2", "application/octet-stream", ""} {
		if analyzable(ct) {
			t.Errorf("%q should NOT be analyzable", ct)
		}
	}
}

// safeBuffer is a concurrency-safe sink for findings written by the proxy.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestProxyAnalyzesPlainHTTPTraffic(t *testing.T) {
	// Target server returns a response with detectable signals.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"You have an error in your SQL syntax"}`))
	}))
	defer target.Close()

	dir := t.TempDir()
	ca, err := EnsureCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := extract.NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := &safeBuffer{}
	go func() {
		_ = Serve(ln, Options{Engine: engine, CA: ca, Out: out, MinSeverity: asset.SeverityInfo})
	}()
	defer ln.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	// Retry briefly until the proxy goroutine is accepting connections.
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(target.URL)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	resp.Body.Close()

	got := out.String()
	if !contains(got, "version_disclosure") || !contains(got, "MySQL") {
		t.Errorf("expected findings streamed from proxy, got: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
