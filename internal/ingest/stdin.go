package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// ReadAssets parses a stream of targets. Each non-empty line is either a JSON
// object (the shared Asset schema, e.g. emitted by DNSRecon) or a plain
// host/URL string. This is what makes the tool pipe-compatible:
//
//	dnsrecon -o jsonl example.com | httpanalyzer analyze --stdin
func ReadAssets(r io.Reader) ([]asset.Asset, error) {
	var assets []asset.Asset
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line[0] == '{' {
			var a asset.Asset
			if err := json.Unmarshal([]byte(line), &a); err == nil {
				assets = append(assets, a)
				continue
			}
			// Fall through: treat an unparseable JSON-looking line as text.
		}
		assets = append(assets, asset.Asset{URL: normalizeTarget(line)})
	}
	return assets, sc.Err()
}

// normalizeTarget turns a bare host into a URL, defaulting to https.
func normalizeTarget(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://" + s
}

// AssetURL returns the URL to fetch for an asset, deriving one from the host
// when no explicit URL is set.
func AssetURL(a asset.Asset) string {
	if a.URL != "" {
		return normalizeTarget(a.URL)
	}
	if a.Host != "" {
		return normalizeTarget(a.Host)
	}
	return ""
}

// FetchAssets fetches every asset concurrently (bounded by concurrency) and
// returns the responses. Targets that fail to fetch are skipped; a scan should
// not abort because one host is down. Order is not guaranteed.
func FetchAssets(ctx context.Context, f *Fetcher, assets []asset.Asset, concurrency int) []*asset.HTTPResponse {
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan asset.Asset)
	var (
		mu  sync.Mutex
		out []*asset.HTTPResponse
		wg  sync.WaitGroup
	)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				url := AssetURL(a)
				if url == "" {
					continue
				}
				resp, err := f.Fetch(ctx, "GET", url)
				if err != nil {
					continue
				}
				mu.Lock()
				out = append(out, resp)
				mu.Unlock()
			}
		}()
	}
	for _, a := range assets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		case jobs <- a:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}
