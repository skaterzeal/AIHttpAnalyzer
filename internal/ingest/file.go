package ingest

import (
	"os"
	"path/filepath"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/httpparse"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// LoadFile reads a single saved HTTP response (.http) file.
func LoadFile(path string) (*asset.HTTPResponse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	resp := httpparse.ParseResponse(string(data), "file")
	// Use the file name as a stable asset id when no request URL is present.
	if resp.Request == nil {
		resp.Request = &asset.HTTPRequest{URL: filepath.ToSlash(path), Path: filepath.Base(path)}
	}
	return resp, nil
}

// LoadDir reads every *.http file in dir. Files that fail to read are skipped so
// one bad file does not abort the batch.
func LoadDir(dir string) ([]*asset.HTTPResponse, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.http"))
	if err != nil {
		return nil, err
	}
	var out []*asset.HTTPResponse
	for _, m := range matches {
		resp, err := LoadFile(m)
		if err != nil {
			continue
		}
		out = append(out, resp)
	}
	return out, nil
}
