// Package ingest turns the various input sources (Burp XML exports, .http
// files, directories, stdin asset streams, live requests) into a uniform stream
// of asset.HTTPResponse values for the extraction engine.
package ingest

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/httpparse"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

type burpItems struct {
	Items []burpItem `xml:"item"`
}

type burpItem struct {
	URL      string   `xml:"url"`
	Status   int      `xml:"status"`
	Request  burpData `xml:"request"`
	Response burpData `xml:"response"`
}

type burpData struct {
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

func (d burpData) decoded() string {
	if strings.EqualFold(d.Base64, "true") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(d.Value)); err == nil {
			return string(raw)
		}
	}
	return d.Value
}

// ParseBurpReader parses a Burp Suite XML export from r. Malformed items are
// skipped rather than aborting the whole import — a triage tool should salvage
// what it can from a partially corrupt capture.
func ParseBurpReader(r io.Reader) ([]*asset.HTTPResponse, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var items burpItems
	if err := xml.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse burp xml: %w", err)
	}
	var out []*asset.HTTPResponse
	for _, it := range items.Items {
		respRaw := it.Response.decoded()
		if strings.TrimSpace(respRaw) == "" {
			continue
		}
		resp := httpparse.ParseResponse(respRaw, "burp")
		resp.Request = httpparse.ParseRequest(it.Request.decoded(), it.URL)
		if resp.StatusCode == 0 {
			resp.StatusCode = it.Status
		}
		out = append(out, resp)
	}
	return out, nil
}

// ParseBurpFile opens path (or stdin when path is "-") and parses it.
func ParseBurpFile(path string) ([]*asset.HTTPResponse, error) {
	if path == "-" {
		return ParseBurpReader(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseBurpReader(f)
}
