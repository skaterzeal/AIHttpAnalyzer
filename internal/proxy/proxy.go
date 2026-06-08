package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/ai"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/extract"
	"github.com/skaterzeal/AIHttpAnalyzer/internal/output"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// maxProxyBody caps how much of each response body we buffer for analysis.
const maxProxyBody = 5 << 20

// analyzableTypes are the content types worth analyzing; binary assets (images,
// fonts, video) are passed through untouched.
var analyzableTypes = []string{"application/json", "text/html", "text/plain", "application/xml", "text/xml", "application/javascript"}

// Options configures the live proxy.
type Options struct {
	Addr        string
	Engine      *extract.Engine
	CA          tls.Certificate
	Out         io.Writer
	MinSeverity asset.Severity
	Verbose     bool

	// Triager, when set, enables advisory AI triage. It runs ASYNCHRONOUSLY so it
	// never blocks the live traffic path; results are emitted as ai_triage records
	// once the model responds. AIConcurrency bounds in-flight LLM calls.
	Triager       *ai.Triager
	AIConcurrency int
}

// Run starts the MITM proxy on opts.Addr and blocks until interrupted.
func Run(opts Options) error {
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	return Serve(ln, opts)
}

// Serve runs the proxy on an existing listener. Each analyzable response is run
// through the deterministic engine and its findings are streamed as JSONL to
// opts.Out. Splitting this out lets tests drive the proxy on an ephemeral port.
func Serve(ln net.Listener, opts Options) error {
	if err := setCA(opts.CA); err != nil {
		return err
	}

	p := goproxy.NewProxyHttpServer()
	p.Verbose = opts.Verbose
	p.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	aiConc := opts.AIConcurrency
	if aiConc < 1 {
		aiConc = 4
	}
	aiSem := make(chan struct{}, aiConc)

	var mu sync.Mutex
	p.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}
		if !analyzable(resp.Header.Get("Content-Type")) {
			return resp
		}

		// Buffer the body for analysis, then restore it for the client.
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
		if err != nil {
			return resp
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))

		ar := opts.Engine.Analyze(toAsset(resp, ctx.Req, body))
		if len(ar.Findings) > 0 {
			mu.Lock()
			_ = output.WriteJSONL(opts.Out, []asset.AnalyzedResponse{ar}, opts.MinSeverity)
			mu.Unlock()
		}

		// AI triage runs off the hot path so live traffic is never blocked. If all
		// AI workers are busy we skip triage for this response rather than queue.
		if opts.Triager != nil && len(ar.Findings) > 0 {
			select {
			case aiSem <- struct{}{}:
				go func(ar asset.AnalyzedResponse) {
					defer func() { <-aiSem }()
					t, err := opts.Triager.Triage(context.Background(), ar, "")
					if err != nil {
						return
					}
					mu.Lock()
					_ = output.WriteAIRecord(opts.Out, ar.Response.AssetID(), t)
					mu.Unlock()
				}(ar)
			default:
			}
		}
		return resp
	})

	return http.Serve(ln, p)
}

// toAsset converts a live request/response pair into the engine's input type.
func toAsset(resp *http.Response, req *http.Request, body []byte) *asset.HTTPResponse {
	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[strings.ToLower(k)] = resp.Header.Get(k)
	}
	var ar *asset.HTTPRequest
	if req != nil {
		reqHeaders := make(map[string]string, len(req.Header))
		for k := range req.Header {
			reqHeaders[strings.ToLower(k)] = req.Header.Get(k)
		}
		ar = &asset.HTTPRequest{
			Method:  req.Method,
			URL:     req.URL.String(),
			Path:    req.URL.Path,
			Headers: reqHeaders,
		}
	}
	return &asset.HTTPResponse{
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		Body:        string(body),
		ContentType: headers["content-type"],
		SizeBytes:   len(body),
		Request:     ar,
		Source:      "proxy",
	}
}

func analyzable(ct string) bool {
	ct = strings.ToLower(ct)
	for _, t := range analyzableTypes {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

// setCA installs the operator's CA into goproxy's MITM machinery.
func setCA(ca tls.Certificate) error {
	if ca.Leaf == nil {
		leaf, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return err
		}
		ca.Leaf = leaf
	}
	goproxy.GoproxyCa = ca
	tlsConfig := goproxy.TLSConfigFromCA(&ca)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}
	return nil
}
