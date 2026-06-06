package httpparse

import "testing"

func TestParseResponseCRLF(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx/1.18.0\r\n\r\n{\"ok\":true}"
	r := ParseResponse(raw, "file")
	if r.StatusCode != 200 {
		t.Errorf("status = %d, want 200", r.StatusCode)
	}
	if r.ContentType != "application/json" {
		t.Errorf("content-type = %q", r.ContentType)
	}
	if r.Headers["server"] != "nginx/1.18.0" {
		t.Errorf("server header = %q", r.Headers["server"])
	}
	if r.Body != `{"ok":true}` {
		t.Errorf("body = %q", r.Body)
	}
	if r.SizeBytes != len(`{"ok":true}`) {
		t.Errorf("size = %d", r.SizeBytes)
	}
}

func TestParseResponseLF(t *testing.T) {
	raw := "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\n<h1>boom</h1>"
	r := ParseResponse(raw, "file")
	if r.StatusCode != 500 {
		t.Errorf("status = %d, want 500", r.StatusCode)
	}
	if r.Body != "<h1>boom</h1>" {
		t.Errorf("body = %q", r.Body)
	}
}

func TestParseResponseHeaderOnly(t *testing.T) {
	r := ParseResponse("HTTP/1.1 204 No Content\r\nX-Foo: bar", "file")
	if r.StatusCode != 204 {
		t.Errorf("status = %d", r.StatusCode)
	}
	if r.Headers["x-foo"] != "bar" {
		t.Errorf("x-foo = %q", r.Headers["x-foo"])
	}
	if r.Body != "" {
		t.Errorf("body should be empty, got %q", r.Body)
	}
}

func TestParseResponseMalformedNoStatusLine(t *testing.T) {
	// Garbage in, but we should still extract the body and not panic.
	r := ParseResponse("just some text\r\n\r\nbody here", "file")
	if r.StatusCode != 0 {
		t.Errorf("status = %d, want 0 for malformed", r.StatusCode)
	}
	if r.Body != "body here" {
		t.Errorf("body = %q", r.Body)
	}
}

func TestParseRequest(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"u\":\"a\"}"
	req := ParseRequest(raw, "https://example.com/api/login")
	if req == nil {
		t.Fatal("request is nil")
	}
	if req.Method != "POST" {
		t.Errorf("method = %q", req.Method)
	}
	if req.Path != "/api/login" {
		t.Errorf("path = %q", req.Path)
	}
	if req.URL != "https://example.com/api/login" {
		t.Errorf("url = %q", req.URL)
	}
	if req.Headers["host"] != "example.com" {
		t.Errorf("host = %q", req.Headers["host"])
	}
	if req.Body != `{"u":"a"}` {
		t.Errorf("body = %q", req.Body)
	}
}

func TestParseRequestEmpty(t *testing.T) {
	if ParseRequest("   ", "") != nil {
		t.Error("empty request should parse to nil")
	}
}
