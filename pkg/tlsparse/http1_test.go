package tlsparse

import (
	"testing"
)

func parseOne(t *testing.T, s *Stream) *HTTPRequest {
	t.Helper()
	req, ok, err := ParseHTTP1(s)
	if err != nil {
		t.Fatalf("ParseHTTP1 error: %v", err)
	}
	if !ok {
		t.Fatalf("ParseHTTP1 reported incomplete, want complete")
	}
	return req
}

func TestParseHTTP1_SplitMidRequestLine(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /v1/mess"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("ages HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	req := parseOne(t, s)
	if req.Method != "GET" || req.Path != "/v1/messages" {
		t.Errorf("got method=%q path=%q", req.Method, req.Path)
	}
}

func TestParseHTTP1_SplitMidHeaders(t *testing.T) {
	s := NewStream()
	s.Append([]byte("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Le"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("ngth: 5\r\n\r\nhello"))
	req := parseOne(t, s)
	if req.Method != "POST" || string(req.Body) != "hello" {
		t.Errorf("got method=%q body=%q", req.Method, req.Body)
	}
}

func TestParseHTTP1_SplitMidBody(t *testing.T) {
	s := NewStream()
	s.Append([]byte("POST /v1/messages HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello "))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("world"))
	req := parseOne(t, s)
	if string(req.Body) != "hello world" {
		t.Errorf("body = %q, want %q", req.Body, "hello world")
	}
}

func TestParseHTTP1_PipelinedRequestsInOneChunk(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"GET /a HTTP/1.1\r\nHost: h\r\n\r\n" +
			"GET /b HTTP/1.1\r\nHost: h\r\n\r\n"))

	first := parseOne(t, s)
	if first.Path != "/a" {
		t.Errorf("first.Path = %q, want /a", first.Path)
	}
	second := parseOne(t, s)
	if second.Path != "/b" {
		t.Errorf("second.Path = %q, want /b", second.Path)
	}
	if s.Len() != 0 {
		t.Errorf("stream has %d leftover bytes, want 0", s.Len())
	}
}

func TestParseHTTP1_ChunkedTransferEncoding(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n" +
			"6\r\n world\r\n" +
			"0\r\n\r\n"))

	req := parseOne(t, s)
	if string(req.Body) != "hello world" {
		t.Errorf("body = %q, want %q", req.Body, "hello world")
	}
	if s.Len() != 0 {
		t.Errorf("stream has %d leftover bytes after chunked body, want 0", s.Len())
	}
}

func TestParseHTTP1_ChunkedThenPipelinedRequest(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n" +
			"0\r\n\r\n" +
			"GET /next HTTP/1.1\r\nHost: h\r\n\r\n"))

	first := parseOne(t, s)
	if string(first.Body) != "hello" {
		t.Errorf("body = %q, want hello", first.Body)
	}
	second := parseOne(t, s)
	if second.Path != "/next" {
		t.Errorf("second.Path = %q, want /next (chunked decode must not over-consume)", second.Path)
	}
}

func TestParseHTTP1_ChunkedIncomplete(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhel"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
}

func TestParseHTTP1_NoBody(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /health HTTP/1.1\r\nHost: h\r\n\r\n"))
	req := parseOne(t, s)
	if len(req.Body) != 0 {
		t.Errorf("body = %q, want empty", req.Body)
	}
}

func TestParseHTTP1_MalformedRequestLine(t *testing.T) {
	s := NewStream()
	s.Append([]byte("NOTAREQUESTLINE\r\n\r\n"))
	_, _, err := ParseHTTP1(s)
	if err == nil {
		t.Fatal("want error for malformed request line")
	}
}

func TestParseHTTP1_QueryVerbatim(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /search?q=a+b&x=1 HTTP/1.1\r\nHost: h\r\n\r\n"))
	req := parseOne(t, s)
	if req.Path != "/search" || req.Query != "q=a+b&x=1" {
		t.Errorf("path=%q query=%q", req.Path, req.Query)
	}
}
