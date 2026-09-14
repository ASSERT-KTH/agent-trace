package tlsparse

import (
	"errors"
	"reflect"
	"testing"
)

// buildClientHello assembles a minimal but structurally valid TLS 1.2-style
// ClientHello record wrapping the given extensions (already TLV-encoded).
func buildClientHello(extensions []byte) []byte {
	body := []byte{}
	body = append(body, 0x03, 0x03) // legacy client version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites: len 2, one suite
	body = append(body, 0x01, 0x00)             // compression methods: len 1, null

	if extensions != nil {
		extLen := len(extensions)
		body = append(body, byte(extLen>>8), byte(extLen))
		body = append(body, extensions...)
	}

	hs := []byte{handshakeTypeClientHello}
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	rec := []byte{recordTypeHandshake, 0x03, 0x01}
	recLen := len(hs)
	rec = append(rec, byte(recLen>>8), byte(recLen))
	rec = append(rec, hs...)
	return rec
}

func sniExtension(host string) []byte {
	entry := []byte{0x00} // name_type host_name
	entry = append(entry, byte(len(host)>>8), byte(len(host)))
	entry = append(entry, host...)
	list := []byte{byte(len(entry) >> 8), byte(len(entry))}
	list = append(list, entry...)
	ext := []byte{0x00, 0x00} // extension type SNI
	ext = append(ext, byte(len(list)>>8), byte(len(list)))
	ext = append(ext, list...)
	return ext
}

func alpnExtension(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	data := []byte{byte(len(list) >> 8), byte(len(list))}
	data = append(data, list...)
	ext := []byte{0x00, 0x10} // extension type ALPN
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}

func TestParseClientHello_SNIPresent(t *testing.T) {
	data := buildClientHello(sniExtension("api.example.com"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "api.example.com" {
		t.Errorf("ServerName = %q, want %q", got.ServerName, "api.example.com")
	}
}

func TestParseClientHello_SNIAbsent(t *testing.T) {
	data := buildClientHello(alpnExtension("http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", got.ServerName)
	}
}

func TestParseClientHello_ALPN_H2(t *testing.T) {
	data := buildClientHello(alpnExtension("h2", "http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", got.ALPN)
	}
}

func TestParseClientHello_ALPN_HTTP11Only(t *testing.T) {
	data := buildClientHello(alpnExtension("http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"http/1.1"}) {
		t.Errorf("ALPN = %v, want [http/1.1]", got.ALPN)
	}
}

func TestParseClientHello_SNIAndALPNTogether(t *testing.T) {
	ext := append(append([]byte{}, sniExtension("example.com")...), alpnExtension("h2")...)
	data := buildClientHello(ext)
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", got.ServerName)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"h2"}) {
		t.Errorf("ALPN = %v, want [h2]", got.ALPN)
	}
}

func TestParseClientHello_NonTLSFirstBytes(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\n\r\n")
	_, err := ParseClientHello(data)
	if !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("err = %v, want ErrNotClientHello", err)
	}
}

func TestParseClientHello_TruncatedRecord(t *testing.T) {
	full := buildClientHello(sniExtension("example.com"))
	// Cut off inside the fixed-size prefix (well before extensions begin).
	truncated := full[:10]
	_, err := ParseClientHello(truncated)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

func TestParseClientHello_SplitAtCaptureLimit(t *testing.T) {
	// SNI first, then a second (large-ish) extension, so cutting the buffer
	// after SNI but mid the second extension simulates net.bpf.c's
	// 1024-byte NET_HELLO capture limit landing inside the extensions
	// block. Truncation there must not be an error and must not lose the
	// SNI already parsed.
	big := alpnExtension("h2", "http/1.1", "spdy/3.1", "http/1.0")
	ext := append(append([]byte{}, sniExtension("example.com")...), big...)
	full := buildClientHello(ext)

	cut := len(full) - 3 // land inside the trailing extension's data
	got, err := ParseClientHello(full[:cut])
	if err != nil {
		t.Fatalf("unexpected error on extension-block truncation: %v", err)
	}
	if got.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com (should survive truncation of a later extension)", got.ServerName)
	}
}

func TestParseClientHello_NoExtensions(t *testing.T) {
	data := buildClientHello(nil)
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "" || got.ALPN != nil {
		t.Errorf("got %+v, want zero-value ClientHello", got)
	}
}
