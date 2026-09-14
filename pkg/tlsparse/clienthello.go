// Package tlsparse parses TLS ClientHello records and HTTP/1.1 requests from
// captured plaintext. It is pure Go with no eBPF and no syscalls, so its
// tests run unprivileged; it exists to be called from pkg/probe/net's
// correlator, which owns all kernel interaction.
package tlsparse

import "errors"

// ErrNotClientHello means the input is not a TLS handshake record carrying a
// ClientHello -- wrong content type, or a handshake message type other than
// client_hello (1). The correlator should mark the connection non-TLS and
// move on; this is not a transient condition that more bytes would fix.
var ErrNotClientHello = errors.New("tlsparse: not a TLS ClientHello")

// ErrTruncated means the input looks like the start of a ClientHello but
// ends before the mandatory fixed-size fields (through the compression
// methods list) are fully present. Unlike ErrNotClientHello, this can be a
// capture-size artifact: the correlator's caller may see it if it (unlike
// net.bpf.c's 1024-byte NET_HELLO capture) hands ParseClientHello something
// smaller. Truncation inside the extensions block, which is far more likely
// in practice given how small the fixed prefix is, is not an error at all --
// see the doc comment on ParseClientHello.
var ErrTruncated = errors.New("tlsparse: truncated ClientHello")

// ClientHello holds the fields this package extracts from a ClientHello.
// Everything else in the message (cipher suites, key shares, supported
// groups, ...) is parsed only far enough to skip past it.
type ClientHello struct {
	// ServerName is the SNI host_name entry, if present. Empty otherwise.
	ServerName string
	// ALPN is the client's offered protocol list, in offered order (e.g.
	// ["h2", "http/1.1"]). Empty when the extension is absent.
	ALPN []string
}

// ParseClientHello extracts the SNI hostname and ALPN protocol list from the
// first TLS record of a connection.
//
// The fixed-size ClientHello prefix (legacy version, random, session ID,
// cipher suites, compression methods) must be fully present or this returns
// ErrTruncated: that prefix is a few dozen bytes and any real capture should
// contain it whole. The extensions block that follows has no such guarantee
// -- a capture limit (net.bpf.c takes at most 1024 bytes) can legitimately
// cut it off mid-extension, especially with a long cipher/extension list
// ahead of SNI. Truncation there is therefore not an error: parsing stops at
// the first incomplete extension and returns whatever was found in the
// extensions read so far. SNI and ALPN are both early, small extensions in
// practice, so this degrades gracefully rather than losing them outright.
func ParseClientHello(data []byte) (ClientHello, error) {
	c := &cursor{buf: data}

	contentType, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if contentType != recordTypeHandshake {
		return ClientHello{}, ErrNotClientHello
	}

	// Legacy record version and record length. We don't validate the
	// version beyond requiring it look like a TLS version (major byte 3):
	// ClientHello records commonly carry 0x0301 regardless of the
	// negotiated version, and stricter checking buys nothing here.
	ver, err := c.u16()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if ver>>8 != 3 {
		return ClientHello{}, ErrNotClientHello
	}
	if _, err := c.u16(); err != nil { // record length, unused: we trust buf's own bounds
		return ClientHello{}, ErrTruncated
	}

	msgType, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if msgType != handshakeTypeClientHello {
		return ClientHello{}, ErrNotClientHello
	}
	if _, err := c.u24(); err != nil { // handshake body length, same as above
		return ClientHello{}, ErrTruncated
	}

	if _, err := c.u16(); err != nil { // legacy client version
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(32); err != nil { // random
		return ClientHello{}, ErrTruncated
	}
	sessionIDLen, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(sessionIDLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}
	cipherSuitesLen, err := c.u16()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(cipherSuitesLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}
	compressionLen, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(compressionLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}

	var hello ClientHello

	// Everything from here on is best-effort: absence or truncation is not
	// an error, per the doc comment above.
	extensionsLen, err := c.u16()
	if err != nil {
		return hello, nil
	}

	remaining := int(extensionsLen)
	for remaining >= 4 && c.remaining() >= 4 {
		extType, err := c.u16()
		if err != nil {
			break
		}
		extLen, err := c.u16()
		if err != nil {
			break
		}
		remaining -= 4
		extData, err := c.bytes(int(extLen))
		if err != nil {
			break
		}
		remaining -= int(extLen)

		switch extType {
		case extTypeSNI:
			if name, ok := parseSNIExtension(extData); ok {
				hello.ServerName = name
			}
		case extTypeALPN:
			hello.ALPN = parseALPNExtension(extData)
		}
	}

	return hello, nil
}

const (
	recordTypeHandshake     = 0x16
	handshakeTypeClientHello = 0x01
	extTypeSNI               = 0x0000
	extTypeALPN              = 0x0010
	sniNameTypeHostName      = 0x00
)

// parseSNIExtension extracts the first host_name entry from a
// server_name_list extension body. Returns ok=false on any malformed input
// rather than an error: a broken SNI extension should not fail the whole
// ClientHello parse.
func parseSNIExtension(data []byte) (string, bool) {
	c := &cursor{buf: data}
	listLen, err := c.u16()
	if err != nil {
		return "", false
	}
	end := int(listLen)
	if end > len(data)-2 {
		end = len(data) - 2
	}
	for c.pos < 2+end {
		nameType, err := c.u8()
		if err != nil {
			return "", false
		}
		nameLen, err := c.u16()
		if err != nil {
			return "", false
		}
		name, err := c.bytes(int(nameLen))
		if err != nil {
			return "", false
		}
		if nameType == sniNameTypeHostName {
			return string(name), true
		}
	}
	return "", false
}

// parseALPNExtension extracts the protocol_name_list from an ALPN extension
// body, in offered order. A malformed entry stops iteration and returns
// whatever was parsed so far rather than erroring.
func parseALPNExtension(data []byte) []string {
	c := &cursor{buf: data}
	if _, err := c.u16(); err != nil { // protocol_name_list length, unused: bounded by data itself
		return nil
	}
	var protos []string
	for c.remaining() > 0 {
		n, err := c.u8()
		if err != nil {
			break
		}
		name, err := c.bytes(int(n))
		if err != nil {
			break
		}
		protos = append(protos, string(name))
	}
	return protos
}

// cursor is a bounds-checked reader over a byte slice.
type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) remaining() int {
	return len(c.buf) - c.pos
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, errShortRead
	}
	b := c.buf[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.bytes(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (c *cursor) u24() (uint32, error) {
	b, err := c.bytes(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

var errShortRead = errors.New("tlsparse: short read")
