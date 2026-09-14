// Package net is the Tier 3 network probe. This first slice (S3, see
// docs/plan/06_tier3_network_design.md section 11) implements only the
// kernel-side identity half: connect/write/sendto/sendmsg/close
// tracepoints, first-write ClientHello capture, and SNI extraction via
// pkg/tlsparse. Content correlation against the SSL_write uprobe (tls.bpf.c,
// the active_write/NET_BIND join, models.ActionNetRequest) is S5 and is not
// implemented here; see STATE.md and design doc section 13 (D1, D3, D5) for
// what blocks it.
//
// Because this slice has no content layer yet, it emits
// models.ActionType(models.NetConnect) events -- "a connection was observed,
// here is its resolved hostname if any" -- rather than NetRequest events.
// This is a deliberate stand-in for S3 only: once S5 lands, connections with
// captured content should produce NetRequest events instead, and
// Observer.readLoop's emission point is where that switch happens.
package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	stdnet "net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// Event type values mirror the NET_* constants in net.bpf.c.
const (
	netConnect uint8 = 1
	netHello   uint8 = 2
	netBind    uint8 = 3 // unused until tls.bpf.c exists (S5)
	netClose   uint8 = 4
)

const (
	afInet  = 2
	afInet6 = 10
)

// Config controls the observer's behavior.
type Config struct {
	// TrackedPID, if > 0, is seeded into tracked_pids at New so this single
	// process's connections are observed. Additional PIDs can be added
	// later via TrackPID. There is no global (untracked) mode: net.bpf.c
	// gates every program on tracked_pids membership unconditionally (see
	// design doc section 4.1), so an Observer with no tracked PID at all
	// sees nothing until TrackPID is called.
	TrackedPID int32

	// EventBufSize is the channel buffer size for emitted events. Defaults
	// to 4096 if zero.
	EventBufSize int
}

// connection is per-connection correlator state, keyed by (tgid, fd).
type connection struct {
	family   uint8
	addr     [16]byte
	port     uint16
	openedAt time.Time
	host     string
	alpn     []string
	emitted  bool
}

// Observer watches network connections via eBPF and emits
// models.GroundTruthEvent values. See the package doc comment for what this
// slice does and does not cover.
type Observer struct {
	objs        bpfObjects
	connectLink link.Link
	writeLink   link.Link
	sendtoLink  link.Link
	sendmsgLink link.Link
	closeLink   link.Link
	reader      *ringbuf.Reader
	events      chan models.GroundTruthEvent
	stopped     chan struct{}
	cfg         Config
	dropped     atomic.Uint64
	stopOnce    sync.Once

	bootOffsetNs int64

	conns map[connKeyGo]*connection
}

// connKeyGo mirrors net.bpf.c's conn_key; it is the correlator's own map
// key, decoded from bpfNetEventHdr fields rather than sharing bpfConnKey's
// generated type, since the header carries tgid/fd directly.
type connKeyGo struct {
	tgid uint32
	fd   uint32
}

// New loads the eBPF programs, attaches the tracepoints, and opens the ring
// buffer. The caller must call Start to begin receiving events and Stop to
// release resources. Requires CAP_BPF + CAP_PERFMON (or root).
func New(cfg Config) (*Observer, error) {
	if cfg.EventBufSize <= 0 {
		cfg.EventBufSize = 4096
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	bootOffsetNs, err := computeBootOffsetNs()
	if err != nil {
		return nil, fmt.Errorf("compute boot offset: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	if cfg.TrackedPID > 0 {
		p := uint32(cfg.TrackedPID)
		one := uint8(1)
		if err := objs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update tracked_pids: %w", err)
		}
	}

	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_connect: %w", err)
	}
	writeLink, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
	if err != nil {
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_write: %w", err)
	}
	sendtoLink, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendto, nil)
	if err != nil {
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_sendto: %w", err)
	}
	sendmsgLink, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSendmsg, nil)
	if err != nil {
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_sendmsg: %w", err)
	}
	closeLink, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceClose, nil)
	if err != nil {
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_close: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Observer{
		objs:         objs,
		connectLink:  connectLink,
		writeLink:    writeLink,
		sendtoLink:   sendtoLink,
		sendmsgLink:  sendmsgLink,
		closeLink:    closeLink,
		reader:       reader,
		events:       make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:      make(chan struct{}),
		cfg:          cfg,
		bootOffsetNs: bootOffsetNs,
		conns:        make(map[connKeyGo]*connection),
	}, nil
}

// computeBootOffsetNs pairs a CLOCK_MONOTONIC read with a wall-clock read
// taken immediately after, so any later bpf_ktime_get_ns() reading can be
// converted to wall-clock time. Identical in method to pkg/probe/proc's
// helper of the same name; kept as a separate copy since each probe package
// is self-contained and independently attachable.
func computeBootOffsetNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	monoNs := ts.Nano()
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}

// TrackPID adds a PID to tracked_pids so its connections are observed. Safe
// to call after Start.
func (o *Observer) TrackPID(pid int32) error {
	p := uint32(pid)
	one := uint8(1)
	if err := o.objs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tracked_pids: %w", err)
	}
	return nil
}

// Events returns the channel on which GroundTruthEvents are delivered. The
// channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// Dropped reports how many events were discarded because the events channel
// was full. Check after Stop returns.
func (o *Observer) Dropped() uint64 {
	return o.dropped.Load()
}

// Start begins reading ring-buffer records in a background goroutine.
func (o *Observer) Start() {
	go o.readLoop()
}

// Stop unblocks the read loop, waits for it, and releases all resources.
// The events channel is closed after Stop returns. Safe to call once.
func (o *Observer) Stop() error {
	o.stopOnce.Do(func() {
		_ = o.reader.Close() // unblocks readLoop's Read with ErrClosed
		<-o.stopped
		_ = o.closeLink.Close()
		_ = o.sendmsgLink.Close()
		_ = o.sendtoLink.Close()
		_ = o.writeLink.Close()
		_ = o.connectLink.Close()
		_ = o.objs.Close()
		close(o.events)
	})
	return nil
}

func (o *Observer) readLoop() {
	defer close(o.stopped)

	var hdr bpfNetEventHdr
	hdrSize := binary.Size(hdr)

	for {
		record, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(record.RawSample) < hdrSize {
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &hdr); err != nil {
			continue
		}

		key := connKeyGo{tgid: hdr.Tgid, fd: hdr.Fd}
		ts := time.Unix(0, int64(hdr.TsNs)+o.bootOffsetNs)

		switch hdr.Type {
		case netConnect:
			o.conns[key] = &connection{
				family:   hdr.Family,
				addr:     hdr.Addr,
				port:     hdr.Port,
				openedAt: ts,
			}

		case netHello:
			conn, ok := o.conns[key]
			if !ok {
				continue
			}
			payloadEnd := hdrSize + int(hdr.PayloadLen)
			if payloadEnd > len(record.RawSample) {
				continue
			}
			payload := record.RawSample[hdrSize:payloadEnd]
			hello, err := tlsparse.ParseClientHello(payload)
			if err != nil || hello.ServerName == "" {
				continue
			}
			conn.host = hello.ServerName
			conn.alpn = hello.ALPN
			o.emit(key, conn, int32(hdr.Tgid), ts)

		case netBind:
			// No-op until tls.bpf.c exists; net.bpf.c never emits this yet.
			continue

		case netClose:
			conn, ok := o.conns[key]
			if ok {
				o.emit(key, conn, int32(hdr.Tgid), ts)
			}
			delete(o.conns, key)
		}
	}
}

// emit sends one models.GroundTruthEvent for conn if it hasn't already been
// emitted (a connection whose SNI was parsed emits once, at NET_HELLO time;
// one that never yielded a hostname emits once, at NET_CLOSE, with a
// peer-address fallback target).
func (o *Observer) emit(key connKeyGo, conn *connection, tgid int32, ts time.Time) {
	if conn.emitted {
		return
	}
	conn.emitted = true

	target := conn.host
	if target == "" {
		target = peerAddrPort(conn.family, conn.addr, conn.port)
	}

	isTopLevel := true
	event := models.GroundTruthEvent{
		Timestamp:  ts,
		ActionType: models.NetConnect,
		Target:     target,
		IsTopLevel: &isTopLevel,
	}

	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

// peerAddrPort formats a fallback target for a connection whose first bytes
// never parsed as a ClientHello with SNI (non-TLS traffic, or a truncated
// hello that lost the extension before it was reached).
func peerAddrPort(family uint8, addr [16]byte, port uint16) string {
	var ip stdnet.IP
	switch family {
	case afInet:
		ip = stdnet.IP(addr[:4])
	case afInet6:
		ip = stdnet.IP(addr[:16])
	default:
		return ""
	}
	return stdnet.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}
