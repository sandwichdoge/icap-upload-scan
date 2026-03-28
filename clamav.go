// clamav.go — ClamAV scanning engine.
//
// Implements the Scanner interface by speaking clamd's INSTREAM protocol
// over a Unix socket. Data is streamed from the in-memory buffer using a
// pooled 32 KB scratch buffer — no extra copy of the full content.
//
// Connections to clamd are pooled (channel-based, bounded) to avoid
// the overhead of dial+close per scan. Each connection is validated
// with a PING before reuse; broken connections are discarded silently.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const clamBuf = 32 << 10 // 32 KB — clamd streaming chunk size

// clamScratchPool avoids GC pressure under load: one 32 KB buffer
// checkout per scan, returned immediately after the INSTREAM
// conversation completes.
var clamScratchPool = sync.Pool{New: func() any { b := make([]byte, clamBuf); return &b }}

// ClamAVScanner sends content to clamd and reports signature matches.
type ClamAVScanner struct {
	Socket   string        // Unix socket path (e.g. /run/clamav/clamd.ctl)
	Timeout  time.Duration // per-scan deadline (default 120s)
	PoolSize int           // max idle connections (default 16)

	pool chan net.Conn // bounded channel of idle connections
}

func (c *ClamAVScanner) Name() string { return "clamav" }

func (c *ClamAVScanner) Init() error {
	if c.Timeout == 0 {
		c.Timeout = 120 * time.Second
	}
	if c.PoolSize <= 0 {
		c.PoolSize = 16
	}
	c.pool = make(chan net.Conn, c.PoolSize)

	// Verify clamd is reachable at startup
	conn, err := net.DialTimeout("unix", c.Socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach clamd at %s: %w", c.Socket, err)
	}
	// Seed the pool with this first connection.
	c.pool <- conn
	return nil
}

func (c *ClamAVScanner) Close() {
	// Drain and close all pooled connections.
	for {
		select {
		case conn := <-c.pool:
			conn.Close()
		default:
			return
		}
	}
}

// getConn returns a pooled connection or dials a new one.
// Pooled connections are validated with a PING; stale ones are discarded.
func (c *ClamAVScanner) getConn() (net.Conn, error) {
	for {
		select {
		case conn := <-c.pool:
			// Validate with PING — clamd responds "PONG\0".
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write([]byte("zPING\x00")); err != nil {
				conn.Close()
				continue
			}
			var buf [64]byte
			n, err := conn.Read(buf[:])
			if err != nil || !strings.Contains(string(buf[:n]), "PONG") {
				conn.Close()
				continue
			}
			return conn, nil
		default:
			// Pool empty — dial a fresh connection.
			return net.DialTimeout("unix", c.Socket, 5*time.Second)
		}
	}
}

// putConn returns a connection to the pool. If the pool is full the
// connection is closed instead.
func (c *ClamAVScanner) putConn(conn net.Conn) {
	select {
	case c.pool <- conn:
		// returned to pool
	default:
		conn.Close() // pool full
	}
}

// ScanBytes streams data to clamd's INSTREAM command and returns the
// threat name if a signature matches, or "" if clean.
func (c *ClamAVScanner) ScanBytes(data []byte, filename, clientIP string) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	return c.scanReader(bytes.NewReader(data))
}

// scanReader implements the INSTREAM wire protocol:
//
//	→ "zINSTREAM\0"
//	→ [4-byte big-endian length][chunk data] ...
//	→ [4-byte zero]              (end of stream)
//	← "stream: OK\0"  or  "stream: <signature> FOUND\0"
func (c *ClamAVScanner) scanReader(r io.Reader) (string, error) {
	conn, err := c.getConn()
	if err != nil {
		return "", fmt.Errorf("clamd connect: %w", err)
	}

	conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		conn.Close() // don't return broken conn to pool
		return "", err
	}

	bp := clamScratchPool.Get().(*[]byte)
	buf := *bp
	defer clamScratchPool.Put(bp)

	var hdr [4]byte
	writeOK := true
	for {
		n, re := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := conn.Write(hdr[:]); err != nil {
				writeOK = false
				break
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				writeOK = false
				break
			}
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			conn.Close()
			return "", re
		}
	}

	if !writeOK {
		conn.Close()
		return "", fmt.Errorf("clamd write error")
	}

	// zero-length chunk terminates INSTREAM
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := conn.Write(hdr[:]); err != nil {
		conn.Close()
		return "", err
	}

	var resp [512]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("clamd read response: %w", err)
	}

	// Connection is healthy — return it to the pool for reuse.
	c.putConn(conn)

	s := strings.TrimRight(string(resp[:n]), "\x00 \r\n")
	if idx := strings.Index(s, "FOUND"); idx > 0 {
		s = s[strings.IndexByte(s, ':')+1:]
		threat := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "FOUND"))
		log.Printf("FOUND %s in %s from %s [clamav]", threat, "<stream>", "")
		return threat, nil
	}
	return "", nil
}
