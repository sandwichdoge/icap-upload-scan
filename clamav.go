// clamav.go — ClamAV scanning engine.
//
// Implements the Scanner interface by speaking clamd's INSTREAM protocol
// over a Unix socket. Data is streamed from the in-memory buffer using a
// pooled 32 KB scratch buffer — no extra copy of the full content.

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

// clamPool avoids GC pressure under load: one 32 KB buffer checkout per
// scan, returned immediately after the INSTREAM conversation completes.
var clamPool = sync.Pool{New: func() any { b := make([]byte, clamBuf); return &b }}

// ClamAVScanner sends content to clamd and reports signature matches.
type ClamAVScanner struct {
	Socket  string        // Unix socket path (e.g. /run/clamav/clamd.ctl)
	Timeout time.Duration // per-scan deadline (default 120s)
}

func (c *ClamAVScanner) Name() string { return "clamav" }

func (c *ClamAVScanner) Init() error {
	if c.Timeout == 0 {
		c.Timeout = 120 * time.Second
	}
	// Verify clamd is reachable at startup
	conn, err := net.DialTimeout("unix", c.Socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach clamd at %s: %w", c.Socket, err)
	}
	conn.Close()
	return nil
}

func (c *ClamAVScanner) Close() {} // nothing to tear down

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
	conn, err := net.DialTimeout("unix", c.Socket, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("clamd connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}

	bp := clamPool.Get().(*[]byte)
	buf := *bp
	defer clamPool.Put(bp)

	var hdr [4]byte
	for {
		n, re := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := conn.Write(hdr[:]); err != nil {
				return "", err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			return "", re
		}
	}

	// zero-length chunk terminates INSTREAM
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := conn.Write(hdr[:]); err != nil {
		return "", err
	}

	var resp [512]byte
	n, _ := conn.Read(resp[:])
	s := strings.TrimRight(string(resp[:n]), "\x00 \r\n")
	if idx := strings.Index(s, "FOUND"); idx > 0 {
		s = s[strings.IndexByte(s, ':')+1:]
		threat := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "FOUND"))
		log.Printf("FOUND %s in %s from %s [clamav]", threat, "<stream>", "")
		return threat, nil
	}
	return "", nil
}
