// icap.go — Shared ICAP/1.0 protocol layer.
//
// Handles TCP accept, ICAP request parsing, OPTIONS negotiation,
// REQMOD dispatch, chunked transfer decoding, multipart splitting,
// and response framing. Scanning is delegated to the pipeline.
//
// This file owns no scanning logic — it only moves bytes between
// the Squid proxy and the scanner pipeline.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"strconv"
	"strings"
	"time"
)

// ── ICAP server ─────────────────────────────────────────────────

// icapServer holds the shared state for the ICAP listener.
type icapServer struct {
	pipe      *pipeline
	blockPage string
	maxBody   int64 // max total body bytes
	maxPart   int64 // max bytes per multipart part
	maxConns  int
	sem       chan struct{} // concurrency limiter
	debug     bool
}

func (s *icapServer) handleConn(conn net.Conn) {
	defer conn.Close()
	s.sem <- struct{}{}        // acquire slot
	defer func() { <-s.sem }() // release slot

	conn.SetDeadline(time.Now().Add(300 * time.Second))
	br := bufio.NewReaderSize(conn, 8192)
	bw := bufio.NewWriterSize(conn, 4096)
	defer bw.Flush()

	// ── ICAP request line ──
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 || fields[2] != "ICAP/1.0" {
		return
	}

	// ── ICAP headers ──
	ih := make(map[string]string, 8)
	for {
		ln, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(ln) == "" {
			break
		}
		if i := strings.IndexByte(ln, ':'); i > 0 {
			ih[strings.ToLower(strings.TrimSpace(ln[:i]))] = strings.TrimSpace(ln[i+1:])
		}
	}

	switch fields[0] {
	case "OPTIONS":
		fmt.Fprintf(bw,
			"ICAP/1.0 200 OK\r\n"+
				"ISTag: \"uploadscan-1\"\r\n"+
				"Methods: REQMOD\r\n"+
				"Service: uploadscan/1.0\r\n"+
				"Allow: 204\r\n"+
				"Max-Connections: %d\r\n"+
				"\r\n", s.maxConns)
	case "REQMOD":
		s.doReqmod(br, bw, ih)
	default:
		fmt.Fprint(bw, "ICAP/1.0 405 Method Not Allowed\r\nISTag: \"uploadscan\"\r\n\r\n")
	}
}

// ── REQMOD handler ──────────────────────────────────────────────
//
// Flow:
//   1. Parse Encapsulated header → locate HTTP request headers + body
//   2. No body → 204
//   3. Handle Preview if present (drain + 100 Continue)
//   4. Multipart → buffer each part, run pipeline on each file part,
//      accumulate text fields, run pipeline on text at the end
//   5. Non-multipart → buffer body, run pipeline once

func (s *icapServer) doReqmod(br *bufio.Reader, bw *bufio.Writer, ih map[string]string) {
	enc := parseEnc(ih["encapsulated"])
	cip := ih["x-client-ip"]

	s.dbg("REQMOD from %s encapsulated=%s", cip, ih["encapsulated"])

	// ── Read encapsulated HTTP request headers ──
	var httpHdr string
	if _, ok := enc["req-hdr"]; ok {
		bodyOff := 0
		if v, ok2 := enc["req-body"]; ok2 {
			bodyOff = v
		} else if v, ok2 := enc["null-body"]; ok2 {
			bodyOff = v
		}
		sz := bodyOff - enc["req-hdr"]
		if sz > 0 && sz < 1<<16 {
			buf := make([]byte, sz)
			if _, err := io.ReadFull(br, buf); err != nil {
				s.dbg("failed to read HTTP headers: %v", err)
				return
			}
			httpHdr = string(buf)
		}
	}

	// ── No body → nothing to scan ──
	if _, ok := enc["req-body"]; !ok {
		s.dbg("null-body request from %s → 204", cip)
		s.send204(bw)
		return
	}

	ct := hdrVal(httpHdr, "content-type")
	s.dbg("content-type: %s", ct)

	// ── Preview handling (safety net) ──
	// If Squid sends a Preview header (from a cached OPTIONS response),
	// drain the preview body and send 100 Continue to get the full body.
	if preview := ih["preview"]; preview != "" {
		s.dbg("preview header present: %s — draining and sending 100 Continue", preview)
		previewReader := &chunkedReader{r: br}
		n, _ := io.Copy(io.Discard, previewReader)
		s.dbg("drained %d preview bytes", n)

		fmt.Fprint(bw, "ICAP/1.0 100 Continue\r\n\r\n")
		bw.Flush()
	}

	body := io.LimitReader(&chunkedReader{r: br}, s.maxBody)

	// ── Multipart: buffer and scan each part ──
	if isMultipart(ct) {
		if _, params, err := mime.ParseMediaType(ct); err == nil {
			if bnd := params["boundary"]; bnd != "" {
				s.dbg("multipart boundary=%s", bnd)
				threat, err := s.scanMultipart(body, bnd, cip)
				if err != nil {
					log.Printf("scan error: %v", err)
					s.send500(bw)
					return
				}
				if threat != "" {
					log.Printf("BLOCKED upload from %s: %s", cip, threat)
					s.sendBlock(bw, threat)
					return
				}
				s.dbg("multipart clean → 204")
				s.send204(bw)
				return
			}
		}
	}

	// ── Non-multipart: buffer entire body, scan once ──
	data, err := io.ReadAll(body)
	if err != nil || len(data) == 0 {
		s.send204(bw)
		return
	}

	fname := inferFilename(httpHdr, "upload")
	s.dbg("non-multipart body: %d bytes, filename=%s", len(data), fname)

	threat, err := s.pipe.scan(data, fname, cip)
	if err != nil {
		log.Printf("scan error: %v", err)
		s.send500(bw)
		return
	}
	if threat != "" {
		log.Printf("BLOCKED upload from %s: %s (%s)", cip, threat, fname)
		s.sendBlock(bw, threat)
		return
	}
	s.send204(bw)
}

// isMultipart returns true if the Content-Type is any multipart/* type
// that carries a boundary and whose parts should be scanned individually.
func isMultipart(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "multipart/")
}

// ── Multipart scanner ───────────────────────────────────────────
//
// Each file part is buffered (up to maxPart) and fed through the full
// pipeline. Text form fields are accumulated and scanned together at
// the end — catches sensitive data in non-file form fields.

func (s *icapServer) scanMultipart(body io.Reader, boundary, clientIP string) (string, error) {
	mr := multipart.NewReader(body, boundary)
	var textFields bytes.Buffer
	partNum := 0

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("multipart parse: %v", err)
			break
		}
		partNum++

		// Determine the effective reader for this part: if the part
		// declares Content-Transfer-Encoding: base64, wrap in a
		// base64 decoder so downstream scanners see raw bytes.
		var partReader io.Reader = p
		cte := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding")))
		if cte == "base64" {
			s.dbg("part %d: decoding base64 content-transfer-encoding", partNum)
			partReader = base64.NewDecoder(base64.StdEncoding, p)
		}

		// Determine filename. For multipart/form-data the filename
		// comes from Content-Disposition "filename" param.
		// For multipart/related (and others) the part may have no
		// Content-Disposition at all; fall back to the part's
		// Content-Type or a generated name.
		fn := partFilename(p, partNum)

		if fn != "" {
			// ── File / named part: buffer and scan through pipeline ──
			data, err := io.ReadAll(io.LimitReader(partReader, s.maxPart))
			p.Close()
			if err != nil {
				return "", fmt.Errorf("read part %s: %w", fn, err)
			}
			s.dbg("part %d: file=%s size=%d bytes (cte=%s)", partNum, fn, len(data), cte)

			threat, err := s.pipe.scan(data, fn, clientIP)
			if err != nil {
				return "", err
			}
			if threat != "" {
				return threat, nil
			}
		} else {
			// ── Text field: accumulate ──
			fieldName := p.FormName()
			n, _ := io.Copy(&textFields, io.LimitReader(partReader, 1<<20))
			textFields.WriteByte('\n')
			p.Close()
			s.dbg("part %d: text field=%s size=%d bytes", partNum, fieldName, n)
		}
	}

	s.dbg("multipart: %d parts, %d bytes text fields", partNum, textFields.Len())

	// Scan concatenated text fields through the pipeline
	if textFields.Len() > 0 {
		threat, err := s.pipe.scan(textFields.Bytes(), "", clientIP)
		if err != nil {
			return "", err
		}
		if threat != "" {
			log.Printf("FOUND %s in form text fields from %s", threat, clientIP)
			return threat, nil
		}
	}

	return "", nil
}

// partFilename extracts a usable filename for a multipart part.
//
// For multipart/form-data, FileName() returns the "filename" param from
// Content-Disposition. For multipart/related and other types the part
// may carry Content-Disposition: attachment with a filename, or have no
// disposition at all. In the latter case we derive a name from
// Content-ID or Content-Type so that every non-trivial part gets scanned
// as a "file".
func partFilename(p *multipart.Part, partNum int) string {
	// 1. Standard filename from Content-Disposition (works for form-data
	//    and attachment dispositions alike).
	if fn := p.FileName(); fn != "" {
		return fn
	}

	// 2. If the part has a Content-Disposition with FormName (i.e. it is
	//    a plain form field with no filename) → treat as text field.
	if p.FormName() != "" {
		return ""
	}

	// 3. No Content-Disposition at all (common in multipart/related).
	//    Use Content-ID if available, otherwise generate a name.
	if cid := p.Header.Get("Content-Id"); cid != "" {
		// Strip angle brackets: <foo@bar> → foo@bar
		cid = strings.Trim(cid, "<> ")
		if cid != "" {
			return cid
		}
	}

	// 4. Derive extension from the part's own Content-Type.
	pct := p.Header.Get("Content-Type")
	ext := ""
	if pct != "" {
		mt, _, _ := mime.ParseMediaType(pct)
		switch {
		case strings.HasPrefix(mt, "text/html"):
			ext = ".html"
		case strings.HasPrefix(mt, "text/xml"), strings.HasPrefix(mt, "application/xml"):
			ext = ".xml"
		case strings.HasPrefix(mt, "text/"):
			ext = ".txt"
		case strings.HasPrefix(mt, "image/jpeg"):
			ext = ".jpg"
		case strings.HasPrefix(mt, "image/png"):
			ext = ".png"
		case strings.HasPrefix(mt, "application/pdf"):
			ext = ".pdf"
		case strings.HasPrefix(mt, "application/octet-stream"):
			ext = ".bin"
		default:
			ext = ".bin"
		}
	}

	// If the part content-type is purely text/plain with no indicators
	// of being a file, treat it as a text field (return "").
	if pct != "" {
		mt, _, _ := mime.ParseMediaType(pct)
		if mt == "text/plain" {
			return ""
		}
	}

	// For anything else (non-text parts with no name), generate one.
	if ext == "" {
		ext = ".bin"
	}
	return fmt.Sprintf("part-%d%s", partNum, ext)
}

// ── ICAP chunked-body reader ────────────────────────────────────
//
// Implements io.Reader over ICAP/HTTP chunked transfer encoding.

type chunkedReader struct {
	r    *bufio.Reader
	left int
	done bool
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.done {
		return 0, io.EOF
	}
	for cr.left == 0 {
		line, err := cr.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		hexStr := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if hexStr == "" {
			continue
		}
		sz, err := strconv.ParseInt(hexStr, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("bad chunk size: %q", hexStr)
		}
		if sz == 0 {
			cr.r.ReadString('\n')
			cr.done = true
			return 0, io.EOF
		}
		cr.left = int(sz)
	}
	if len(p) > cr.left {
		p = p[:cr.left]
	}
	n, err := cr.r.Read(p)
	cr.left -= n
	if cr.left == 0 {
		cr.r.ReadString('\n')
	}
	return n, err
}

// ── ICAP response helpers ───────────────────────────────────────

func (s *icapServer) send204(bw *bufio.Writer) {
	fmt.Fprint(bw, "ICAP/1.0 204 No Content\r\nISTag: \"uploadscan\"\r\n\r\n")
}

func (s *icapServer) send500(bw *bufio.Writer) {
	fmt.Fprint(bw, "ICAP/1.0 500 Server Error\r\nISTag: \"uploadscan\"\r\n\r\n")
}

func (s *icapServer) sendBlock(bw *bufio.Writer, threat string) {
	page := []byte(strings.ReplaceAll(
		strings.ReplaceAll(s.blockPage, "%VVN%", threat),
		"%huo%", ""))
	rh := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n", len(page))
	fmt.Fprintf(bw,
		"ICAP/1.0 200 OK\r\n"+
			"ISTag: \"uploadscan\"\r\n"+
			"Encapsulated: res-hdr=0, res-body=%d\r\n"+
			"\r\n", len(rh))
	bw.WriteString(rh)
	fmt.Fprintf(bw, "%x\r\n", len(page))
	bw.Write(page)
	bw.WriteString("\r\n0\r\n\r\n")
}

// ── Parsing helpers ─────────────────────────────────────────────

func parseEnc(s string) map[string]int {
	m := make(map[string]int, 4)
	for _, seg := range strings.Split(s, ",") {
		seg = strings.TrimSpace(seg)
		if i := strings.IndexByte(seg, '='); i > 0 {
			if v, err := strconv.Atoi(strings.TrimSpace(seg[i+1:])); err == nil {
				m[strings.TrimSpace(seg[:i])] = v
			}
		}
	}
	return m
}

func hdrVal(hdrs, name string) string {
	lo := strings.ToLower(name)
	for _, line := range strings.Split(hdrs, "\r\n") {
		if i := strings.IndexByte(line, ':'); i > 0 {
			if strings.ToLower(strings.TrimSpace(line[:i])) == lo {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func inferFilename(httpHdr, fallback string) string {
	cd := hdrVal(httpHdr, "content-disposition")
	if cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := params["filename"]; fn != "" {
				return fn
			}
		}
	}
	if idx := strings.Index(httpHdr, " "); idx > 0 {
		rest := httpHdr[idx+1:]
		if sp := strings.Index(rest, " "); sp > 0 {
			path := rest[:sp]
			if last := strings.LastIndex(path, "/"); last >= 0 && last < len(path)-1 {
				return path[last+1:]
			}
		}
	}
	return fallback
}

func (s *icapServer) dbg(format string, args ...any) {
	if s.debug {
		log.Printf("[icap-debug] "+format, args...)
	}
}
