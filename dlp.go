// dlp.go — DLP scanning engine with YARA rules.
//
// Implements the Scanner interface. Scans content against compiled YARA
// rules with three layers of analysis:
//
//   1. Raw bytes — catches binary YARA patterns in any file type
//   2. OOXML extraction — unzips .docx/.xlsx/.pptx, strips XML tags,
//      and scans plaintext + embedded media individually
//   3. Encoding detection — decodes base64, hex, and URL-encoded
//      payloads and re-scans the decoded content
//
// Rules are compiled at Init() from .yar files in a configurable
// directory. SIGHUP triggers a hot-reload (old rules remain active
// if the new set fails to compile).

package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

// DLPScanner applies YARA DLP rules to content.
type DLPScanner struct {
	RulesDir string // directory containing .yar files
	Debug    bool   // verbose per-scan logging

	rules      *yara.Rules
	mu         sync.RWMutex
	generation uint64    // incremented on rule reload; scanners with stale gen are discarded
	scanPool   sync.Pool // pool of *pooledScanner
}

// pooledScanner pairs a YARA scanner with the rule generation it was
// created from. On checkout, if the generation doesn't match the
// current one, the scanner is destroyed and a fresh one is created.
type pooledScanner struct {
	scanner *yara.Scanner
	gen     uint64
}

func (d *DLPScanner) Name() string { return "dlp" }

func (d *DLPScanner) Init() error {
	rules, count, err := d.loadRules(d.RulesDir)
	if err != nil {
		return err
	}
	d.rules = rules
	d.generation = 1
	log.Printf("dlp: loaded %d rule file(s) from %s", count, d.RulesDir)
	return nil
}

func (d *DLPScanner) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rules != nil {
		d.rules.Destroy()
		d.rules = nil
	}
}

// ReloadRules hot-reloads YARA rules from disk. Safe for concurrent
// scans — the old ruleset stays active until the new one is ready.
// Called from the SIGHUP handler.
func (d *DLPScanner) ReloadRules() {
	log.Printf("dlp: reloading YARA rules from %s", d.RulesDir)
	rules, count, err := d.loadRules(d.RulesDir)
	if err != nil {
		log.Printf("ERROR: dlp rule reload failed: %v (keeping previous rules)", err)
		return
	}
	d.mu.Lock()
	old := d.rules
	d.rules = rules
	d.generation++ // invalidates all pooled scanners from previous rules
	d.mu.Unlock()
	if old != nil {
		old.Destroy()
	}
	log.Printf("dlp: loaded %d rule file(s) successfully", count)
}

// ScanBytes is the Scanner interface entry point. Orchestrates raw scan,
// OOXML extraction, and encoding detection.
func (d *DLPScanner) ScanBytes(data []byte, filename, clientIP string) (string, error) {
	return d.scanFile(data, filename, clientIP)
}

// ── YARA rule management ────────────────────────────────────────

func (d *DLPScanner) loadRules(dir string) (*yara.Rules, int, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, 0, fmt.Errorf("yara compiler init: %w", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil {
		return nil, 0, fmt.Errorf("glob rules dir: %w", err)
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no .yar files found in %s", dir)
	}

	count := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", f, err)
		}
		ns := strings.TrimSuffix(filepath.Base(f), ".yar")
		if err := compiler.AddString(string(raw), ns); err != nil {
			return nil, 0, fmt.Errorf("compile %s: %w", f, err)
		}
		count++
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, 0, fmt.Errorf("finalise rules: %w", err)
	}
	return rules, count, nil
}

// ── YARA scanning ───────────────────────────────────────────────

func (d *DLPScanner) scanData(data []byte, label string) string {
	if len(data) == 0 {
		return ""
	}

	d.mu.RLock()
	rules := d.rules
	gen := d.generation
	d.mu.RUnlock()

	if rules == nil {
		return ""
	}

	// Try to get a pooled scanner. If the generation doesn't match
	// (rules were reloaded), destroy it and create a fresh one.
	var sc *yara.Scanner
	if ps, ok := d.scanPool.Get().(*pooledScanner); ok && ps != nil {
		if ps.gen == gen {
			sc = ps.scanner
		} else {
			// Stale scanner from previous rules — discard.
			ps.scanner.Destroy()
		}
	}

	if sc == nil {
		var err error
		sc, err = yara.NewScanner(rules)
		if err != nil {
			log.Printf("dlp: scanner init error: %v", err)
			return ""
		}
		sc.SetTimeout(30 * time.Second)
	}

	var matches yara.MatchRules
	if err := sc.SetCallback(&matches).ScanMem(data); err != nil {
		log.Printf("dlp: scan error [%s]: %v", label, err)
		sc.Destroy() // don't return a potentially broken scanner
		return ""
	}

	// Return scanner to pool for reuse.
	d.scanPool.Put(&pooledScanner{scanner: sc, gen: gen})

	if len(matches) > 0 {
		m := matches[0]
		result := m.Namespace + "." + m.Rule
		d.dbg("scanData(%s): %d bytes → MATCH: %s", label, len(data), result)
		return result
	}
	d.dbg("scanData(%s): %d bytes → clean", label, len(data))
	return ""
}

// ── Composite file scanner ──────────────────────────────────────

func (d *DLPScanner) scanFile(data []byte, filename, clientIP string) (string, error) {
	d.dbg("scanFile: %s (%d bytes) magic=%x", filename, len(data), head(data, 4))

	// 1. Raw bytes
	if threat := d.scanData(data, "raw:"+filename); threat != "" {
		log.Printf("dlp: FOUND %s in raw bytes of %s from %s", threat, filename, clientIP)
		return threat, nil
	}

	// 2. OOXML extraction — cheap magic-byte check, then short-circuit
	//    scan of each ZIP entry. Runs before encoding detection to avoid
	//    expensive regex passes over binary ZIP data.
	if isOOXML(data) {
		d.dbg("scanFile: %s is OOXML/ZIP, extracting", filename)
		threat, err := d.scanOOXML(data, filename, clientIP)
		if err != nil {
			log.Printf("dlp: ooxml scan warning [%s]: %v", filename, err)
			return "", nil
		}
		if threat != "" {
			return threat, nil
		}
	}

	// 3. Encoding detection — base64, hex, URL-encoded payloads.
	if threat := d.scanDecoded(data, filename, clientIP); threat != "" {
		return threat, nil
	}

	return "", nil
}

// ── OOXML scanning (short-circuit) ──────────────────────────────
//
// scanOOXML opens the ZIP, iterates entries, and scans each XML/media
// entry as it is decompressed. Returns immediately on the first threat
// without decompressing remaining entries.

func (d *DLPScanner) scanOOXML(data []byte, filename, clientIP string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("zip open: %w", err)
	}

	for _, f := range zr.File {
		if f.UncompressedSize64 > 50<<20 {
			continue // zip bomb guard
		}

		lower := strings.ToLower(f.Name)

		// ── XML entries: strip tags, decode entities, scan ──
		if strings.HasSuffix(lower, ".xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			raw, err := io.ReadAll(io.LimitReader(rc, 10<<20))
			rc.Close()
			if err != nil {
				continue
			}
			stripped := stripXMLTags(raw)
			decoded := decodeXMLEntities(stripped)

			if threat := d.scanData(decoded, "xml:"+f.Name); threat != "" {
				log.Printf("dlp: FOUND %s in XML entry %s of %s from %s", threat, f.Name, filename, clientIP)
				return threat, nil
			}
		}

		// ── Media/embedded entries: scan raw bytes ──
		if isMediaPath(f.Name) {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			raw, err := io.ReadAll(io.LimitReader(rc, 20<<20))
			rc.Close()
			if err != nil {
				continue
			}

			if threat := d.scanData(raw, f.Name); threat != "" {
				log.Printf("dlp: FOUND %s in %s embedded in %s from %s", threat, f.Name, filename, clientIP)
				return threat, nil
			}
		}
	}

	return "", nil
}

func isOOXML(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04
}

var ooxmlMediaDirs = []string{
	"word/media/", "ppt/media/", "xl/media/",
	"word/embeddings/", "ppt/embeddings/", "xl/embeddings/",
}

func isMediaPath(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range ooxmlMediaDirs {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func stripXMLTags(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data) / 2)
	inTag := false
	for _, b := range data {
		switch {
		case b == '<':
			inTag = true
		case b == '>':
			inTag = false
			out.WriteByte(' ')
		case !inTag:
			out.WriteByte(b)
		}
	}
	return out.Bytes()
}

func decodeXMLEntities(data []byte) []byte {
	if !bytes.ContainsRune(data, '&') {
		return data
	}
	s := string(data)
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&apos;", "'")
	s = strings.ReplaceAll(s, "&#10;", "\n")
	s = strings.ReplaceAll(s, "&#13;", "\r")
	s = strings.ReplaceAll(s, "&#9;", "\t")
	return []byte(s)
}

// ── Encoding detection & decoding ───────────────────────────────

var (
	reBase64Block = regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`)
	reHexBlock    = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[\s:]?){32,}`)
	rePctTriple   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
)

func tryDecodeBase64(data []byte) []byte {
	matches := reBase64Block.FindAll(data, 32)
	if len(matches) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, m := range matches {
		decoded, err := base64.StdEncoding.DecodeString(string(m))
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(string(m))
			if err != nil {
				continue
			}
		}
		buf.Write(decoded)
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

func tryDecodeHex(data []byte) []byte {
	matches := reHexBlock.FindAll(data, 32)
	if len(matches) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, m := range matches {
		clean := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				return r
			}
			return -1
		}, string(m))
		if len(clean)%2 != 0 {
			clean = clean[:len(clean)-1]
		}
		decoded, err := hex.DecodeString(clean)
		if err != nil {
			continue
		}
		buf.Write(decoded)
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

func tryDecodeURL(data []byte) []byte {
	triplets := rePctTriple.FindAll(data, -1)
	if len(triplets) == 0 {
		return nil
	}
	encodedBytes := len(triplets) * 3
	if float64(encodedBytes)/float64(len(data)) < 0.20 {
		return nil
	}
	decoded, err := url.QueryUnescape(string(data))
	if err != nil {
		return nil
	}
	if decoded == string(data) {
		return nil
	}
	return []byte(decoded)
}

func (d *DLPScanner) scanDecoded(data []byte, label, clientIP string) string {
	// Base64
	if decoded := tryDecodeBase64(data); len(decoded) > 0 {
		d.dbg("scanDecoded(%s): base64, decoded %d bytes", label, len(decoded))
		if threat := d.scanData(decoded, "b64:"+label); threat != "" {
			log.Printf("dlp: FOUND %s in base64-decoded content of %s from %s", threat, label, clientIP)
			return threat
		}
		if isOOXML(decoded) {
			threat, err := d.scanOOXML(decoded, "b64:"+label, clientIP)
			if err == nil && threat != "" {
				return threat
			}
		}
	}

	// Hex
	if decoded := tryDecodeHex(data); len(decoded) > 0 {
		d.dbg("scanDecoded(%s): hex, decoded %d bytes", label, len(decoded))
		if threat := d.scanData(decoded, "hex:"+label); threat != "" {
			log.Printf("dlp: FOUND %s in hex-decoded content of %s from %s", threat, label, clientIP)
			return threat
		}
	}

	// URL-encoding
	if decoded := tryDecodeURL(data); len(decoded) > 0 {
		d.dbg("scanDecoded(%s): url-encoded, decoded %d bytes", label, len(decoded))
		if threat := d.scanData(decoded, "url:"+label); threat != "" {
			log.Printf("dlp: FOUND %s in URL-decoded content of %s from %s", threat, label, clientIP)
			return threat
		}
	}

	return ""
}

// ── helpers ─────────────────────────────────────────────────────

func head(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}

func (d *DLPScanner) dbg(format string, args ...any) {
	if d.Debug {
		log.Printf("[dlp-debug] "+format, args...)
	}
}
