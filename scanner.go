// scanner.go — Scanner interface and pipeline execution.
//
// Each scanning engine (ClamAV, DLP, future engines) implements the
// Scanner interface. The pipeline fans out every registered scanner
// against each piece of content in parallel. The first threat detected
// (by pipeline registration order) wins.
//
// Adding a new scanner:
//   1. Create a new file (e.g. watermark.go)
//   2. Implement the Scanner interface
//   3. Register it in main.go's scanner slice

package main

import (
	"fmt"
	"log"
	"sync"
)

// Scanner is the interface every scanning engine must implement.
type Scanner interface {
	// Name returns a short identifier used in log lines and block pages
	// (e.g. "clamav", "dlp").
	Name() string

	// Init performs one-time setup (connect to daemon, compile rules, etc.).
	// Called once at startup before the listener opens.
	Init() error

	// ScanBytes inspects a buffered blob (a file part, accumulated text
	// fields, or a non-multipart body). Returns the threat identifier
	// (non-empty string) if malicious content is found, or "" if clean.
	//
	// Parameters:
	//   data     — full content bytes (already buffered by the ICAP layer)
	//   filename — best-effort filename ("" for text fields, "upload" as fallback)
	//   clientIP — X-Client-IP from ICAP headers (for logging)
	ScanBytes(data []byte, filename string, clientIP string) (threat string, err error)

	// Close releases resources (sockets, YARA rules, etc.).
	// Called once during graceful shutdown.
	Close()
}

// pipeline holds the ordered list of scanners.
// Scanners run in parallel; the lowest-index threat wins (preserves
// registration-order priority).
type pipeline struct {
	scanners []Scanner
}

// newPipeline creates an empty pipeline.
func newPipeline() *pipeline {
	return &pipeline{}
}

// register appends a scanner to the pipeline.
func (p *pipeline) register(s Scanner) {
	p.scanners = append(p.scanners, s)
}

// initAll calls Init on every registered scanner.
// Returns on the first error — partial init is not useful.
func (p *pipeline) initAll() error {
	for _, s := range p.scanners {
		if err := s.Init(); err != nil {
			return fmt.Errorf("scanner %s init: %w", s.Name(), err)
		}
		log.Printf("scanner %s initialised", s.Name())
	}
	return nil
}

// closeAll calls Close on every registered scanner.
func (p *pipeline) closeAll() {
	for _, s := range p.scanners {
		s.Close()
	}
}

// scanResult holds the outcome of a single scanner goroutine.
type scanResult struct {
	name   string
	threat string
	err    error
	idx    int // registration order — lowest wins
}

// scan runs all registered scanners against a single blob in parallel.
// The data slice is read-only during scanning, so sharing it across
// goroutines is safe. The returned threat string is prefixed with the
// scanner name for the block page / log.
//
// When multiple scanners detect a threat, the one registered first
// (lowest index) wins — preserving the same priority semantics as the
// old sequential loop.
func (p *pipeline) scan(data []byte, filename, clientIP string) (string, error) {
	n := len(p.scanners)

	// Fast path — single scanner, no goroutine overhead.
	if n == 1 {
		s := p.scanners[0]
		threat, err := s.ScanBytes(data, filename, clientIP)
		if err != nil {
			return "", fmt.Errorf("%s: %w", s.Name(), err)
		}
		if threat != "" {
			return fmt.Sprintf("[%s] %s", s.Name(), threat), nil
		}
		return "", nil
	}

	// Fan out all scanners in parallel.
	results := make([]scanResult, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i, s := range p.scanners {
		go func(i int, s Scanner) {
			defer wg.Done()
			threat, err := s.ScanBytes(data, filename, clientIP)
			results[i] = scanResult{
				name:   s.Name(),
				threat: threat,
				err:    err,
				idx:    i,
			}
		}(i, s)
	}
	wg.Wait()

	// Collect results in registration order — first threat wins.
	var firstErr error
	for _, r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", r.name, r.err)
		}
		if r.threat != "" {
			return fmt.Sprintf("[%s] %s", r.name, r.threat), nil
		}
	}

	if firstErr != nil {
		return "", firstErr
	}
	return "", nil
}

// names returns the scanner names in pipeline order (for logging).
func (p *pipeline) names() []string {
	out := make([]string, len(p.scanners))
	for i, s := range p.scanners {
		out[i] = s.Name()
	}
	return out
}
