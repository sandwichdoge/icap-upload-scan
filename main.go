// main.go — uploadscan: unified ICAP REQMOD upload scanner.
//
// Merges ClamAV virus scanning and YARA-based DLP into a single ICAP
// service. Each uploaded file is buffered once and passed through an
// ordered pipeline of scanners. The first scanner to flag a threat
// short-circuits the pipeline and returns a 403 block page.
//
// Build:
//   apt install libyara-dev pkg-config
//   CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o uploadscan .
//
// Usage:
//   uploadscan \
//     -port 1380 \
//     -clamd-socket /run/clamav/clamd.ctl \
//     -rules-dir /etc/dlpscan/rules \
//     -log /var/log/uploadscan/uploadscan.log
//
// Squid config (single service replaces the chain):
//   icap_service icap_uploadscan reqmod_precache bypass=off \
//       icap://127.0.0.1:1380
//   adaptation_access icap_uploadscan allow uploads
//
// Signals:
//   SIGHUP  — hot-reload YARA rules from disk
//   SIGINT  — graceful shutdown
//   SIGTERM — graceful shutdown

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// ── flags ───────────────────────────────────────────────────────

var (
	fPort    = flag.Int("port", 1380, "ICAP listen port")
	fClamd   = flag.String("clamd-socket", "/run/clamav/clamd.ctl", "clamd Unix socket path")
	fRules   = flag.String("rules-dir", "/etc/dlpscan/rules", "YARA .yar rules directory")
	fTpl     = flag.String("template", "", "block-page HTML template (%VVN% = threat name)")
	fLog     = flag.String("log", "/var/log/uploadscan/uploadscan.log", "log file path")
	fMaxMB   = flag.Int("max-body-mb", 30, "max total body size in MB")
	fMaxPart = flag.Int("max-part-mb", 15, "max size per multipart part in MB")
	fConns   = flag.Int("max-conns", 64, "max concurrent scans (connections may exceed this)")
	fDebug   = flag.Bool("debug", false, "enable verbose debug logging")

	// Scanner toggles — allow disabling either engine without recompiling.
	fNoClamAV = flag.Bool("no-clamav", false, "disable ClamAV scanning")
	fNoDLP    = flag.Bool("no-dlp", false, "disable YARA DLP scanning")

	fClamdPool = flag.Int("clamd-pool", 16, "max idle clamd connections in pool")
)

func main() {
	flag.Parse()

	// ── Logging ──
	if *fLog != "" {
		os.MkdirAll(filepath.Dir(*fLog), 0755)
		lf, err := os.OpenFile(*fLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer lf.Close()
		log.SetOutput(lf)
	}

	// ── Block page ──
	blockPage := `<html><body><h1>Upload Blocked</h1><p>%VVN%</p></body></html>`
	if *fTpl != "" {
		if b, err := os.ReadFile(*fTpl); err == nil {
			blockPage = string(b)
		}
	}

	// ── Build scanner pipeline ──
	pipe := newPipeline()

	// ClamAV runs first — fast binary signature check before the more
	// expensive YARA + OOXML analysis.
	var dlpScanner *DLPScanner
	if !*fNoClamAV {
		pipe.register(&ClamAVScanner{
			Socket:   *fClamd,
			PoolSize: *fClamdPool,
		})
	}
	if !*fNoDLP {
		dlpScanner = &DLPScanner{
			RulesDir: *fRules,
			Debug:    *fDebug,
		}
		pipe.register(dlpScanner)
	}

	if len(pipe.scanners) == 0 {
		log.Fatal("FATAL: all scanners disabled — nothing to do")
	}

	if err := pipe.initAll(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer pipe.closeAll()

	// ── ICAP server ──
	srv := &icapServer{
		pipe:      pipe,
		blockPage: blockPage,
		maxBody:   int64(*fMaxMB) << 20,
		maxPart:   int64(*fMaxPart) << 20,
		maxConns:  *fConns,
		sem:       make(chan struct{}, *fConns),
		debug:     *fDebug,
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *fPort))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("uploadscan on :%d — pipeline: [%s] (max %d conns)",
		*fPort, strings.Join(pipe.names(), " → "), *fConns)
	fmt.Printf("uploadscan listening on 127.0.0.1:%d\n", *fPort)

	// ── Signal handling ──
	// SIGHUP  = hot-reload YARA rules
	// SIGINT/SIGTERM = graceful shutdown
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				if dlpScanner != nil {
					dlpScanner.ReloadRules()
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("shutting down on %s", sig)
				ln.Close()
				return
			}
		}
	}()

	// ── Accept loop ──
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}
		go srv.handleConn(c)
	}
}
