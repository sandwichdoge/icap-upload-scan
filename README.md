# icap-upload-scan

An ICAP/1.0 REQMOD service that scans HTTP file uploads for threats. It integrates two scanning engines in a pipeline:

1. **ClamAV** — binary signature-based virus detection (fast)
2. **YARA DLP** — pattern/regex-based content inspection for data loss prevention (deep)

The service is designed to sit between Squid and the origin server. Squid sends each upload request via ICAP; the service buffers the body, scans it, and returns either `204 No Modification` (clean) or a `403 Forbidden` block page (threat found).

---

## Architecture

```
Client → Squid (REQMOD) → icap-upload-scan → ClamAV socket
                                           → YARA rules (in-process)
```

- **Stateless**: no database, no disk I/O beyond logging
- **All data in memory**: upload bodies are buffered in RAM, never written to disk
- **Pipeline**: ClamAV runs first (fast); YARA only runs if ClamAV is clean
- **Short-circuit**: the first scanner to find a threat returns immediately

---

## Build

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y automake libtool make gcc pkg-config libssl-dev libjansson-dev libmagic-dev
```

### 2. Build YARA 4.5.2 from source (static lib required)

```bash
git clone --depth 1 --branch v4.5.2 https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure --disable-shared --enable-static --without-crypto
make -j$(nproc)
sudo make install
sudo ldconfig
```

### 3. Verify pkg-config sees the static lib

```bash
pkg-config --static --libs yara
```

### 4. Build

```bash
make
```

Produces a statically-linked `uploadscan` binary with no runtime library dependencies.

> **CGO required**: `CGO_ENABLED=1` is set by the Makefile. The Go toolchain must be able to compile C code.

---

## Deployment

### File layout

| Path | Description |
|------|-------------|
| `/opt/uploadscan/uploadscan` | Binary |
| `/etc/dlpscan/rules/` | Default YARA rules directory (`.yar` files) |
| `/var/lib/uploadscan/rules-<name>/` | Per-instance rule directories (by convention) |
| `/var/log/uploadscan/` | Log directory (service must have read and write access) |
| `/run/clamav/clamd.ctl` | Default clamd Unix socket path |

### Systemd

Install the unit file and enable the service:

```bash
cp uploadscan-hr.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now uploadscan-hr
```

The included `uploadscan-hr.service` is an example for an HR-profile instance running on port `1391`. Copy and adapt it for each logical profile needed.

**Key systemd behaviors**:
- Runs as user `c-icap` — ensure the binary and rule directories are readable by this user
- `ExecStartPre` creates `/var/log/uploadscan` and chowns it to `c-icap`
- `ExecReload=/bin/kill -HUP $MAINPID` triggers a live YARA rule reload (no restart needed)
- `Restart=on-failure` with `RestartSec=5` — the service restarts automatically on crash

### Multiple instances

Run one process per logical scanning profile (different YARA rule sets, different ports). Each instance is an independent binary with its own flags. Example:

```
uploadscan-hr.service    → port 1391, rules /var/lib/uploadscan/rules-hr/
uploadscan-finance.service  → port 1392, rules /var/lib/uploadscan/rules-finance/
```

### Squid integration

#### Architecture: two-tier global + per-department chains

The live `squid.conf` uses a **global baseline + per-department overlay** pattern. Every request passes through a shared global scanner first; department-specific scanners run second within a chain. This lets you enforce organisation-wide rules centrally while adding stricter per-department YARA profiles on top.

```
                         ┌─────────────────────────────────┐
POST (HR subnet)         │  chain_upload_hr                │
─────────────────────>   │  icap_upload_global (1380) →    │
                         │  icap_uploadscan_hr  (1381)     │
                         └─────────────────────────────────┘

POST (other dept, future)
─────────────────────>   icap_upload_global (1380) only
```

`bypass=off` is set on every service and chain. If any ICAP service is unreachable, Squid refuses the upload — **fail-closed** across the board.

#### adaptation_access evaluation model

Squid's `adaptation_access` rules are processed **per service/chain**, in declaration order, first match wins. Each service builds its own virtual ACL from the lines that name it:

| Service/Chain | Effective access list |
|---|---|
| `icap_upload_global` | deny GET/HEAD/OPTIONS → deny dept_hr → allow all |
| `chain_upload_hr` | deny GET/HEAD/OPTIONS → allow dept_hr → deny all |

Squid evaluates every service/chain independently for each request, then applies all that returned `allow`.

#### Request routing trace

**HR subnet POST (10.8.70.0/24):**

1. `http_access allow dept_hr` → request admitted.
2. `icap_upload_global` ACL: `deny get_request` — no match (POST) → `deny dept_hr` — **match → standalone global skipped**.
3. `chain_upload_hr` ACL: `deny get_request` — no match → `allow dept_hr` — **match → chain applied**.
4. Chain runs in order:
   - `icap_upload_global` (1380) scans. If it blocks → Squid returns 403, chain stops.
   - `icap_uploadscan_hr` (1381) scans. If it blocks → Squid returns 403.
   - Both pass → 204, request forwarded to origin.

**HR subnet GET:**

1. `http_access allow dept_hr` → admitted.
2. Both `icap_upload_global` and `chain_upload_hr` ACLs hit `deny get_request` first → neither ICAP service is consulted. Request goes straight to origin.

**Non-department traffic:**

1. Hits `http_access deny all` → blocked at Squid before ICAP is ever consulted.
2. The global fallback `adaptation_access icap_upload_global allow all` is **currently dead code** — it will activate automatically when a future department's include file adds an `http_access allow dept_X` rule without pairing it with a chain that excludes the global.

#### Adding a new department

```
# In /etc/squid/departments/finance.conf (or inline):

acl dept_finance src 10.8.80.0/24
http_access allow dept_finance

icap_service icap_uploadscan_finance reqmod_precache bypass=off \
    icap://127.0.0.1:1382/uploadscan max-conn=32 on-overload=wait

adaptation_service_chain chain_upload_finance icap_upload_global icap_uploadscan_finance

adaptation_access chain_upload_finance deny get_request
adaptation_access chain_upload_finance allow dept_finance
adaptation_access chain_upload_finance deny all

adaptation_access icap_upload_global deny dept_finance   # exclude from standalone global
```

The corresponding `uploadscan-finance.service` must listen on the port referenced here (1382).

#### Port alignment requirement

**Critical**: the port in `icap_service` must exactly match the `-port` flag of the running `uploadscan` instance. A mismatch causes `on-overload=wait` to stall all uploads for that department until the connection times out.

> **Current discrepancy**: `uploadscan-hr.service` in this repo declares `-port 1391`, but `squid.conf` points `icap_uploadscan_hr` at port `1381`. Verify which port the service is actually bound to (`ss -tlnp | grep uploadscan`) and align the two.

#### max-conn alignment

Squid's `max-conn=N` and the ICAP service's `-max-conns N` are independent knobs:

- Squid stops opening new connections to the ICAP service once it has `max-conn` in-flight.
- The ICAP service queues connections that exceed its `-max-conns` semaphore (they wait, they do not fail).

If Squid's `max-conn` exceeds the ICAP service's `-max-conns`, surplus connections will sit idle inside the ICAP service consuming goroutines. Keep them equal or set Squid's `max-conn` slightly below `-max-conns`.

#### Security observations

| Finding | Risk | Notes |
|---------|------|-------|
| Department uploadscan missing `-clamd-socket` falls back to global clamd | **High** | Both chain members would hit identical signatures — ClamAV runs twice with zero added coverage. Each department service **must** set `-clamd-socket` to its own clamd socket. See [Per-department custom signatures](#per-department-custom-signatures). |
| `safe_domain` ACL exempts Google/Microsoft/CDNs from **response** scanning | Medium | Malware hosted on a compromised jsdelivr, unpkg, gstatic, etc. page would bypass AV on download. Deliberate performance tradeoff — document it as accepted risk. |
| `#http_access deny dept_hr exe_ext` is commented out | Low | `.exe` files from HR are not blocked by policy; they are still scanned by ClamAV/YARA. A zero-day or packed EXE could pass. Re-enable or compensate with a YARA rule. |
| `icap_preview_enable` is commented out | Negligible | The ICAP service handles preview correctly (buffers and sends `100 Continue`). Enabling preview would reduce Squid-side buffering for large uploads but has no impact on scan coverage. |
| `icap_resp_global max-conn=400` | Operational | If the response scanner can't sustain 400 concurrent connections, `on-overload=wait` will cause user-visible latency. Tune to match the scanner's actual capacity. |
| Global fallback (`allow all`) is live for response scanning | Low | Any department added via include that has `http_access allow` but no chain will have its responses scanned only by the global scanner and its downloads scanned without a department-specific YARA overlay. Intentional but easy to miss when templating new departments. |

---

## Configuration

All configuration is via command-line flags. There are no config files or environment variables.

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `1380` | TCP port to listen on |
| `-clamd-socket` | `/run/clamav/clamd.ctl` | Path to clamd Unix domain socket |
| `-rules-dir` | `/etc/dlpscan/rules` | Directory containing `.yar` YARA rule files |
| `-template` | *(empty)* | Path to block-page HTML template. `%VVN%` is replaced with the threat name. If empty, a plain-text 403 response is sent. |
| `-log` | `/var/log/uploadscan/uploadscan.log` | Log file path. Parent directory is created automatically. |
| `-max-body-mb` | `30` | Maximum total HTTP body size accepted (MB). Larger bodies return 400. |
| `-max-part-mb` | `15` | Maximum size per multipart part (MB). Parts exceeding this are skipped. |
| `-max-conns` | `64` | Maximum concurrent scans. Excess connections wait (soft semaphore). |
| `-clamd-pool` | `16` | Maximum idle clamd connections kept in the pool. |
| `-debug` | `false` | Enable verbose per-request logging. Do not use in production under load. |
| `-no-clamav` | `false` | Disable ClamAV scanning entirely. |
| `-no-dlp` | `false` | Disable YARA DLP scanning entirely. |

---

## YARA Rules

Rules are loaded from `*.yar` files in the directory specified by `-rules-dir`.

- Each file is compiled as a separate namespace. The namespace name is the filename without extension (e.g., `pci_cards.yar` → namespace `pci_cards`).
- All files must be valid at startup, or the service will refuse to start.
- Match results are reported as `<namespace>.<rule_name>` (e.g., `pci_cards.AMEX_PATTERN`).

### Hot-reload

Send `SIGHUP` to reload rules without restarting:

```bash
systemctl reload uploadscan-hr
# or directly:
kill -HUP $(pidof uploadscan)
```

**Behavior during reload**:
- New rules are compiled first. If compilation fails, the old rules remain active and the error is logged — the service keeps running.
- In-flight scans complete with the old rules. New scans use the new rules immediately after the atomic swap.

---

## ClamAV

The service connects to `clamd` over a Unix socket using the `INSTREAM` protocol.

### Connection pool

- A bounded pool (size `-clamd-pool`, default 16) reuses connections.
- Before reuse, each connection is validated with a `PING`/`PONG` exchange (2 s deadline). Stale connections are discarded and a fresh connection is dialed.
- If the pool is empty, a new connection is dialed with a 5 s timeout.
- A failed connection is never returned to the pool.

### Startup requirement

If ClamAV is enabled (default) and the clamd socket is unreachable at startup, **the service will not start**. Ensure `clamav-daemon` is running before starting `uploadscan`.

```bash
systemctl status clamav-daemon
```

### Per-department custom signatures

Each department already runs its own `clamd` instance — the same one that backs its RESPMOD response scanner (e.g. `icap_resp_hr` on port 1345 uses `clamd-hr`). That instance has its own `DatabaseDirectory` where department-specific signature files are managed independently of the global daemon.

To make the upload scanner use the department clamd, set `-clamd-socket` in the department service unit:

```ini
-clamd-socket /run/clamav/clamd-hr.ctl
```

Without this flag the upload scanner falls back to the global `/run/clamav/clamd.ctl`, meaning ClamAV runs twice in the chain with identical signatures — wasted CPU, no added coverage.

**ClamAV custom signature formats** (drop files into the department's `DatabaseDirectory`; clamd picks them up on reload):

| Extension | Format | Use case |
|-----------|--------|----------|
| `.ndb` | Extended body-based patterns (hex or regex) | Custom malware patterns |
| `.ldb` | Logical signatures (AND/OR of conditions) | Multi-condition detection |
| `.hdb` / `.hsb` | MD5/SHA hash signatures | Block specific known-bad files by hash |
| `.yar` / `.yara` | YARA rules (ClamAV built-in) | Redundant with this service's YARA engine — prefer `.ndb`/`.ldb` |

After adding or changing signature files, reload the department clamd:

```bash
systemctl reload clamav-daemon-hr   # SIGHUP — no connection drop
```

---

## Scan Pipeline

For each uploaded file or multipart part:

1. **Raw bytes** — scanned by ClamAV (whole body streamed to clamd)
2. **Raw bytes** — scanned by YARA (in-process)
3. **Archive extraction** — if the file is a ZIP or OOXML (`.docx`, `.xlsx`, `.pptx`, etc.), each entry is extracted and scanned:
   - XML files: tags stripped, entities decoded, text scanned
   - Binary files: scanned raw
   - Nested ZIPs: recursed up to **5 levels** deep
4. **Encoded data** — YARA scans decoded variants:
   - Base64 (standard and URL-safe) — if decoded result is a ZIP, it is also extracted and scanned
   - Hex-encoded data
   - URL-encoded data

Any positive match short-circuits the pipeline and returns immediately.

### Multipart uploads

For `multipart/form-data` bodies:
- **File fields** (with `filename` in `Content-Disposition`): buffered and scanned individually.
- **Text fields** (no filename): accumulated and scanned together at the end of the request.
- Base64 `Content-Transfer-Encoding` parts are decoded before scanning.

### Memory limits

| Limit | Default | Flag |
|-------|---------|------|
| Total body | 30 MB | `-max-body-mb` |
| Per multipart part | 15 MB | `-max-part-mb` |
| Per ZIP entry (uncompressed) | 50 MB | hard-coded |
| Total ZIP decompression budget | 200 MB | hard-coded |

Bodies exceeding `-max-body-mb` are rejected before scanning. Parts exceeding `-max-part-mb` are skipped (not scanned, not blocked).

---

## Timeouts

| Timeout | Value | Description |
|---------|-------|-------------|
| ICAP connection idle | 60 s | Keep-alive connections closed after 60 s with no new request |
| ICAP request deadline | 300 s | Total time allowed per request (read + scan + write) |
| ClamAV scan | 120 s | Per-file streaming timeout to clamd |
| YARA scan | 30 s | Per-buffer YARA scan timeout |
| clamd dial | 5 s | New connection dial timeout |
| clamd PING validation | 2 s | Stale-connection check timeout |

---

## ICAP Protocol Behavior

- **REQMOD only** — RESPMOD and OPTIONS (other than negotiation) are not processed.
- **Allow: 204** advertised — Squid will use `204 No Modification` for clean content instead of echoing the full request back.
- **Max-Connections** header reflects the `-max-conns` flag value.
- **ISTag**: `"uploadscan-1"` — static; update in source if cache invalidation is needed after a rule change that should not be served from cache.
- **Preview support**: Preview bytes are buffered, `100 Continue` is sent to the client, and the preview bytes are prepended to the rest of the body for scanning.

### Response codes

| Condition | ICAP Response |
|-----------|--------------|
| Content is clean | `204 No Modification` |
| Threat found | `200 OK` + HTTP `403 Forbidden` body (block page) |
| Read/body error | `204 No Modification` (fail-open for read errors) |
| Scan engine error | `500 Server Error` |
| No encapsulated body | `204 No Modification` |

> **Fail-open on read errors**: If the request body cannot be fully read (e.g., client disconnects mid-upload), the service returns 204 (allow) rather than 500. This is intentional to avoid blocking legitimate uploads due to network hiccups.

---

## Logging

Logs are written to the path specified by `-log`. The directory is created automatically on startup.

Key log events:
- `"dlp: loaded N rule file(s) from <dir>"` — YARA startup summary
- `"dlp: reloaded rules"` / `"dlp: reload failed: ..."` — SIGHUP result
- `"clamav: <threat>"` or `"dlp: <namespace>.<rule>"` — threat found
- `"scan error: ..."` — engine-level errors
- Debug mode (`-debug`): logs request URL, content type, part names, scan timing per request

Logs are plain text, not structured JSON. For log aggregation, consider wrapping with `systemd-journald` or forwarding via syslog.

---

## Operational Notes

- **The service is fail-closed for ClamAV at startup** but fail-open for per-request read errors (see Response codes above). If strict fail-closed behavior is required for read errors, set `bypass=off` in Squid and configure Squid to block when the ICAP service returns 500.
- **YARA rules must be present at startup**. An empty rules directory is valid (zero rules loaded), but a directory with malformed `.yar` files will prevent the service from starting.
- **No graceful drain on SIGTERM** beyond closing the listener. In-flight connections are terminated. For zero-downtime restarts, let Squid retry (configure `max-conn` and retry logic in Squid).
- **`-debug` flag is expensive**: it logs per-part details for every request. Use only for troubleshooting specific issues.
- **ClamAV signature updates**: clamd handles these independently. The ICAP service does not need to be restarted when ClamAV signatures are updated — the connection pool will pick up the updated engine automatically.
