# NetworkMonitor — Architecture

A macOS network monitor: Zeek-style per-protocol logging with per-process
attribution, a storage layer with configurable retention, and (not yet built) a
live dashboard.

This document describes what each layer does and why the boundaries fall where
they do. The reasoning behind individual decisions — including several that were
reversed by measurement — is in [DECISIONS.md](DECISIONS.md).

---

## 1. What makes this different from a Zeek port

macOS exposes a `pktap` pseudo-interface that prefixes every captured packet
with kernel metadata:

```
pid   process name   Mach-O UUID   effective pid   effective name
interface   direction   service class   retransmit flag
```

So every packet arrives already attributed to the process that owns the socket —
and, when a proxy process carries traffic on an application's behalf, to the
application it is really for. This needs root but **no NetworkExtension
entitlement**, which would otherwise require Apple approval.

Everything distinctive follows from that:

| Capability | How pktap enables it |
|---|---|
| "Safari used 2 GB", not "nsurlsessiond used 2 GB" | `pth_epid` names the delegating application |
| Unambiguous hostnames behind a shared CDN address | DNS answers are cached per **requesting pid**, not per address |
| Accurate retransmission marking | `PTH_FLAG_REXMIT` — the kernel already knows |
| Wireshark shows process names in extracted captures | The metadata is written into the savefile |

---

## 2. Layers

```
                      ┌──────────────────────────────┐
                      │  CPktap  (C shim)            │
                      │  struct pktap_header,        │
                      │  Apple's real pcap headers   │
                      └──────────────┬───────────────┘
                                     │
                      ┌──────────────┴───────────────┐
                      │  NMCore                      │
                      │  ByteReader · IPAddress      │
                      │  records · Timestamp · Limits│
                      └──┬────────┬────────┬─────────┘
                         │        │        │
        ┌────────────────┘        │        └─────────────────┐
        │                         │                          │
┌───────┴────────┐    ┌───────────┴──────────┐   ┌───────────┴────────┐
│  NMCapture     │    │  NMFlow              │   │  NMStore           │
│  ROOT ONLY     │    │  L3/L4 parsers       │   │  SQLite wrapper    │
│  pcap handle   │    │  FlowKey/FlowTable   │   │  schema            │
│  PKTAP decode  │    │  TCPStateMachine     │   │  StoreWriter actor │
│  pcap file I/O │    │  FlowEngine          │   │  partition · seal  │
│                │    │  HostnameCache       │   │  retention         │
│                │    │  ReassemblyPool      │   └────────────────────┘
│                │    │  PacketAnalyzer      │
└────────────────┘    └───────────┬──────────┘
                                  │
                      ┌───────────┴──────────┐   ┌────────────────────┐
                      │  NMAnalyzers         │   │  NMSource          │
                      │  DNS · TLS           │   │  RecordSource      │
                      │  JA4/JA3 · X.509     │   │  SyntheticSource   │
                      └──────────────────────┘   └────────────────────┘

                      ┌──────────────────────────────────────────────┐
                      │  NMIPC                                       │
                      │  wire types · LiveRing · DaemonServer        │
                      │  DaemonClient · Authorization                │
                      └──────────────────────────────────────────────┘
```

### The one boundary that is load-bearing

**`NMCapture` must never import `NMFlow` or `NMAnalyzers`.**

It is the only module that holds a root-privileged BPF handle. Keeping it free
of parsers means a later split into a small root capturer plus an unprivileged
analyzer process is a change to `main.swift`, not a rewrite. The two sides are
coupled through exactly one type (`PacketContext`) and one bridging function
(`makeContext` in `Sources/nmcapd/FlowMode.swift`). Keep that seam thin.

Corollaries:

- L3/L4 parsers live in `NMFlow`, not in an analyzer module — building a flow
  key requires them, so putting them above `NMFlow` would be circular.
- The `PacketAnalyzer` protocol is declared in `NMFlow` (the engine calls it)
  while implementations live in `NMAnalyzers`.
- `HostnameCache` is in `NMFlow` under a protocol-neutral name: DNS feeds it
  today, TLS SNI already does, HTTP Host will.

### `RecordSource`: why the stack builds without root

`NMSource` defines a protocol that both a synthetic generator and the real pcap
source conform to. Everything above the packet parser — storage, rollups,
retention, and later IPC and the UI — consumes `RecordSource`, so it can be
built, benchmarked and demonstrated with **no root and no pcap code**.

That is why the storage layer was benchmarked at 50k rows/minute before any UI
existed. Preserve this property.

---

## 3. Data flow

```
  NIC / host stack
        │
        ▼
  ┌─────────────────┐   pcap_set_want_pktap(h, 1)  ← without this you get
  │ CaptureSession  │   pcap_create("pktap,all")      DLT_RAW and no metadata
  └────────┬────────┘
           │  one memcpy, nothing else on this thread
           ▼
  ┌─────────────────┐
  │ PktapDecoder    │   fields read by the wire's pth_length, never sizeof
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ PacketContext   │   ← the entire NMCapture ↔ NMFlow interface
  └────────┬────────┘
           ▼
  ┌─────────────────────────────────────────────────────────┐
  │ FlowEngine                                              │
  │   IPParser → TransportParser → FlowKey                  │
  │   FlowTable (arena + timing wheel + flood shedding)     │
  │   TCPStateMachine  (conn_state, history)                │
  │   ReassemblyPool   (TCP only, analyzer-attached flows)  │
  │   AnalyzerRegistry → DNSAnalyzer / TLSAnalyzer          │
  │   HostnameCache    (address → name, keyed by pid)       │
  └────────┬────────────────────────────────────────────────┘
           │  ConnRecord · DNSRecord · SSLRecord
           ▼
  ┌─────────────────┐
  │ StoreWriter     │   batched transactions, 4 Hz
  │   live.db       │   ──rename()──▶ archive/nm-YYYY-MM-DD.db ──seal──▶ read-only
  │   meta.db       │   exec/name/fingerprint dimensions, alerts, catalog
  │   rollup.db     │   what the dashboard reads
  │   pcap.db       │   packet ring index
  └─────────────────┘
```

---

## 4. Capture layer (`NMCapture`)

Opens `pktap,all` through libpcap and decodes the per-packet metadata header.

**The header is a reconstruction.** `net/pktap.h` is not in the macOS SDK, so
`struct nm_pktap_header` is declared by hand in `Sources/CPktap/include/CPktap.h`
with a `_Static_assert` on every field offset. Verified against live kernel
output on macOS 26.6.2.

Key behaviours:

- **PKTAP framing is opt-in.** `pcap_create("pktap,all")` alone activates
  cleanly and returns `DLT_RAW` — bare IP, no metadata, everything appearing to
  work. `pcap_set_want_pktap(h, 1)` is required before activate.
- **Field presence is decided by the wire's `pth_length`,** never `sizeof`.
  Older macOS shipped shorter headers; a 108-byte header must yield `nil` for
  the fields it does not cover rather than reading packet bytes as a UUID.
- **`pth_pid` and `pth_epid` can be `-1`** (no attribution). Never treat that as
  a pid — use `attributedPID` / `effectivePID`.
- **`debug.bpf_maxbufsize` defaults to 512 KB**, about 4 ms of gigabit traffic.
  `CaptureSession.open()` raises it to 16 MB; SIP does not block this.
- The capture thread does one `memcpy` and nothing else. It holds the kernel
  buffer while it runs, so time spent there is drop rate.

`PcapFileWriter` / `PacketReplay` close the loop without root: write a synthetic
capture, read it back through the same decoder a live capture uses, and
cross-check against Apple's `tcpdump` on the same file.

---

## 5. Flow layer (`NMFlow`)

Turns packets into one record per conversation.

### FlowKey

Three non-obvious decisions:

1. **Endpoints are sorted** so both directions hash to the same bucket.
   Without it you get two half-flows and every byte count is halved.
2. **The interface is part of the key.** The same 5-tuple legitimately appears
   on `utun0` and `en0` at once (VPN inner and outer), and twice per packet on
   `lo0`.
3. **The hash is seeded per process.** A fixed, publicly known hash lets an
   attacker craft colliding 5-tuples and degrade the table to a linked list —
   a denial of service costing them almost nothing.

### Orientation

Decided **once**, at flow creation, and read back from the entry. For TCP the
handshake names the initiator unambiguously (a SYN-ACK means the sender is the
responder); otherwise the first packet seen is the best available guess and the
state machine records that it was a guess (`OTH`).

### conn_state

Zeek's full vocabulary, because the distinctions are the diagnostic value:

| State | Meaning |
|---|---|
| `S0` | SYN, no reply — dead host, filtered port, or a scan |
| `S1` | Established, still open |
| `SF` | Completed normally (or, for UDP, both directions seen) |
| `REJ` | Actively refused |
| `RSTO` / `RSTR` | Reset by originator / responder |
| `S2` / `S3` | Half-closed, originator / responder finished |
| `SH` | SYN then FIN, no reply — stealth-scan shape |
| `OTH` | Picked up mid-stream, no handshake seen |

`history` is capped at 64 characters and each letter is emitted at most once per
direction — an unbounded history is a memory-exhaustion vector reachable by
anyone who can send packets.

### Bounds

| Resource | Cap | Behaviour at the limit |
|---|---|---|
| Concurrent flows | 262,144 | Flood mode at 90%, leaves at 70% |
| Reassembly buffers | 4,096 flows × 8 KB/direction | Pool refuses new flows |
| TLS sessions | 4,096 | Analyzer returns `notMine` |
| DNS pending queries | 4,096 | Oldest evicted |
| Hostname cache | 65,536 keys | Expired first, then oldest tenth |

Under flood, **half-open flows are shed first** — a SYN flood is thousands of
them and they carry the least information. Shed flows are **aggregated** into one
record per (process, destination, port, state); emitting them individually would
bury the log under millions of near-identical rows exactly when something
interesting is happening.

### Reassembly

Deliberately minimal: the first K bytes per direction, in order, with an explicit
gap flag. No out-of-order queues.

- Overlaps resolve to **first-seen** bytes, which is what macOS itself does.
  Matching the endpoint's view is what closes the divergence TCP evasion attacks
  exploit.
- A hole **stops buffering** rather than splicing. A spliced stream parses into
  plausible nonsense; stopping visibly is what makes `missed_bytes` mean
  something.
- Sequence comparison is a **signed difference**, never `<`/`>` — numbers wrap
  at 2³² and the naive comparison reads a wrap as a 4 GB gap.

---

## 6. Analyzer layer (`NMAnalyzers`)

Analyzers are **singletons**, not per-flow objects: a per-flow analyzer would
put a heap allocation on flow creation, the path a SYN flood hammers. Per-flow
state lives in the flow entry or in a bounded table the analyzer keys itself.

Dispatch is a flat 65,536-entry table per protocol — one array index, no hashing.
Both ports are consulted, because either end may be the well-known one. A
`notMine` verdict detaches the flow permanently.

### DNS

Produces `dns.log` rows and feeds the hostname cache.

- **Name compression is the most reachable DoS in the project.** The rule that
  closes it is that a pointer must target a **strictly smaller offset**; a jump
  counter alone only bounds how long a cycle runs before producing garbage. Both
  are implemented.
- Reserved label types (`01`, `10`) are rejected, not read as literal lengths.
- Labels are escaped on render — a label may legally contain a dot, so an
  unescaped one lets `a.b` inside one label impersonate two labels.
- **Unanswered queries are reported.** A pairing that only fires on responses
  shows nothing in exactly the case a user is debugging. mDNS is excluded from
  pairing (broadcast, no expected reply).
- CNAME chains resolve back to the name **originally asked for** — caching the
  final CDN edge-node name would be technically true and useless.
- **The parser alone is not a filter for "is this DNS".** Twelve bytes of
  anything form a valid header, so `isPlausiblyDNS` adds structural checks.
  Without them a DNS tunnel or a port scan is logged as name resolution.

### TLS

Produces `ssl.log` rows, SNI, and JA4/JA3 fingerprints.

Three facts the UI must be built around, recorded as facts rather than absences:

- **TLS 1.3 encrypts the Certificate message.** Certificate fields are
  *unavailable*, not unknown — `certsEncrypted` says which. Under 1.2 they are
  plaintext and parsed (via `SecCertificate`; no hand-written DER parser).
- **Under TLS 1.3 the server's ALPN is in `EncryptedExtensions`** and not
  visible. Reporting the client's offer as negotiated would be a guess.
- **ECH means the visible SNI is the public outer name.** `sniIsOuter` is set
  and the name is deliberately *not* asserted as the connection's hostname.

A malformed individual extension is **skipped, not fatal** to the ClientHello.
Discarding the message over one odd entry would throw away the SNI and the
fingerprint — exactly what an attacker wanting to stay unlogged would arrange.
The extension's type is still recorded so the fingerprint reflects it.

JA4 is primary because it sorts the cipher and extension lists before hashing,
surviving the extension shuffling Chrome/BoringSSL do deliberately — the thing
that made JA3 useless for modern browsers. JA3 is kept as a threat-intel join
key. `ja4Raw` is stored because two disagreeing digests tell you nothing about
which field diverged.

### Hostname precedence

`HostnameSource.strength`, highest wins, and a weaker source never overwrites a
stronger one:

```
TLS SNI  >  HTTP Host  >  per-process DNS  >  wildcard DNS  >  reverse PTR
```

SNI outranks the DNS cache because it is what the client literally asked *this*
server for on *this* connection, rather than an inference from an earlier lookup
that may have been another process's.

Enrichment runs at **flow creation**, so the answer reflects what was known when
the connection was made rather than minutes later when the flow closes.

---

## 7. Storage layer (`NMStore`)

### Four databases, four lifetimes

| File | Contents | Lifetime |
|---|---|---|
| `live.db` | today's raw records | rotated daily |
| `archive/nm-YYYY-MM-DD.db` | a sealed day | unlinked at retention |
| `meta.db` | exec/name/fingerprint dimensions, alerts, catalog | outlives every partition |
| `rollup.db` | time-bucketed aggregates | the long history |
| `pcap.db` | packet ring index | independent of the log files |

### Rotation and sealing

Rotation is `rename()` — O(1), no lock, no free space needed. Sealing then:

1. `journal_mode = DELETE`, so the archive has no `-wal`/`-shm` at all
2. builds extra read indices (free — nothing is writing)
3. `VACUUM INTO` a sibling, then swap (compaction without an exclusive lock)
4. `chmod 0640` and records the file in `meta.file_catalog`

A sealed archive is opened with `?mode=ro&immutable=1`, which disables locking
and change detection.

### Retention

Three shapes, cheapest first:

1. Past **every** retention → `unlink()`, without opening the file
2. In the **mixed band** (older than the shortest retention, younger than the
   longest) → opened once in its life to drop the expired tables, then
   incremental-vacuumed. A second pass does no work.
3. Rollups and alerts expire **by row** in their own databases, so the aggregate
   history outlives the raw rows it came from.

Defaults are tiered, not flat, for a measured reason: at 50k rows/minute the
store costs ~19 GB/day, so a flat 30-day raw retention needs ~580 GB and does
not fit a laptop.

```
conn 30d · dns 14d · ssl 30d · payload 7d
rollup minute 2d · hour 90d · day 10y · alerts 365d
pcap ring 20 GB, with a 2 GB free-space floor
```

### Query shapes that matter

All measured (see [DECISIONS.md](DECISIONS.md) for the numbers):

- Pagination is **keyset**, never `OFFSET` — and `OFFSET` is also *incorrect*
  under concurrent inserts, which is the normal state here.
- Domain suffix search compiles to a **range**, never `LIKE` — SQLite will not
  use an index for a `LIKE` prefix under the default case-insensitive collation.
- Addresses are **BLOBs** in native width so CIDR compiles to `BETWEEN`, an index
  range scan. As TEXT the same filter is a full scan.
- The dashboard reads **only** rollup tables.
- Hostnames, SNI and DNS query names share one `meta.name` dimension with the
  reversed spelling stored once; TLS fingerprints are interned in
  `meta.fingerprint`. This cut bytes/row from 257 to 175.

`SQLITE_MAX_ATTACHED` is 10 in this build; `meta`/`rollup`/`pcap` take three,
leaving seven for day files. Queries spanning more must use rollups or merge
per-file in Swift.

---

## 8. IPC layer (`NMIPC`)

Two processes have to talk:

```
NetworkMonitor.app  (logged-in user)  ←──→  nmcapd  (root)
  draws the screen                            captures packets, owns the store
```

### The channel is deliberately not uniform

| Channel | Mechanism | Why |
|---|---|---|
| **Bulk history** (log browser, drill-downs, export) | app opens SQLite **read-only, directly** | proxying a million-row scan costs 5–10× in serialisation, and makes the capture daemon spend CPU on table scans instead of draining the BPF buffer |
| **Live state** (throughput, open connections) | **XPC push**, 1–4 Hz | a flow is written when it **closes**, so every currently-open connection exists nowhere but in the daemon's memory — polling the store returns the recent past and misses the present |
| **Control** (config, retention, rotation) | XPC + Authorization Services | needs authenticated peer identity and a human's approval |
| **Query fallback** | XPC | for users not in the readers group, and while a hot WAL is recovering |

Localhost TCP was rejected for a specific reason: it has **no peer identity**,
so any local process, any sandboxed app, and — via DNS rebinding — any web page
can reach it. A unix socket is better but leaves peer credentials, framing and
reconnection to be hand-rolled, and gives nothing XPC does not.

### LiveRing

The daemon's in-memory view of *now*. Fed at packet rate by a thread that must
never block, so everything in it is bounded:

| | Cap |
|---|---|
| per-second history | 600 s |
| open flows tracked | 2,048 |
| distinct processes | 256 |

Idle seconds are **filled with zeroes rather than skipped** — a chart that
interpolates across a gap implies traffic that did not happen.

Per-process totals are recomputed from open flows plus anything closed inside
the window, never accumulated. Counting only on close makes a machine holding a
few long-lived connections show no traffic at all.

### Authorization

**The daemon decides, never the client.** The client is a separate binary a user
can replace or patch, so a privilege check it performs on itself is decoration.

Authorization Services is used rather than a home-made group check because the
decision is then made by `authd`: a patched client would have to forge authd's
answer, which it cannot reach. The client obtains an `AuthorizationExternalForm`
(raising the standard admin prompt, which only a process with a UI session can
do), and the daemon converts it back and **re-evaluates the right itself**.

A group-membership fallback exists for unsigned development builds and is marked
as strictly weaker — it proves *who* the caller is, not that a human approved
*this action*.

**Peer identity never uses the pid.** Pids are recycled, so a check against one
is a check against whoever holds it now. Identity comes from the code-signing
requirement and the effective uid.

### Client behaviour

Two things that decide whether the tool is kept or uninstalled:

- It **unsubscribes when its window is occluded**. The daemon stops producing
  the moment nobody is listening.
- It **reconnects with capped backoff**. The daemon restarts on upgrade and on
  KeepAlive bounces; an app needing relaunch after each one is broken in
  practice even though each individual failure is "correct".

### Testing without root

`--live` runs the server and a client in one process over an **anonymous
`NSXPCListener`**. Snapshots are genuinely encoded, pushed across the boundary
and decoded, so the wire format, push cadence, subscription lifecycle and
payload size are all exercised. Only the launchd-registered Mach service name is
left uncovered.

## 9. Security model

`nmcapd` runs as root and parses attacker-controlled bytes.

**The single most important fact:** `UnsafeRawBufferPointer`'s bounds check is a
`_debugPrecondition` and is **compiled out under `-O`**. A release build has no
automatic protection on the packet path.

Therefore every read goes through `ByteReader`, which checks explicitly. **No
parser may touch a raw pointer directly** — a lint rule, not a style preference.

| Defence | Where |
|---|---|
| Explicit bounds check on every read | `ByteReader.need`, written `limit - offset >= n` so a wire-supplied length cannot overflow the check |
| Every wire length clamped to captured bytes | all parsers |
| Hard caps on every loop | `Limits` in `Sources/NMCore/Paths.swift` |
| Per-process hash seed | `FlowHashSeed` — defeats algorithmic-complexity DoS |
| Bounded tables everywhere | see §5 |
| X.509 delegated to `SecCertificate` | `CertificateParser` — no hand-written DER parser |
| Fuzzed in release builds | DNS and TLS: random input plus bit-flip mutation of valid messages |

Bit-flip fuzzing matters more than random fuzzing here: random bytes almost never
form a valid header, so they never reach the interesting parsers at all.

---

## 10. Honesty invariants

The product's value depends on not presenting guesses as facts. These look like
complications worth simplifying away unless the reason is written down:

| Invariant | Why |
|---|---|
| `lossEpoch` advances on any capture drop; flows spanning one are marked `captureLossSuspected` | byte counts across a drop are approximate and say so |
| Loopback counted once (kernel taps it twice) | otherwise every localhost byte doubles |
| IP `total_length == 0` falls back to captured length, sets `clamped` | TSO offload makes this normal, not an error |
| Direction calibration refuses to conclude without locally-sourced packets | a confident answer from no evidence is worse than none |
| Hostname lookups record which key matched and flag ambiguity | a coin flip presented as fact is worse than admitting doubt |
| TLS 1.3 certificates reported as *encrypted*, not unknown | "encrypted" is a fact; "unknown" is a shrug |
| ECH outer names not asserted as the destination | blank beats confidently wrong |
| Shed flows aggregated and counted, never silently dropped | visible loss beats invisible loss |

---

## 11. Build and test

**Command Line Tools only — no Xcode, no Homebrew, no third-party dependencies.**

```bash
swift build                      # debug
swift build -c release           # release — use for any benchmark
swift run nmtest                 # the test suite. NOT `swift test`
```

`swift test` does not work: neither XCTest nor swift-testing ships with the
Command Line Tools. Tests are an executable built on `Sources/NMTestKit`.

### Everything below runs without root

```bash
nmcapd --make-fixture /tmp/f.pcap 200   # synthetic pktap capture
nmcapd --replay /tmp/f.pcap             # decode and print pktap fields
nmcapd --flows-file /tmp/f.pcap         # conn.log + DNS + TLS
nmcapd --ingest /tmp/f.pcap [dbdir]     # whole pipeline into a real database
nmcapd --live [secs]                    # live pipeline through the real XPC path
nmcapd --store-info <dbdir> [--run-retention]
nmcapd --bench-flows 4000 2000000       # flow engine throughput + flood bound
nmcapd --bench 50000 600                # storage: rows/s, bytes/row, query plans
nmcapd --layout                         # compiled-in struct layout
tcpdump -r /tmp/f.pcap -k -n            # Apple's decoder on the same file
```

### These need root

Claude Code's `!` prefix has no TTY, so `sudo` cannot prompt there — run them in
a normal Terminal window:

```bash
sudo Tools/verify-pktap.sh 20     # tees a transcript to ./verify-pktap.log
sudo nmcapd --flows 20
sudo nmcapd --self-test 20
```

`tcpdump -k` takes an **optional** argument, so `-k NPID` makes getopt treat
`NPID` as the filter expression. Valid metadata characters are `INPSDCFU` only.
Plain `-k` prints everything.

---

## 12. Status

| Layer | State |
|---|---|
| PKTAP decode | Verified against live kernel output and Apple's tcpdump |
| Flow tracking | 1.02M pps steady; bounded at capacity under SYN flood |
| TCP reassembly | Overlap, gap and sequence-wrap cases covered |
| DNS | Fuzzed in release; compression attacks covered |
| TLS + JA4/JA3 | JA4_b pinned to the published reference value |
| Hostname enrichment | Per-process cache verified against the shared-CDN case |
| Storage | 60k rows/s; schema and query plans measured |
| Retention / rotation / seal | Day arithmetic, mixed band, pcap budget covered |
| XPC layer | End-to-end over an anonymous listener; Mach service needs the installer |
| **SwiftUI app** | Not started |
| **Install scripts** | Not started |

Two probes remain unverified, both needing root:

- **P4** — does `lo0` really double-tap as assumed?
- **P5** — does `pth_epid` on DNS packets name the *requesting* application when
  mDNSResponder queries on its behalf? If not, the pid-keyed DNS cache degrades
  gracefully to wildcard.
