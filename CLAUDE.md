# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A macOS network monitor: Zeek-style per-protocol logging, a storage layer with
configurable retention, a live SwiftUI dashboard, and raw record / packet
browsing. Early stage — the capture, flow-tracking and storage layers exist and
are verified; the analyzers, IPC and UI do not yet.

## Documentation map

| Document | Audience | Purpose |
|---|---|---|
| **this file** | future Claude Code sessions | working agreements, traps, where things live |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | developers and users | what each layer does, data flow, current status |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | anyone changing a decision | why, with evidence; **REVERSED** entries are the ones most likely to be wrongly "corrected" back |
| `README.md` | first-time reader | orientation and the build constraints |
| `~/.claude/plans/elegant-churning-diffie.md` | historical | the original design, including parts measurement later overturned |

## Working agreement on documentation

**Any decision about a layer, a boundary, or an analysis approach must be
recorded before the work is considered done.** Not "should be" — this is the
mechanism that keeps the project coherent across sessions, and an undocumented
decision reliably gets reversed by the next person who reads only the upstream
spec.

Specifically:

- A new layer, module, or moved boundary → update `docs/ARCHITECTURE.md`
- A decision with a non-obvious reason, or one that contradicts documentation
  or an earlier plan → add an entry to `docs/DECISIONS.md`, **with the evidence**
  (a measurement, a query plan, a failing test, a cross-check against another
  tool — not an assertion)
- A trap that would cost the next session time → add it here
- Anything measured → record the number, not the adjective

If a change reverses something already in `DECISIONS.md`, edit that entry rather
than adding a contradictory one, and say what new evidence changed it.

## Build environment constraints

**Xcode 26.6 is now installed** (`xcode-select -p` →
`/Applications/Xcode.app/Contents/Developer`), but the project is deliberately
still buildable with **Command Line Tools alone**, and takes **no third-party
dependencies**. Do not introduce a dependency on Xcode-only tooling without a
specific reason — the constraint is what lets the suite run on a bare machine.

Verified after the switch: clean release build, all 237 tests, and the
`_Static_assert`s on the PKTAP layout (156 / 280 / 149 / 258) all hold against
Xcode's SDK.

What the constraint shaped:

| Constraint | Consequence |
|---|---|
| `XCTest` and `swift-testing` ship with Xcode, not CLT | **`swift test` does not work.** Tests are an executable built on `Sources/NMTestKit`. |
| `actool`/`ibtool` refuse to run without Xcode | No asset catalogs. App icon must be a plain `.icns` referenced by `CFBundleIconFile` — *not* `CFBundleIconName`, which needs a compiled catalog and silently yields a generic icon. |
| No Developer ID | `SMAppService` cannot register the daemon. Install is `sudo Tools/install.sh` (not yet written); XPC peer identity will be pinned by cdhash at install time. |
| The `--bench*` modes | Written when there was no Instruments. Still the right first stop: they measure the specific things that matter (bytes/row, query plans, flood bounds) rather than a general profile. **They print the load average** — a throughput figure without it is not comparable, and a busy machine has read as a 20% regression before. |

If SwiftUI work starts: `@main` must **not** live in a file named `main.swift`
(`'main' attribute cannot be used in a module that contains top-level code`),
and `Info.plist` needs `NSPrincipalClass = NSApplication` or AppKit will not
initialize the app properly.

## Commands

```bash
swift build                      # debug
swift build -c release           # release — use this for any benchmark
swift run nmtest                 # the whole test suite (94 tests). NOT `swift test`.
```

There is no per-test filter. To run a subset, comment out the `run*Tests()`
calls in `Sources/nmtest/main.swift`.

Everything below runs **without root**:

```bash
.build/debug/nmcapd --layout                     # compiled-in struct layout
.build/debug/nmcapd --make-fixture /tmp/f.pcap 200
.build/debug/nmcapd --replay /tmp/f.pcap         # decode, print pktap fields
.build/debug/nmcapd --flows-file /tmp/f.pcap     # conn.log-style output + DNS
.build/debug/nmcapd --ingest /tmp/f.pcap         # whole pipeline into a real DB
.build/release/nmcapd --bench-flows 4000 2000000 # flow engine throughput + flood bound
.build/release/nmcapd --bench 50000 600          # storage: rows/s, bytes/row, dbstat, query plans
tcpdump -r /tmp/f.pcap -k -n                     # Apple's decoder on the same file
```

These need root, and **Claude Code's `!` prefix has no TTY so `sudo` cannot
prompt there** — ask the user to run them in a normal Terminal window:

```bash
sudo Tools/verify-pktap.sh 20     # tees a transcript to ./verify-pktap.log, which IS readable
sudo .build/release/nmcapd --flows 20
sudo .build/release/nmcapd --self-test 20
```

`tcpdump -k` takes an **optional** argument: `-k NPID` makes getopt treat `NPID`
as the filter expression, and the only valid metadata characters are `INPSDCFU`
(a stray `D` is parsed as `-D` and lists interfaces). Plain `-k` prints
everything and is what you want.

## Architecture

```
CPktap          C shim: hand-declared struct pktap_header + Apple's real pcap headers
  └ NMCore      ByteReader, IPAddress/IPPrefix, records, Timestamp, Paths, Limits
      ├ NMCapture   pcap handle, PKTAP decode, pcap file read/write   [root-only surface]
      ├ NMFlow      L3/L4 parsers, FlowKey, FlowTable, TCPStateMachine,
      │             FlowEngine, PacketAnalyzer protocol, HostnameCache
      │   └ NMAnalyzers   DNS and TLS parsing and analysis
      ├ NMStore     SQLite wrapper, schema, StoreWriter, partition/seal/retention
      ├ NMIPC       wire types, LiveRing, DaemonServer/Client, Authorization
      └ NMSource    RecordSource protocol + SyntheticSource
nmcapd          CLI that wires them together
nmtest          test suite executable
```

**Module boundaries are functional, not cosmetic.** `NMCapture` must never
import `NMFlow` or `NMAnalyzers`: it is the only code holding a root-privileged
BPF handle, and keeping it free of parsers is what makes a later split into a
small root capturer plus an unprivileged analyzer a `main.swift` change instead
of a rewrite. The two are coupled only through `PacketContext`
(`Sources/NMFlow/PacketContext.swift`) and one bridging function,
`makeContext` in `Sources/nmcapd/FlowMode.swift`. Keep that seam thin.

L3/L4 parsers live in `NMFlow`, not in an analyzer module, because building a
flow key requires them — putting them above `NMFlow` would be circular. For the
same reason the `PacketAnalyzer` protocol is declared in `NMFlow` (the engine
calls it) while implementations live in `NMAnalyzers`.

`HostnameCache` is in `NMFlow` under a protocol-neutral name, not inside the DNS
analyzer: TLS SNI and HTTP Host will feed it too.

Analyzers are **singletons**, not per-flow objects — a per-flow analyzer would
put a heap allocation on flow creation, the path a SYN flood hammers. Per-flow
state belongs in the flow entry or in a bounded table the analyzer keys itself.

`RecordSource` + `SyntheticSource` exist so everything above the packet parser
(storage, rollups, retention, IPC, UI) can be built and benchmarked with **no
root and no pcap code**. That is why the storage layer was already benchmarked
at 50k rows/min before any UI existed. Preserve this property.

## The PKTAP foundation

macOS's `pktap` pseudo-interface prefixes every captured packet with kernel
metadata naming the pid, process name and Mach-O UUID of the socket owner, plus
an *effective* pid when a proxy process carries traffic on an application's
behalf. That needs root but no NetworkExtension entitlement, and it is the whole
reason this product is not just a Zeek port.

**`net/pktap.h` is not in the SDK.** `struct nm_pktap_header` in
`Sources/CPktap/include/CPktap.h` is a reconstruction, pinned by
`_Static_assert` on every field offset in `shim.c`. Verified against live kernel
output on macOS 26.6.2.

Things that were established by experiment and must not be "corrected" back:

- **PKTAP framing is opt-in.** `pcap_create("pktap,all")` alone activates
  cleanly and returns `DLT_RAW` (12) — bare IP with no metadata. You must call
  `pcap_set_want_pktap(h, 1)` before activate. It is exported from libpcap but
  absent from the public headers, so it is declared in `CPktap.h`.
- **Direction flags:** `flags & 0x3 == 0x1` is inbound, `0x2` is outbound.
  Verified by correlating live packets against this host's own addresses. XNU's
  own comments on those macros are transposed relative to their names.
- **`pth_pid` and `pth_epid` can be `-1`** (no attribution; forwarded traffic,
  inbound packets before a socket is associated). `epid` is only populated on
  genuine delegation, which is the exception, not the rule. Never treat `-1` as
  a pid — use `attributedPID` / `effectivePID`.
- **Apple's `struct pcap_pkthdr` is 280 bytes**, not the 24 every portable
  libpcap example assumes (trailing `char comment[256]`). Never redeclare it in
  Swift; import through `CPktap`.
- **Savefile link type is 149, not 258.** Apple's tcpdump dissects 149 fully and
  reports `UNSUPPORTED` for 258; Wireshark is the other way round. The ring
  writes 149 so captures open in the tcpdump every Mac has;
  `PcapFileWriter.rewriteLinkType` converts four header bytes for Wireshark
  export. Apple's tcpdump writes **pcapng** for pktap captures, not classic pcap.
- **`debug.bpf_maxbufsize` defaults to 512 KB** — about 4 ms of gigabit traffic.
  `CaptureSession.open()` raises it to 16 MB; SIP does not block this.

## Security posture

`nmcapd` runs as root and parses attacker-controlled bytes.

**`UnsafeRawBufferPointer`'s bounds check is a `_debugPrecondition` and is
compiled out under `-O`.** A release build has *no* automatic protection on the
packet path. Every read therefore goes through `ByteReader`
(`Sources/NMCore/ByteReader.swift`), which checks explicitly. **No parser may
touch a raw pointer directly** — this is a lint rule, not a style preference.

Related invariants:

- `ByteReader.need` is written `limit - offset >= n`, never `offset + n <= limit`
  — the latter overflows for a wire-supplied length and the overflowed
  comparison *passes*.
- Every wire length is clamped against what was captured; every loop has a hard
  cap (see `Limits` in `Sources/NMCore/Paths.swift`).
- The flow hash is seeded per process (`FlowHashSeed`). A fixed hash lets an
  attacker craft colliding 5-tuples and turn the flow table into a linked list.
- `FlowTable` has a hard capacity and sheds half-open flows first. Shed flows are
  **aggregated** into one record per (process, destination, port, state) — the
  aggregate itself is capped too.
- X.509 parsing, when it arrives, goes to `SecCertificate*`. Do not hand-write a
  DER parser in this process.

## DNS specifics

Name compression is the most reachable denial of service in the whole project.
The rule that closes it is that **a pointer must target a strictly smaller
offset** — a jump counter alone only bounds how long a cycle runs before it
produces garbage. Both are implemented. Reserved label types (`01`, `10`) are
rejected rather than read as literal lengths.

Labels are escaped on render. A label may legally contain a dot, so an
unescaped one lets `a.b` inside a single label impersonate two labels.

Nothing iterates or allocates on the DNS header's record counts — they are
attacker-supplied 16-bit values.

The parser is **not a sufficient filter for "is this DNS"**: twelve bytes of
anything form a valid header, so random payloads on port 53 parse into a message
with a garbage opcode and no questions. `DNSAnalyzer.isPlausiblyDNS` adds the
structural checks; without them a DNS tunnel or a port scan is logged as
ordinary name resolution.

Unanswered queries are reported via a pending table with a 5s timeout. A pairing
that only fires on responses shows nothing in exactly the case a user is
debugging. mDNS is excluded from pairing — it is broadcast with no expectation of
a matching response, and pairing it manufactures phantom "unanswered" rows.

CNAME chains resolve back to the name originally asked for. Caching the final
CDN edge-node name would be technically true and useless.

## TLS specifics

Three facts the UI must be built around, all recorded explicitly rather than
left blank:

- **TLS 1.3 encrypts the Certificate message.** Certificate fields are
  *unavailable*, not unknown — `certsEncrypted` says which. Under 1.2 they are
  plaintext and get parsed.
- **Under TLS 1.3 the server's ALPN is in `EncryptedExtensions`** and is not
  visible. Reporting the client's offer as negotiated would be a guess.
- **ECH means the visible SNI is the public outer name.** `sniIsOuter` is set
  and the name is deliberately *not* asserted as the connection's hostname.

Hostname precedence is `HostnameSource.strength`: SNI > HTTP Host > per-process
DNS > wildcard DNS > PTR. A weaker source never overwrites a stronger one.

**A malformed individual extension is skipped, not fatal to the ClientHello.**
Discarding the whole message over one odd entry would throw away the SNI and the
fingerprint — which is exactly what an attacker wanting to stay unlogged would
arrange. The extension's type is still recorded so the fingerprint reflects it.

X.509 goes through `SecCertificate`. Do not hand-write a DER parser here.

JA4 is primary because it sorts cipher and extension lists before hashing, so it
survives the extension shuffling Chrome/BoringSSL do deliberately — the thing
that made JA3 useless for modern browsers. JA3 is kept as a threat-intel join
key. `ja4Raw` is stored because two disagreeing digests tell you nothing about
which field diverged.

## Reassembly

Deliberately minimal: first K bytes per direction, in order, with an explicit
gap flag. No out-of-order queues. Overlaps resolve to **first-seen** bytes,
which is what macOS itself does — matching the endpoint's view is what closes
the divergence TCP evasion attacks exploit.

Sequence comparison is a signed difference, never `<`/`>`: numbers wrap at 2^32
and the naive comparison reads a wrap as a 4 GB gap.

Buffers live in `ReassemblyPool` keyed by flow slot, not in `FlowEntry` (262k
entries × 8 KB would be 2 GB). `FlowTable.onSlotReleased` must stay wired or the
pool fills with dead flows' buffers and refuses new ones.

## IPC

The channel is **hybrid, and that reverses the original plan** (DECISIONS I1):

- bulk history → the app reads SQLite **directly, read-only**
- live state → **XPC push** (open flows exist nowhere else — they are written on
  close, so polling the store misses the present entirely)
- control → XPC + Authorization Services

Non-negotiables:

- **The daemon decides authorization**, never the client. `authd` makes the call;
  a patched client cannot forge its answer.
- **Never identify a peer by pid** — pids are recycled.
- The server stops pushing when the last subscriber goes; the client
  unsubscribes on occlusion and reconnects with capped backoff.
- `LiveRing` is fed at packet rate and is bounded everywhere. Idle seconds are
  filled with zeroes, never skipped.

Test it with `swift run nmtest` (anonymous `NSXPCListener`, no root) or see it
with `nmcapd --live`.

## Honesty invariants

The product's value depends on not presenting guesses as facts. These are
deliberate and should not be "simplified away":

- A monotonic `lossEpoch` advances on any capture drop; flows spanning one are
  marked `captureLossSuspected` and their byte counts render as approximate.
- Loopback is tapped twice by the kernel (once per endpoint). Only the outbound
  copy is counted, or every localhost byte doubles — but both are fed to the
  state machine so a handshake is not missed.
- IP `total_length` is routinely 0 at the host stack because TSO/LRO offload
  fills it in later. Falling back to the captured length is normal operation,
  not error handling; the fallback sets `clamped`.
- Direction calibration refuses to conclude anything when it has no
  locally-sourced packets to compare against.
- Hostname lookups record which key matched (`dnsPerProcess` vs `dnsWildcard`)
  and flag ambiguity when several names are on file, rather than presenting the
  newest as fact. Enrichment runs at flow *creation* so the answer reflects what
  was known when the connection was made.
- TLS 1.3 encrypts the Certificate message, and ECH makes the visible SNI not
  the real destination. The UI must say "encrypted" / flag `sniIsOuter` rather
  than showing a confident wrong hostname.

## Retention and partitioning

Retention is `unlink()` on a day file. That is the reason the store is split at
all — see DECISIONS.md S8 for what the single-database alternative costs.

- The writer's **current day comes from the data, not the clock**. Taking it from
  the wall clock meant replaying an old capture rotated on the first write.
- Rotation is `rename()`; sealing then sets `journal_mode=DELETE` (so the archive
  has no `-wal`/`-shm` at all), builds extra read indices, and `VACUUM INTO`s a
  sibling before swapping.
- Three expiry shapes: past every retention → `unlink` without opening; in the
  mixed band → opened once to drop expired tables; rollups/alerts expire by row.
- Defaults are **tiered, not flat**: at 50k rows/min a flat 30-day raw retention
  needs ~580 GB.
- Day arithmetic is integer (Howard Hinnant's algorithm), never a date formatter
  — retention must not depend on locale or time zone.
- Rotating twice in one day appends a suffix rather than overwriting. An archive
  whose name does not parse as a date is reported and **never deleted on a guess**.

Inspect with `nmcapd --store-info <dir>`; it is a dry report unless
`--run-retention` is passed.

## Storage

Measured on this machine with `--bench`, not estimated:

| | 5k conn/min (realistic) | 50k conn/min (heavy) |
|---|---|---|
| sustained write | 59k rows/s | 60k rows/s |
| headroom vs target | 708x | 72x |
| bytes/row (incl. indices) | 182 | 175 |
| 30-day raw retention | 60 GB | 579 GB |

**SQLite's write path is not a constraint — disk is.** At 50k rows/min a 30-day
raw retention does not fit a 466 GB disk, so tiered retention is the default and
Settings must show a measured projection.

Design consequences, all measured:

- Retention is **day-partitioned files**: rotate by `rename()`, drop by
  `unlink()`. A single DB with nightly `DELETE` writes every freed page to the
  WAL (costlier than the insert), never shrinks, and `VACUUM` takes an exclusive
  lock for minutes.
- Sealed archives get extra read indices at zero cost to the hot write path, and
  have no `-wal`/`-shm` at all.
- **Suffix search compiles to a range, never `LIKE`.** `LIKE 'com.apple.%'`
  produces a full index `SCAN` (SQLite will not use an index for a `LIKE` prefix
  under the default case-insensitive collation); `>= 'com.apple.' AND
  < 'com.apple/'` produces a `SEARCH`. Measured 9.90 ms vs 0.56 ms.
- Addresses are stored as **BLOBs** in native width so CIDR compiles to
  `BETWEEN` — an index range scan. As TEXT the same filter is a full scan.
- Pagination is **keyset**, never `OFFSET`: measured 0.07 ms vs 8.26 ms at 500k
  rows, and `OFFSET` is also incorrect under concurrent inserts.
- The Overview screen reads **only** rollup tables. The same aggregate costs
  0.21 ms from rollups and 210 ms from raw rows.
- Hostnames, SNI and DNS query names share one `meta.name` dimension (they are
  the same namespace), with the reversed spelling stored once there rather than
  per row. TLS fingerprints are interned in `meta.fingerprint`. This cut
  bytes/row from 257 to 175.
- `SQLITE_MAX_ATTACHED` is 10 in this build; `meta`/`rollup`/`pcap` take three,
  leaving seven for day files. Queries spanning more must use rollups or merge
  per-file in Swift.
- Statements must be reset after stepping or SQLite refuses to `COMMIT` with
  error 5, "SQL statements in progress" — an error that surfaces far from its
  cause. `Statement.step()` auto-resets on `SQLITE_DONE` to make the whole class
  of bug impossible.

## Concurrency

Swift 6 language mode on every target.

- Capture loop: a dedicated `Thread` running blocking `pcap_dispatch`. Not
  `pcap_setnonblock` (spins), not `DispatchSource` (GCD latency).
- The packet path uses thread-confined classes that are deliberately **not**
  `Sendable`, so the compiler prevents sharing. That is stricter than an actor
  and free — an actor would put a suspension point on the per-packet path, and
  at ~1 µs/packet that is the entire budget.
- Actors are for cold paths only: `StoreWriter`, and later the XPC listener.
- `nonisolated(unsafe)` has exactly one justified use: the `@convention(c)` pcap
  callback's context pointer.

## Verification state

| Layer | Status |
|---|---|
| PKTAP decode | Verified against live kernel output and Apple's tcpdump |
| Flow tracking | 1.02M pps steady; bounded at capacity under SYN flood |
| Storage | Benchmarked to 60k rows/s; schema and query plans measured |
| Retention / rotation / seal | Day arithmetic, mixed band, pcap budget covered |
| DNS parsing + analysis | Fuzzed in release; compression attacks covered |
| Hostname enrichment | Per-process cache verified against the shared-CDN case |
| TCP reassembly | Overlap, gap and sequence-wrap cases covered |
| TLS analysis + JA4/JA3 | JA4_b pinned to the published reference value |
| XPC, retention/seal, SwiftUI app, install scripts | Not started |

Two probes from the plan remain unverified and both need root:
**P4** (does lo0 really double-tap as assumed) and **P5** (does `pth_epid` on
DNS packets name the *requesting* application — the pid-keyed DNS cache degrades
gracefully to wildcard if not).
