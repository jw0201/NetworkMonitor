# Decision record

Why things are the way they are, with the evidence.

Entries marked **REVERSED** contradict what the original design document said.
They were changed by measurement or experiment, not by re-reading documentation,
and they are the entries most likely to be helpfully "corrected" back by someone
who has only read the upstream headers. Each carries the evidence that settled
it.

Measurements were taken on the development machine: macOS 26.6.2, Intel
i5-1038NG7 (4 cores / 8 threads), 16 GB RAM, Swift 6.3.3, Command Line Tools
only.

---

## Capture

### C1. PKTAP framing is opt-in — `pcap_set_want_pktap` is required

`pcap_create("pktap,all")` followed by the usual setters and `pcap_activate`
succeeds cleanly and returns **`DLT_RAW` (12)**: bare IP packets with no
metadata at all. Nothing errors. The capture works. The per-packet process
attribution — the entire reason for capturing this way — is silently absent.

`pcap_set_want_pktap(h, 1)` must be called before activate. It is exported from
Apple's libpcap but **absent from the public headers**, so it is declared in
`CPktap.h`. `pcap_set_datalink(h, DLT_PKTAP)` after activate is the fallback,
guarded by a check that the device actually offers 149.

> Evidence: `verify-pktap.log` from the first live run —
> `open failed: capture device returned DLT 12, expected 149`.
> After the fix: `link types offered 149, 12`.

### C2. Savefile link type is **149**, not 258 — **REVERSED**

libpcap's own `dlt.h` argues at length that a pktap savefile should record
`LINKTYPE_PKTAP` (258) so files read identically on every OS, and the original
plan followed that. Measured, the two viewers disagree and only one of them is
present on a stock Mac:

| link type | Apple `tcpdump` 4.99.1 | Wireshark |
|---|---|---|
| **149** (Apple `DLT_PKTAP`) | dissects fully, with process names | "DLT_USER2 — unknown" |
| **258** (`LINKTYPE_PKTAP`) | `UNSUPPORTED` + raw hex dump | dissects fully |

Wireshark is not installed on the development machine, and `tcpdump` ships with
every macOS. Writing 258 would produce captures that **no tool on the machine
can open**. The ring therefore writes 149 and
`PcapFileWriter.rewriteLinkType` converts four header bytes for Wireshark
export; the packet records are byte-identical either way.

> Evidence: the same synthetic file, byte-for-byte, read twice —
> `tcpdump -r f.pcap -k -n` on 258 → `UNSUPPORTED`;
> patched to 149 → `(en0, proc Safari:842, eproc Mail:904, svc BE, out)`.

Related: **Apple's tcpdump writes pcapng for pktap captures**, not classic pcap.
Reading "offset 20" of such a file yields `4294967295`, because in a pcapng
Section Header Block that offset lands mid-way through the 8-byte section-length
field, which is `0xFFFF…FF` for "unknown".

### C3. Direction flags: `0x1` is inbound, `0x2` is outbound

XNU's comments on `PTH_FLAG_DIR_IN` and `PTH_FLAG_DIR_OUT` are transposed
relative to the macro names, so the header cannot be trusted on its own. The
values were established empirically instead: correlate live packets against this
host's own interface addresses, since a packet whose **source** is a local
address went out.

```
flags & 0x3 = 0x1 :  0 local-source,  9 remote-source (  0%)  → INBOUND
flags & 0x3 = 0x2 : 11 local-source,  0 remote-source (100%)  → OUTBOUND
```

A clean 100/0 split over 20 live packets. Independently confirmed by Apple's own
tcpdump reading our synthetic file and printing `out` for `0x2`.

The calibration routine **refuses to conclude anything** when it has seen no
locally-sourced packets — an earlier version reported both bit patterns as
"inbound" from zero evidence.

### C4. Field presence comes from the wire's `pth_length`, never `sizeof`

Older macOS shipped shorter pktap headers and future ones may append fields. A
108-byte header must yield `nil` for `flowid`, `ipproto` and the UUIDs rather
than reading adjacent packet bytes as them.

This makes the decoder strictly more robust than Apple's: on a 108-byte header,
`tcpdump` discards the metadata entirely while ours still extracts pid, process
name and interface.

### C5. Apple's `struct pcap_pkthdr` is 280 bytes

It carries a trailing `char comment[256]` that the portable 24-byte layout does
not. Any Swift redeclaration based on the portable version reads `caplen` and
`len` correctly but computes every subsequent offset wrong. The struct is
imported through the C shim and asserted at compile time; **never redeclare it**.

### C6. `pth_pid` and `pth_epid` can be `-1`

Observed live. `-1` means the kernel had no attribution — forwarded traffic, or
an inbound packet arriving before a socket is associated. `pth_epid` is
populated **only on genuine delegation**, which is the exception rather than the
rule: in a 20-packet live sample exactly one packet carried it
(`kernel_task:0` → `eproc gh:17463`).

Never treat `-1` as a pid. `attributedPID` / `effectivePID` return optionals.

### C7. `debug.bpf_maxbufsize` defaults to 512 KB and root can raise it

512 KB holds roughly 310 full-size pktap packets — about 4 ms of gigabit
traffic. `CaptureSession.open()` raises it to 16 MB. SIP does **not** block this
(confirmed: the value was observed at 16777216 after a daemon run).

---

## Flow tracking

### F1. Orientation is decided once, at flow creation

An earlier version recomputed it per packet. Since the guess for a lone packet is
always "the sender is the initiator", nearly every packet counted as originator
and the two directions of each conversation silently collapsed into one.

> Evidence: five tests failed simultaneously — `origPkts` 6 instead of 4,
> `respBytes` 0 instead of 500, state `S2` instead of `SF`.

### F2. The flow hash is seeded per process

Not a micro-optimisation — a security requirement. With a fixed, publicly known
hash an attacker can craft 5-tuples that all collide into one bucket, degrading
the flow table to a linked list. That is an algorithmic-complexity denial of
service costing the attacker very little traffic.

Swift's synthesised `Hashable` is also unsuitable for a second reason: it calls
SipHash once per stored property, which is measurable at hundreds of thousands
of packets per second.

### F3. The interface is part of the flow key

The same 5-tuple legitimately appears on `utun0` and `en0` simultaneously (a VPN
carries the inner packet while the outer tunnel is its own conversation), and
twice per packet on `lo0`.

### F4. Shed flows are aggregated, not emitted individually

Under a SYN flood the table sheds flows as fast as packets arrive. Emitting one
record per shed flow is wrong twice: it buries the log under millions of
near-identical rows exactly when something interesting is happening, and the
per-record work becomes the bottleneck precisely when the engine is already
under pressure.

One record per `(process, destination, port, state)`. The aggregate table is
itself capped — otherwise the thing built to bound the problem becomes unbounded.

### F5. Reassembly is minimal and overlaps resolve to first-seen bytes

Full reassembly — out-of-order queues, overlap resolution, the TCP evasion
literature — is a large body of subtle code and a large attack surface. What the
analyzers need is narrower: the first K bytes per direction, in order, with an
explicit gap flag.

Overlaps keep the bytes seen **first**. That is the conservative BSD-like policy
and, decisively, it is what macOS itself does — so our view of a stream matches
the endpoint's. Divergence between the two is exactly what TCP evasion attacks
are built on.

A hole **stops buffering** rather than splicing across it. A spliced stream
parses into plausible nonsense; stopping visibly is what makes `missed_bytes`
mean something.

### F6. Sequence comparison is a signed difference

Sequence numbers wrap at 2³², which any long-lived transfer reaches. Comparing
with `<` or `>` turns the wrap into a phantom four-gigabyte gap.

### F7. IP `total_length` of 0 is normal, not an error

Capture happens at the **host stack**, not on the wire, so TSO/LRO offload means
the kernel hands the NIC one large segment and hardware fills in the length
afterwards. Packets can be 64 KB and `total_length` is frequently 0. A parser
that trusts the field computes negative payload lengths on a perfectly ordinary
machine.

Falls back to the captured length and sets `clamped`.

---

## Analyzers

### A1. Analyzers are singletons, not per-flow objects

A per-flow analyzer puts a heap allocation on flow creation — the path a SYN
flood hammers. Per-flow state lives in the flow entry or in a bounded table the
analyzer keys itself.

### A2. A DNS pointer must target a strictly smaller offset

Name compression is the most reachable denial of service in the project: a
two-byte pointer that references itself spins forever inside a root process,
from a packet that fits in a single datagram.

A **jump counter alone does not close it** — it only bounds how long the loop
runs before producing garbage. Monotonically decreasing offsets make a cycle
impossible to construct. Both are implemented; there is a test for a two-pointer
cycle that a counter-only decoder would merely survive rather than reject.

### A3. The DNS parser is not a sufficient test for "is this DNS"

Twelve bytes of anything form a syntactically valid DNS header. Forty bytes of
`0xFF` parsed into a "message" with a garbage opcode and no questions, and the
analyzer labelled the flow `dns`.

Without the structural checks in `isPlausiblyDNS`, a **DNS tunnel or a port scan
is logged as ordinary name resolution** — the opposite of what a monitoring tool
should do.

> Evidence: found by a test asserting the malformed counter incremented; it did
> not, because the parse had succeeded.

### A4. CNAME chains resolve back to the name originally asked for

A CDN answer is a chain of aliases. Caching the final edge-node name would be
technically true and useless: the application asked for `www.example.com` and
that is the name a person recognises in a log.

### A5. Unanswered DNS queries are reported

A request/response pairing that only fires on responses shows nothing at all in
exactly the case a user is debugging — a resolver that has stopped answering, a
captive portal, a firewall drop. A pending table with a five-second timeout turns
silence into a row.

mDNS is excluded from pairing: it is broadcast with no expectation of a matching
response on the same flow, and pairing it manufactures phantom "unanswered" rows
forever.

### A6. The DNS cache is keyed by `(requesting pid, address)`

The feature that distinguishes this from an IP-only tool. CDNs put many names
behind one address, so an address-only cache keeps whichever name resolved most
recently and presents it as fact for every process that subsequently connects.

pktap makes better possible: DNS is resolved by `mDNSResponder`, but the pktap
header on the query names the process that **requested** it. So when Safari
connects to a shared CDN address we prefer the name Safari itself looked up, even
if Mail resolved the same address to something else moments earlier.

A wildcard entry is stored alongside and the lookup records **which key matched**,
so a fallback is visible as a fallback. When several names are genuinely on file
the newest wins but the row is marked ambiguous.

TTLs are clamped to a 60 s floor and 1 h ceiling, with the server's actual TTL
preserved for display. The floor exists because CDN answers carry 5–30 second
TTLs and honouring those literally means the connection that immediately follows
the lookup finds nothing cached.

### A7. A malformed TLS extension is skipped, not fatal

Discarding the whole ClientHello over one odd extension throws away the SNI and
the fingerprint — **exactly what an attacker wanting to stay unlogged would
arrange**. The extension's type is still recorded, so the fingerprint reflects
that it was offered.

### A8. JA4 is primary, JA3 is kept as a join key

JA4 sorts the cipher and extension lists before hashing, which makes it immune to
the extension shuffling Chrome and BoringSSL do deliberately — shuffling that
made JA3 unstable and largely useless for modern browsers. JA3 is retained
because every existing threat-intelligence feed is keyed on it, and once the
ClientHello is parsed it costs one MD5 over a string already built.

> Evidence: a test asserts the asymmetry directly — the same client with
> reordered extensions produces one JA4 and two different JA3s.

**JA4_b is pinned to the published reference value `8daaf6152771`** for a known
cipher list. That one assertion covers GREASE stripping, 4-hex rendering,
ascending sort, comma join and SHA-256 truncation together. Without an external
anchor a self-consistent but wrong implementation looks fine.

`ja4Raw` (the unhashed string) is stored because two disagreeing hex digests tell
you nothing about which field diverged.

### A9. SNI outranks the DNS cache

It is what the client literally asked *this* server for on *this* connection,
rather than an inference from an earlier lookup that may have been another
process's. `HostnameSource.strength` enforces that a weaker source never
overwrites a stronger one.

### A10. ECH outer names are not asserted as the destination

With Encrypted Client Hello the visible SNI is the public outer name. The record
sets `sniIsOuter` and the analyzer deliberately does **not** offer the name as
the connection's hostname. Blank beats confidently wrong.

### A11. X.509 goes through `SecCertificate`

Hand-writing a DER parser inside a root process consuming attacker-supplied
certificates would add an entire class of memory-safety bugs for no benefit. Only
the SHA-256 fingerprint is computed directly, and that is a hash over the DER
bytes requiring no parsing.

TLS 1.3 encrypts the Certificate message, so for most modern traffic the fields
are **unavailable rather than unknown**, and `certsEncrypted` records which.

---

## Storage

### S1. SQLite's write path is not the constraint — disk is

Measured with `nmcapd --bench`:

| | 5k conn/min (realistic) | 50k conn/min (heavy) |
|---|---|---|
| sustained write | 59k rows/s | 60k rows/s |
| headroom vs target | **708×** | **72×** |
| bytes/row (incl. indices) | 182 | 175 |
| 30-day raw retention | 60 GB | **579 GB** |

At the heavy rate a flat 30-day raw retention does not fit a typical laptop
disk. That, not the database engine, is what shapes the design.

### S2. Dimension tables cut bytes/row from 257 to 175 — 32%

Found with `dbstat`, not guessed. The first measurement showed the `ssl` table at
**249 bytes/row** — 28% of the file despite having fewer rows than `conn`. The
causes were JA4/JA4_r/JA3 strings at ~146 bytes on every row, and storing both
the forward and reversed spelling of every domain.

Both moved to dimension tables (`meta.fingerprint`, `meta.name`), with the
reversed spelling stored **once**. `uid` also changed from an 8-byte BLOB to
INTEGER, which SQLite varint-encodes to 2–4 bytes for sequential ids.

### S3. Suffix search compiles to a range, never `LIKE`

SQLite's default `LIKE` is ASCII case-insensitive, so it **will not use an index
for a prefix pattern** and silently degrades to a full scan.

```
LIKE 'com.apple.%'                           → SCAN    9.90 ms
text_rev >= 'com.apple.' AND < 'com.apple/'  → SEARCH  0.56 ms
```

Confirmed by `EXPLAIN QUERY PLAN`, not inferred.

### S4. Pagination is keyset, never `OFFSET`

`OFFSET N` makes SQLite **produce and discard** N rows.

```
OFFSET, deep in the table  → SCAN    8.26 ms
keyset, same position      → SEARCH  0.07 ms     118×
```

And `OFFSET` is also *incorrect* here: the daemon writes while a user browses,
so a row inserted at the head shifts every subsequent page boundary, producing
duplicated and skipped rows. Keyset cursors anchor to data, not position.

### S5. Addresses persist as BLOBs in native width

SQLite compares BLOBs with `memcmp`, so a CIDR filter compiles to
`daddr BETWEEN ?1 AND ?2` — an index range scan (0.18 ms). Stored as TEXT the
same filter is a full table scan. It is also half the bytes for the common case.

### S6. The dashboard reads only rollup tables

```
Overview aggregate from rollups  →   0.21 ms
the same aggregate from raw rows → 210.86 ms     1000×
```

Rollups are maintained by the writer from counters it already keeps in memory,
never derived by scanning raw rows later.

### S7. Timestamps are INTEGER microseconds

pcap hands us a `struct timeval`, so integer microseconds is the lossless,
conversion-free landing spot. A float makes range boundaries and de-duplication
keys subtly wrong, and must never be a primary key component. ISO-8601 text would
cost over a gigabyte a day at the heavy rate.

### S8. Day-partitioned files, not DELETE + VACUUM

Retention becomes `unlink()`: O(1), no lock, no free space required, no stall.

A single database with a nightly `DELETE` writes every freed page to the WAL
(more I/O than the original insert cost), never shrinks the file — so the
steady state is permanently sized to the worst week — and correcting that with
`VACUUM` takes an exclusive lock for minutes and needs 2× the file size free.

Sealing is the other half: a file nobody will write again carries extra read
indices at zero cost to the hot write path, and drops its WAL entirely, which
also removes the `-shm` write requirement that complicates cross-process reads.

### S9. Statements must reset on `SQLITE_DONE`

A stepped `PRAGMA` left un-reset keeps a statement "in progress", and SQLite then
refuses to `COMMIT` with error 5 — an error that surfaces nowhere near the
statement that caused it. `Statement.step()` resets automatically to make the
whole class of bug impossible rather than a thing to remember.

### S10. The writer's current day comes from the data, not the clock

Taking it from the wall clock at startup meant a writer replaying an older
capture rotated on its very first write, archiving an empty partition and putting
the real data in the "next" day. It is now derived from the first record, and
recovered from rows already in the live file after a restart.

---

## Inter-process communication

### I1. The channel is hybrid, not all-XPC — **REVERSED**

The original plan routed everything through XPC, on the grounds that a
read-only SQLite connection to a WAL database needs **write** access to the
`-shm` file (readers register a read-mark in the shared-memory index), which
makes a root-owned store awkward to read from a user process.

That trap is real, but solvable: SQLite's unix VFS creates `-wal` and `-shm`
with the same mode/uid/gid as the main database, so a `_networkmonitor` group
plus `0770` on the directory and `0660` on the file is sufficient. The directory
is 0770 rather than 0750 specifically because a reader must be able to *create*
the `-shm` when the daemon is not running — with 0750 it fails only when the
daemon is down, which is the worst possible time for a confusing error. Sealed
archives sidestep it entirely, having no `-wal` at all.

Against that, proxying bulk reads costs 5–10× in serialisation and makes the
**capture daemon spend its CPU serving table scans instead of draining the BPF
buffer** — trading packet loss for architectural tidiness.

So: bulk history is read directly, live state and control go over XPC.

### I2. Live state cannot be served from the database

Not a performance choice. A flow is written when it **closes**, so every
currently-open connection exists nowhere but in the daemon's memory. A "current
connections" view built by polling the store would show the recent past and miss
the present entirely.

This is why `LiveRing` exists and why the live channel cannot be removed by
making queries faster.

### I3. Authorization is decided by the daemon

The client is a separate binary a user can replace or patch, so a privilege
check it performs on itself is decoration.

Authorization Services rather than a home-made group check, because the decision
is then made by `authd`: a patched client would have to forge authd's answer,
which it cannot reach. The group-membership fallback for unsigned development
builds is marked as strictly weaker — it proves who the caller is, not that a
human approved this action.

### I4. Peer identity never uses the pid

Pids are recycled. A check against one is a check against whoever holds it now.
Identity comes from the code-signing requirement and the effective uid, both
captured once at accept time.

### I5. The daemon stops producing when nobody is listening

A background monitor that keeps serialising snapshots for an occluded window
burns battery for nothing, and that is the kind of thing that gets a tool
uninstalled rather than filed as a bug. The client unsubscribes on occlusion and
the server's push timer stops when the last subscriber goes.

The client also reconnects with capped backoff: the daemon restarts on upgrade
and on KeepAlive bounces, and an app that needs relaunching after each one is
broken in practice even though each individual failure is "correct".

### I6. Live per-process totals come from open flows, not from closes

The first version accumulated only when a flow ended, so a machine holding a few
long-lived connections showed **no per-process traffic at all** — which on a
real machine is most of the interesting traffic. Totals are now recomputed each
refresh from the open flows plus anything closed inside the window, which also
removes any chance of counting a flow once while open and again when it closes.

> Found by running `--live` and seeing an empty "Top processes" section.

### I7. Wire payloads are versioned JSON in `Data`, not @objc types

The daemon and the app are separate binaries that can be updated independently —
a user can replace the app while the daemon keeps running. Encoding the domain
types directly would couple the protocol to every internal refactor, and an
@objc protocol is awkward to version. Both sides check `wireVersion` and report
a mismatch rather than silently accepting a payload they may misread.

## Concurrency

### N1. The packet path uses thread-confined classes, not actors

An actor would put a suspension point on the per-packet path. At roughly 1 µs
per packet that is the entire budget. The types it owns are deliberately **not**
`Sendable`, so the compiler prevents sharing — stricter than an actor, and free.

Actors are used for cold paths only: `StoreWriter`, and later the XPC listener.

### N2. The capture loop is a dedicated thread with blocking `pcap_dispatch`

`pcap_setnonblock` turns the loop into a spin, burning a core. A
`DispatchSource` on the BPF descriptor adds GCD scheduling latency and a subtle
dependency on readability semantics for no benefit.

### N3. Immediate mode off, 20 ms read timeout

Immediate mode wakes the reader per packet: at 80 kpps that is 80,000 syscall
returns per second, which pins a core and thermally throttles a laptop. 20 ms
(rather than the conventional 1000 ms) is chosen so the 512 KB fallback buffer
does not overflow on timeout alone.

### N4. `nonisolated(unsafe)` has exactly one justified use

The `@convention(c)` pcap callback's context pointer. Swift closures cannot be
`@convention(c)` if they capture. Every other use is a bug; grep for it in
review.

---

## Environment

### E1. `swift test` does not work

Neither XCTest nor swift-testing ships with the Command Line Tools. Tests are an
ordinary executable built on `Sources/NMTestKit` — `swift run nmtest`.

### E2. No asset catalogs

`actool` and `ibtool` refuse to run without Xcode. The app icon must be a plain
`.icns` referenced by `CFBundleIconFile` — **not** `CFBundleIconName`, which
needs a compiled catalog and silently yields a generic icon.

### E3. `SMAppService` is unavailable without a Developer ID

Daemon registration requires a valid signature and matching team ID.
Installation will be `sudo Tools/install.sh`, with XPC peer identity pinned by
cdhash at install time. Revisit when a signing identity exists.

### E4. `tcpdump -k` takes an optional argument

`-k NPID` makes getopt treat `NPID` as the filter expression. The valid metadata
characters are `INPSDCFU` only, and anything else is parsed as a separate option
— a stray `D` becomes `-D` and lists interfaces instead of capturing. Plain `-k`
prints everything.

### E5. macOS has no `timeout(1)` and its `awk` has no `strtonum`

`timeout` is GNU coreutils. `strtonum` is a gawk extension; macOS ships BWK awk.
`Tools/verify-pktap.sh` uses a background-and-kill helper and bash base-16
arithmetic instead.

### E6. Root output must be written to a file

Capture needs root, and a root run in a separate terminal cannot be read back by
an assistant session. `Tools/verify-pktap.sh` tees its transcript to
`verify-pktap.log` — "I ran it" is not something anyone can act on.
