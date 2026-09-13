# NetworkMonitor

A macOS network monitoring app: Zeek-style per-protocol logging, a storage
layer with configurable retention, a live SwiftUI dashboard, and raw record /
packet browsing.

## Why PKTAP

macOS exposes a `pktap` pseudo-interface that prefixes every captured packet
with kernel metadata naming the **pid, process name and Mach-O UUID** of the
socket owner -- plus an *effective* pid identifying the application on whose
behalf a proxy process (`nsurlsessiond`, `mDNSResponder`, `trustd`) is acting.

This is what makes the product different from a Zeek port. It needs root, but
no NetworkExtension entitlement, and it is what lets the DNS answer cache be
keyed by `(requesting pid, IP)` rather than by IP alone -- which resolves the
CDN shared-address ambiguity that defeats IP-only tools.

## Build constraints

This project builds with **Command Line Tools only** -- no Xcode, no Homebrew,
**no third-party dependencies**. That has three consequences worth knowing
before you touch anything:

| Constraint | Consequence |
|---|---|
| `XCTest` and `swift-testing` ship with Xcode, not CLT | `swift test` does not work. Tests are an executable: `swift run nmtest`, built on `Sources/NMTestKit`. |
| `actool` / `ibtool` refuse to run without Xcode | No asset catalogs. The app icon is a plain `.icns` referenced by `CFBundleIconFile` (**not** `CFBundleIconName`, which needs a compiled catalog and silently yields a generic icon). |
| No Developer ID | `SMAppService` cannot register the daemon. Installation is `sudo Tools/install.sh`; peer identity for XPC is pinned by cdhash at install time. |

## Layout

```
Sources/
  CPktap/       C shim. Hand-declared struct pktap_header (net/pktap.h is NOT
                in the SDK) with a _Static_assert on every field offset, plus
                Apple's real pcap headers.
  NMCore/       ByteReader -- the only sanctioned way to read packet bytes.
  NMCapture/    pcap handle, PKTAP decode, capture loop. Root-only surface.
  NMTestKit/    Minimal test harness (see above).
  nmcapd/       The capture daemon.
  nmtest/       Test suite.
```

`NMCapture` must never import the flow or analyzer modules. That boundary is
what keeps a later split into a small root capturer plus an unprivileged
analyzer a `main.swift` change rather than a rewrite.

## The link-type fork

A pktap savefile can carry link type 149 or 258, and the two viewers disagree
about which. Measured here, not inferred from the header comments:

| link type | Apple `tcpdump` (ships with macOS) | Wireshark |
|---|---|---|
| **149** (Apple `DLT_PKTAP`) | dissects fully, with process names | "DLT_USER2 - unknown" |
| **258** (`LINKTYPE_PKTAP`) | `UNSUPPORTED` + raw hex | dissects fully |

libpcap's own `dlt.h` argues for 258 so files read identically on every OS. But
Apple's tcpdump 4.99.1 still only handles 149 -- exactly as that comment
predicted back in the Mavericks era. So the ring writes **149**, because a
capture no tool on the machine can open is worthless, and export for Wireshark
rewrites four header bytes. The packet records are identical either way.

## Two facts that will bite you

1. **Apple's `struct pcap_pkthdr` is 280 bytes**, not the 24 that every
   portable libpcap example assumes -- it carries a trailing `char comment[256]`.
   Never redeclare it in Swift; import it through `CPktap`.

2. **`UnsafeRawBufferPointer`'s bounds check is a `_debugPrecondition`** and is
   compiled out under `-O`. A release build has *no* automatic protection on
   the packet path. Every read goes through `ByteReader`, which checks
   explicitly. This is a lint rule, not a style preference: `nmcapd` runs as
   root and parses attacker-controlled bytes.

## Verify the capture layer

```bash
swift build
swift run nmtest              # 30 tests, no root needed
sudo Tools/verify-pktap.sh    # diffs our decoder against Apple's tcpdump
```

No root? The decode path is fully exercisable without it:

```bash
.build/debug/nmcapd --make-fixture /tmp/f.pcap 60   # synthetic pktap capture
.build/debug/nmcapd --replay /tmp/f.pcap            # our decoder
tcpdump -r /tmp/f.pcap -k -n                        # Apple's decoder, same file
```

That cross-check already confirmed the header layout field for field, and
settled the direction flags: Apple's tcpdump reads `flags & 0x3 == 0x2` as
`out` and `0x1` as `in`, matching the reconstruction in `CPktap.h`.

`verify-pktap.sh` remains the gate for the one thing a fixture cannot prove --
that the KERNEL emits what we think it does. It needs root once.

Note on `tcpdump -k`: the argument is optional, so `-k NPID` makes getopt treat
`NPID` as the filter expression. Valid metadata characters are `INPSDCFU` only;
anything else is parsed as a separate option (a stray `D` becomes `-D` and lists
interfaces). Plain `-k` prints everything and is what you want.
