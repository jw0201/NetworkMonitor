#!/bin/bash
#
# verify-pktap.sh -- the gate for the entire capture layer.
#
# struct pktap_header is a reconstruction (net/pktap.h is not in the SDK).
# Static asserts prove it is self-consistent and a synthetic round-trip proves
# our encoder and decoder agree, but only a live capture proves the KERNEL
# emits what we think it does. This runs our decoder and Apple's tcpdump over
# the same live interface and puts the output side by side.
#
# Nothing downstream should be trusted until the two agree.
#
set -uo pipefail
cd "$(dirname "$0")/.."

COUNT="${1:-20}"
OUT="verify-pktap.log"

# Tee everything. Capture needs root, and a root run in a separate terminal
# cannot be read back by an assistant session -- leaving a transcript behind is
# the difference between "I ran it" and being able to act on what it said.
exec > >(tee "$OUT") 2>&1

if [ "$(id -u)" -ne 0 ]; then
    echo "This needs root: /dev/bpf* is mode 0600 root:wheel."
    echo "Run:  sudo Tools/verify-pktap.sh ${COUNT}"
    exit 1
fi

# macOS has no timeout(1) -- that is GNU coreutils. Without a limit, tcpdump -c N
# blocks forever on a quiet machine, which looks like a hang rather than "no
# traffic".
run_limited() {
    local secs="$1"; shift
    "$@" &
    local pid=$!
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) &
    local killer=$!
    wait "$pid" 2>/dev/null
    kill "$killer" 2>/dev/null
    wait "$killer" 2>/dev/null
}

echo "Building..."
if ! swift build 2>&1 | tail -3; then
    echo "build failed -- fix that first"
    exit 1
fi

echo
echo "############################################################"
echo "# 0. Environment"
echo "############################################################"
echo "  macOS            $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
echo "  SIP              $(csrutil status 2>/dev/null | sed 's/^.*: //')"
echo "  bpf_maxbufsize   $(sysctl -n debug.bpf_maxbufsize)"
echo "  bpf_bufsize      $(sysctl -n debug.bpf_bufsize 2>/dev/null || echo '?')"
echo "  tcpdump          $(tcpdump --version 2>&1 | head -1)"
echo
echo "  Generate traffic in another window if this machine is idle:"
echo "    ping -c 30 1.1.1.1   /   curl -s https://example.com >/dev/null"

echo
echo "############################################################"
echo "# 1. Apple tcpdump -- ground truth"
echo "############################################################"
# Plain -k prints all available packet metadata. Do NOT pass a spaced argument:
# -k takes an OPTIONAL argument, so `-k NPID` makes getopt treat NPID as the
# filter expression, and the valid metadata characters are only INPSDCFU anyway
# (a stray D is parsed as -D and lists interfaces instead of capturing).
run_limited 25 tcpdump -i pktap,all -k -n -c "$COUNT"

echo
echo "############################################################"
echo "# 2. Our decoder"
echo "############################################################"
run_limited 40 .build/debug/nmcapd --self-test "$COUNT" 25

echo
echo "############################################################"
echo "# 3. Savefile link type"
echo "############################################################"
TMP="$(mktemp -t nmpktap)"
rm -f "$TMP"
TMP="$TMP.pcap"
run_limited 25 tcpdump -i pktap,all -c 5 -w "$TMP" >/dev/null 2>&1
if [ -s "$TMP" ]; then
    # Apple's tcpdump writes PCAPNG for pktap captures, not a classic pcap
    # savefile -- the man page says so, and it is why reading "offset 20" gave
    # 4294967295: in a pcapng Section Header Block, offset 20 lands in the middle
    # of the 8-byte section-length field, which is 0xFFFF...FF for "unknown".
    # Classic pcap must be forced with the RAW data link type.
    MAGIC_HEX=$(xxd -l 4 -e -g 4 "$TMP" | awk '{print $2}')
    case "$MAGIC_HEX" in
        0a0d0d0a)
            echo "  $TMP -> PCAPNG (Apple tcpdump's default for pktap)"
            echo "  Link type lives in an Interface Description Block, not at offset 20."
            echo "  Our ring writes classic pcap; pcap_open_offline reads both."
            LINKTYPE="pcapng"
            ;;
        a1b2c3d4|d4c3b2a1)
            # macOS ships BWK awk, which has no strtonum -- that is a gawk
            # extension. bash's base-16 arithmetic needs no external dependency.
            LINKTYPE_HEX=$(xxd -s 20 -l 4 -e -g 4 "$TMP" | awk '{print $2}')
            LINKTYPE=$((16#$LINKTYPE_HEX))
            echo "  $TMP -> classic pcap, linktype $LINKTYPE"
            ;;
        *)
            echo "  $TMP -> unrecognised magic $MAGIC_HEX"
            LINKTYPE="?"
            ;;
    esac
    # Measured on this machine: Apple tcpdump dissects 149 fully and reports
    # UNSUPPORTED for 258; Wireshark is the other way round. We write 149 by
    # default so captures open in the tcpdump every Mac has, and rewrite four
    # header bytes when exporting for Wireshark.
    case "$LINKTYPE" in
        149)    echo "  149 = Apple DLT_PKTAP. tcpdump dissects this; Wireshark needs 258." ;;
        258)    echo "  258 = LINKTYPE_PKTAP. Wireshark dissects this; Apple tcpdump does not." ;;
        pcapng) : ;;
        *)      echo "  unexpected link type -- pktap framing was not applied." ;;
    esac
    echo
    echo "  Replaying that file through our decoder:"
    .build/debug/nmcapd --replay "$TMP" 5 2>&1 | sed -n '/^#  *iface/,/^$/p' | sed 's/^/    /'
    rm -f "$TMP"
else
    echo "  no packets captured (machine idle, or the capture was refused)"
fi

echo
echo "Compare sections 1 and 2 field by field: interface, direction, pid,"
echo "process name, and the effective pid/name for delegated traffic."
echo
echo "Transcript: $(pwd)/$OUT"
