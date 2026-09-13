/*
 * shim.c -- compile-time proof that our hand-declared PKTAP layout matches
 * what the kernel actually emits.
 *
 * net/pktap.h is absent from the SDK, so struct nm_pktap_header is a
 * reconstruction. Every field offset is asserted here. If Apple ever changes
 * the layout, or if the reconstruction is wrong on some architecture, this
 * file fails to compile -- which is enormously preferable to silently decoding
 * every packet at the wrong offsets.
 */

#include "include/CPktap.h"

/* ---- struct nm_pktap_header ------------------------------------------- */

_Static_assert(MAXCOMLEN == 16, "MAXCOMLEN changed; pth_comm sizing is wrong");
_Static_assert(NM_PKTAP_IFXNAMESIZE == 24, "PKTAP_IFXNAMESIZE changed");

_Static_assert(offsetof(struct nm_pktap_header, pth_length) == 0, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_type_next) == 4, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_dlt) == 8, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_ifname) == 12, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_flags) == 36, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_protocol_family) == 40, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_frame_pre_length) == 44, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_frame_post_length) == 48, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_pid) == 52, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_comm) == 56, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_svc) == 76, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_iftype) == 80, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_ifunit) == 82, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_epid) == 84, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_ecomm) == 88, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_flowid) == 108, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_ipproto) == 112, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_tstamp) == 116, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_uuid) == 124, "");
_Static_assert(offsetof(struct nm_pktap_header, pth_euuid) == 140, "");
_Static_assert(sizeof(struct nm_pktap_header) == 156, "pktap v1 header must be 156 bytes");

/* pid_t must be exactly int32_t or the pid fields shift everything after them. */
_Static_assert(sizeof(pid_t) == 4, "pid_t is not 32-bit; header layout invalid");
_Static_assert(sizeof(struct timeval32) == 8, "timeval32 is not 8 bytes");
_Static_assert(sizeof(uuid_t) == 16, "uuid_t is not 16 bytes");

/* ---- Apple's pcap_pkthdr ----------------------------------------------
 *
 * This is the assertion that catches the most dangerous possible mistake.
 * A portable libpcap has a 24-byte pcap_pkthdr (timeval + caplen + len).
 * Apple appends char comment[256]. Any Swift-side redeclaration based on the
 * portable layout reads caplen and len correctly but computes the wrong stride
 * and the wrong packet base for anything that indexes by header size.
 */
_Static_assert(sizeof(struct pcap_pkthdr) >= 280,
               "Apple pcap_pkthdr is expected to carry a trailing comment[256]; "
               "if this fires, re-check the SDK before trusting any offset math");

/* ---- DLT values --------------------------------------------------------
 *
 * On Darwin, DLT_PKTAP is DLT_USER2 (149) for live handles, but a savefile
 * MUST record 258 so Wireshark applies the pktap dissector and shows process
 * names. Writing 149 produces a file that reads as "DLT_USER2 -- unknown",
 * which makes the whole pcap ring feature worthless.
 */
_Static_assert(DLT_PKTAP == 149, "expected Apple DLT_PKTAP == DLT_USER2 == 149");
#define NM_LINKTYPE_PKTAP_FILE 258

struct nm_pktap_layout nm_pktap_layout(void) {
    struct nm_pktap_layout l;
    l.header_size          = (uint32_t)sizeof(struct nm_pktap_header);
    l.pcap_pkthdr_size     = (uint32_t)sizeof(struct pcap_pkthdr);
    l.dlt_pktap_live       = (uint32_t)DLT_PKTAP;
    l.linktype_pktap_file  = NM_LINKTYPE_PKTAP_FILE;
    l.maxcomlen            = (uint32_t)MAXCOMLEN;
    l.ifxnamesize          = (uint32_t)NM_PKTAP_IFXNAMESIZE;
    return l;
}
