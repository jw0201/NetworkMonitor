/*
 * CPktap.h -- hand-declared PKTAP structures plus Apple's real pcap headers.
 *
 * macOS exposes per-packet process attribution through the `pktap` pseudo
 * interface: every captured packet is prefixed by a metadata header naming the
 * pid, process name and Mach-O UUID of the socket owner. That is the whole
 * reason this project can attribute traffic to applications without a
 * NetworkExtension entitlement.
 *
 * The catch: net/pktap.h is NOT shipped in the macOS SDK. The structure below
 * is reconstructed from XNU and from tcpdump's print-pktap.c. Every field
 * offset is pinned by a _Static_assert in shim.c so a layout mistake is a
 * build error rather than silently garbled packet data.
 *
 * Two rules that are not negotiable:
 *
 *   1. Never use sizeof(struct nm_pktap_header) to find the inner frame.
 *      Always use the wire's pth_length. Older macOS shipped shorter variants
 *      and future ones may append fields.
 *
 *   2. Never redeclare struct pcap_pkthdr in Swift. Apple's version carries a
 *      trailing char comment[256], making it 280 bytes rather than the 24 that
 *      every portable libpcap tutorial assumes.
 */

#ifndef NM_CPKTAP_H
#define NM_CPKTAP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>      /* MAXCOMLEN == 16 */
#include <uuid/uuid.h>
#include <net/bpf.h>
#include <net/if_types.h>   /* IFT_LOOP, IFT_PKTAP, IFT_ETHER */
#include <pcap/pcap.h>
#include <pcap/dlt.h>     /* DLT_PKTAP -- pcap.h pulls in pcap/bpf.h, not dlt.h */

#define NM_PKTAP_IFXNAMESIZE 24

/* ------------------------------------------------------------------------ */
/* PKTAP v1 header -- what the kernel emits unless v2 is explicitly opted in */
/* ------------------------------------------------------------------------ */

struct nm_pktap_header {
    uint32_t pth_length;                    /*   0  size of THIS header */
    uint32_t pth_type_next;                 /*   4  NM_PTH_TYPE_* */
    uint32_t pth_dlt;                       /*   8  DLT of the inner frame */
    char     pth_ifname[NM_PKTAP_IFXNAMESIZE]; /* 12  e.g. "en0" */
    uint32_t pth_flags;                     /*  36  NM_PTH_FLAG_* */
    uint32_t pth_protocol_family;           /*  40  PF_INET == 2, PF_INET6 == 30 */
    uint32_t pth_frame_pre_length;          /*  44  link header bytes before L3 */
    uint32_t pth_frame_post_length;         /*  48  trailer bytes after L3 */
    pid_t    pth_pid;                       /*  52  socket-owning pid */
    char     pth_comm[MAXCOMLEN + 1];       /*  56  process name (17 bytes) */
    uint32_t pth_svc;                       /*  76  SO_TRAFFIC_CLASS */
    uint16_t pth_iftype;                    /*  80  IFT_ETHER / IFT_LOOP / ... */
    uint16_t pth_ifunit;                    /*  82 */
    pid_t    pth_epid;                      /*  84  EFFECTIVE pid (delegation) */
    char     pth_ecomm[MAXCOMLEN + 1];      /*  88  effective process name */
    uint32_t pth_flowid;                    /* 108  kernel flow id */
    uint32_t pth_ipproto;                   /* 112  IPPROTO_TCP / UDP */
    struct timeval32 pth_tstamp;            /* 116 */
    uuid_t   pth_uuid;                      /* 124  Mach-O UUID of pth_pid */
    uuid_t   pth_euuid;                     /* 140  Mach-O UUID of pth_epid */
};                                          /* 156 */

/* The smallest historically-shipped v1 header: everything through pth_epid and
 * pth_ecomm, without flowid/ipproto/tstamp/uuids. A header shorter than this is
 * rejected outright. */
#define NM_PKTAP_MIN_HDR_LEN 108

#define NM_PTH_TYPE_NONE   0
#define NM_PTH_TYPE_PACKET 1
#define NM_PTH_TYPE_DROP   2    /* kernel is reporting dropped packets, not a frame */

/*
 * Flag bits.
 *
 * DIR_IN and DIR_OUT are VERIFIED against live kernel output on macOS 26.6.2.
 * `nmcapd --self-test` correlated 20 live packets against this host's own
 * interface addresses and split cleanly:
 *
 *     flags & 0x3 == 0x1 :  0 local-source,  9 remote-source  -> INBOUND
 *     flags & 0x3 == 0x2 : 11 local-source,  0 remote-source  -> OUTBOUND
 *
 * That matters because XNU's own comments on these two macros are transposed
 * relative to their names, so the header is not trustworthy on its own.
 *
 * The REMAINING values below are still reconstructions. Apple's tcpdump prints
 * short mnemonics for some of them ("so" alongside every socket-attributed
 * packet, "ka" for keep-alives), which is the lever for verifying each one:
 * capture with `tcpdump -k`, then compare against the raw flag word.
 */
#define NM_PTH_FLAG_DIR_IN         0x0001
#define NM_PTH_FLAG_DIR_OUT        0x0002
#define NM_PTH_FLAG_PROC_DELEGATED 0x0004
#define NM_PTH_FLAG_IF_DELEGATED   0x0008
#define NM_PTH_FLAG_KEEP_ALIVE     0x0010
#define NM_PTH_FLAG_SOCKET         0x0020
#define NM_PTH_FLAG_NEXUS_CHAN     0x0040
#define NM_PTH_FLAG_V2_HDR         0x0080
#define NM_PTH_FLAG_NEW_FLOW       0x0100
#define NM_PTH_FLAG_REXMIT         0x0200
#define NM_PTH_FLAG_WAKE_PKT       0x0400

/* ------------------------------------------------------------------------ */
/* PKTAP v2 header -- compact, offset-table layout.                          */
/*                                                                          */
/* We never call pcap_set_pktap_hdr_v2, so the kernel gives us v1. This is   */
/* decoded anyway so that a future macOS flipping the default degrades to a  */
/* logged warning instead of total blindness.                                */
/* ------------------------------------------------------------------------ */

struct nm_pktap_v2_hdr {
    uint8_t  pth_length;
    uint8_t  pth_uuid_offset;
    uint8_t  pth_e_uuid_offset;
    uint8_t  pth_ifname_offset;
    uint8_t  pth_comm_offset;
    uint8_t  pth_e_comm_offset;
    uint16_t pth_dlt;
    uint16_t pth_frame_pre_length;
    uint16_t pth_frame_post_length;
    uint16_t pth_iftype;
    uint16_t pth_ipproto;
    uint32_t pth_protocol_family;
    uint32_t pth_svc;
    uint32_t pth_flowid;
    pid_t    pth_pid;
    pid_t    pth_e_pid;
    uint32_t pth_flags;
};

/* ------------------------------------------------------------------------ */
/* libpcap symbols Apple exports but does not declare in the public headers. */
/* Verified present in libpcap.A.tbd. Declared here so we can call them;      */
/* each call site must tolerate their absence on other systems.               */
/* ------------------------------------------------------------------------ */

int  pcap_set_want_pktap(pcap_t *, int);
int  pcap_set_pktap_hdr_v2(pcap_t *, int);
int  pcap_setup_pktap_interface(const char *, char *);
void pcap_cleanup_pktap_interface(const char *);
int  pcap_set_head_drop(pcap_t *, int);

/* ------------------------------------------------------------------------ */
/* Layout self-description, for runtime verification against a live capture. */
/* ------------------------------------------------------------------------ */

struct nm_pktap_layout {
    uint32_t header_size;       /* expected sizeof(struct nm_pktap_header) */
    uint32_t pcap_pkthdr_size;  /* Apple's, including comment[256] */
    uint32_t dlt_pktap_live;    /* DLT value on a live handle (149 on Darwin) */
    uint32_t linktype_pktap_file; /* what MUST be written into a savefile (258) */
    uint32_t maxcomlen;
    uint32_t ifxnamesize;
};

struct nm_pktap_layout nm_pktap_layout(void);

#endif /* NM_CPKTAP_H */
