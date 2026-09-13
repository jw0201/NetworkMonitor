import CPktap

/// Prints what the build actually compiled, so a layout question can be settled
/// without a debugger and without root.
func printLayout() -> Int32 {
    let l = nm_pktap_layout()
    print("""
    struct nm_pktap_header   \(l.header_size) bytes
    struct pcap_pkthdr       \(l.pcap_pkthdr_size) bytes
    DLT_PKTAP (live handle)  \(l.dlt_pktap_live)
    LINKTYPE_PKTAP (file)    \(l.linktype_pktap_file)
    MAXCOMLEN                \(l.maxcomlen)
    PKTAP_IFXNAMESIZE        \(l.ifxnamesize)

    A savefile MUST record linktype \(l.linktype_pktap_file), not \(l.dlt_pktap_live).
    Writing \(l.dlt_pktap_live) yields a file Wireshark reads as "DLT_USER2 - unknown",
    which loses the per-packet process names that are the point of PKTAP.
    """)
    return 0
}
