import Darwin
import Foundation

// Top-level await requires an async context; main.swift provides one.
let args = CommandLine.arguments

func usage() -> Never {
    print("""
    nmcapd -- NetworkMonitor capture daemon

    USAGE
      nmcapd --self-test [count] [secs]
                                   Decode live pktap packets and print the fields,
                                   plus an empirical calibration of the direction
                                   flag. Requires root. Diff against:
                                     sudo tcpdump -i pktap,all -k -n
      nmcapd --bench-flows [flows] [pkts]
                                   Benchmark the flow engine in memory, and
                                   verify the table stays bounded under a flood.
      nmcapd --bench [rate] [secs]  Benchmark the storage layer against synthetic
                                   traffic. No root, no packets. `rate` is conn
                                   rows per minute (default 5000), `secs` is how
                                   much simulated traffic to generate (default 60).
      nmcapd --replay <file> [n]   Decode a saved pktap capture. NO ROOT NEEDED.
                                   Produce the file once with:
                                     sudo tcpdump -i pktap,all -c 200 -w /tmp/pktap.pcap
      nmcapd --make-fixture <f> [n] Write a synthetic pktap capture, for testing
                                   --replay without any privileges.
      nmcapd --flows [secs]        Capture live and print a conn.log-style table
                                   of conversations with the process that owned
                                   each one. Requires root.
      nmcapd --flows-file <f>      The same, over a saved capture. NO ROOT NEEDED.
      nmcapd --ingest <f> [dbdir]  Run a saved capture through the whole pipeline
                                   into a real database. NO ROOT NEEDED.
      nmcapd --live [secs] [--capture]
                                   Run the live pipeline and render it through
                                   the real XPC path. Synthetic traffic unless
                                   --capture is given (which needs root).
      nmcapd --store-info <dir> [--run-retention]
                                   Show partitions, sizes, the retention policy
                                   and a projection. Deletes nothing unless
                                   --run-retention is given.
      nmcapd --layout              Print the compiled-in struct layout and exit.
      nmcapd --help
    """)
    exit(2)
}

switch args.dropFirst().first {
case "--self-test":
    let count = Int32(args.dropFirst(2).first.flatMap(Int.init) ?? 20)
    let wait = args.dropFirst(3).first.flatMap(Double.init) ?? 15
    exit(runSelfTest(packetCount: count, waitSeconds: wait))

case "--replay":
    guard let file = args.dropFirst(2).first else {
        print("--replay needs a capture file path\n")
        usage()
    }
    let rows = args.dropFirst(3).first.flatMap(Int.init) ?? 20
    exit(runReplay(path: file, printRows: rows))

case "--make-fixture":
    guard let out = args.dropFirst(2).first else {
        print("--make-fixture needs an output path\n")
        usage()
    }
    exit(makeFixture(path: out, packets: args.dropFirst(3).first.flatMap(Int.init) ?? 60))

case "--flows":
    let secs = args.dropFirst(2).first.flatMap(Double.init) ?? 20
    exit(runFlowsLive(seconds: secs, limit: 30))

case "--flows-file":
    guard let file = args.dropFirst(2).first else {
        print("--flows-file needs a capture file path\n")
        usage()
    }
    exit(runFlowsFromFile(path: file, limit: 30))

case "--ingest":
    guard let file = args.dropFirst(2).first else {
        print("--ingest needs a capture file path\n")
        usage()
    }
    exit(await runIngest(path: file, databaseRoot: args.dropFirst(3).first))

case "--live":
    let secs = args.dropFirst(2).first.flatMap(Double.init) ?? 15
    exit(await runLiveMode(seconds: secs, useCapture: args.contains("--capture")))

case "--store-info":
    guard let dir = args.dropFirst(2).first else {
        print("--store-info needs a store directory\n")
        usage()
    }
    exit(await runStoreInfo(root: dir,
                            applyRetention: args.contains("--run-retention")))

case "--bench-flows":
    let flows = args.dropFirst(2).first.flatMap(Int.init) ?? 4_000
    let count = args.dropFirst(3).first.flatMap(Int.init) ?? 2_000_000
    exit(runFlowBenchmark(flows: flows, packets: count))

case "--bench":
    let rate = args.dropFirst(2).first.flatMap(Int.init) ?? 5_000
    let secs = args.dropFirst(3).first.flatMap(Int.init) ?? 60
    exit(await runBenchmark(connsPerMinute: rate, seconds: secs))

case "--layout":
    exit(printLayout())

case "--help", "-h", .none:
    usage()

case .some(let unknown):
    print("unknown option: \(unknown)\n")
    usage()
}
