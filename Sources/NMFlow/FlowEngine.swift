//
//  FlowEngine.swift
//
//  Packet in, connection record out.
//
//  Everything here runs on one thread and the types it owns are deliberately
//  NOT Sendable, so the compiler prevents them being shared. That is stricter
//  than wrapping them in an actor and it costs nothing at runtime -- an actor
//  would put a suspension point on the per-packet path, which at hundreds of
//  thousands of packets per second is the entire budget.
//

import NMCore

public struct EngineStats: Sendable, Equatable {
    public var packets: Int64 = 0
    public var bytes: Int64 = 0
    public var parseFailures: Int64 = 0
    public var nonIPPackets: Int64 = 0
    public var loopbackDeduplicated: Int64 = 0
    public var unknownDirection: Int64 = 0
    public var unattributed: Int64 = 0
    public var recordsEmitted: Int64 = 0
    public var droppedNoCapacity: Int64 = 0
    public var analyzerInvocations: Int64 = 0
    public var analyzerDetached: Int64 = 0
}

public final class FlowEngine {

    public let table: FlowTable
    public private(set) var stats = EngineStats()

    /// Called for every finalised flow. The engine knows nothing about storage.
    public var onConnectionRecord: ((ConnRecord, FlowEndReason) -> Void)?
    /// Application-layer records produced by analyzers.
    public var onDNSRecord: ((DNSRecord) -> Void)?
    public var onSSLRecord: ((SSLRecord) -> Void)?
    /// A hostname learned for an address. Wired to the enrichment cache.
    public var onResolvedName: ((IPAddress, String, UInt32, Int32) -> Void)?

    /// Application-layer analyzers, dispatched by protocol and port.
    public let analyzers = AnalyzerRegistry()

    /// Incremented by the capture layer whenever packets are dropped.
    public var lossEpoch: UInt64 = 0

    private var lastExpiryCheck: Timestamp = 0
    private var lastAnalyzerTick: Timestamp = 0
    /// Flows an analyzer has detached from, so a `notMine` verdict is not
    /// re-evaluated on every subsequent packet of the same flow.
    private var detachedFlows: Set<UInt64> = []

    /// Shed flows are aggregated rather than emitted individually.
    ///
    /// Emitting one record per evicted flow is wrong twice over: it buries the
    /// log under near-identical rows exactly when something interesting is
    /// happening, and the per-record work becomes the bottleneck precisely when
    /// the engine is already under pressure.
    private struct EvictionKey: Hashable {
        var pid: Int32
        var responderHi: UInt64
        var responderLo: UInt64
        var responderPort: UInt16
        var state: ConnState
        var proto: UInt8
    }

    private struct EvictionAggregate {
        var record: ConnRecord
        var count: Int
    }

    private var evictionAggregates: [EvictionKey: EvictionAggregate] = [:]
    /// Bounded: a scan across a wide address range produces many distinct keys,
    /// so the aggregate itself needs a cap or it just moves the problem.
    private static let maxEvictionAggregates = 4096

    /// Proxy processes whose attribution should be superseded when the kernel
    /// later names a real application. Traffic these carry belongs to someone
    /// else, and showing "nsurlsessiond used 2 GB" is useless to a user.
    private static let proxyProcesses: Set<String> = [
        "nsurlsessiond", "mDNSResponder", "trustd", "apsd", "kernel_task",
        "networkserviceproxy", "symptomsd",
    ]

    public init(table: FlowTable = FlowTable()) {
        self.table = table
    }

    // MARK: - Packet path

    /// Processes one packet. `reader` must be scoped to the captured L3 bytes.
    public func process(_ context: PacketContext, l3 reader: inout ByteReader) {
        stats.packets += 1

        let l3: L3Info
        do {
            l3 = try IPParser.parse(&reader)
        } catch {
            stats.nonIPPackets += 1
            return
        }

        // A non-initial fragment has no L4 header, so it cannot start or be
        // keyed to a flow. Counting it would need reassembly state that is not
        // worth its attack surface here; it is counted as a statistic instead.
        if l3.isNonInitialFragment {
            table.countNonInitialFragment()
            return
        }

        var l4Reader = reader
        let l4: L4Info? = (try? TransportParser.parse(proto: l3.proto, &l4Reader,
                                                      availableLength: l3.payloadLength)) ?? nil

        let sourcePort = l4?.sourcePort ?? 0
        let destinationPort = l4?.destinationPort ?? 0

        let interfaceIndex = table.interfaceIndex(for: context.interfaceName)
        let key = FlowKey(addressA: l3.source, portA: sourcePort,
                          addressB: l3.destination, portB: destinationPort,
                          proto: l3.proto, interfaceIndex: interfaceIndex)

        // Orientation is decided ONCE, when the flow is created, and then read
        // back from the entry. Recomputing it per packet would make every
        // packet look like it came from the originator, because the guess for a
        // lone packet is always "the sender is the initiator" -- which silently
        // collapses a conversation's two directions into one.
        let sourceIsLow = key.isLowEndpoint(address: l3.source, port: sourcePort)
        var initialOriginatorIsLow = sourceIsLow
        if let info = l4, l3.proto == TransportParser.tcp {
            // The handshake names the initiator unambiguously: a SYN-ACK means
            // the SENDER is the responder.
            if info.flags.isSynAck { initialOriginatorIsLow = !sourceIsLow }
            else if info.flags.isSynOnly { initialOriginatorIsLow = sourceIsLow }
        }

        guard let slot = table.lookupOrCreate(key: key,
                                              originatorIsLow: initialOriginatorIsLow,
                                              now: context.timestamp,
                                              lossEpoch: lossEpoch,
                                              finalize: { [weak self] entry, reason in
                                                  self?.emit(entry, reason)
                                              }) else {
            stats.droppedNoCapacity += 1
            return
        }

        // Loopback is tapped twice by the kernel, once per endpoint. Counting
        // both doubles every localhost byte, so only the outbound copy is
        // counted -- but BOTH are fed to the state machine, so a handshake is
        // not missed when one copy is dropped.
        let countBytes = !(context.isLoopback && context.direction == .inbound)
        if !countBytes { stats.loopbackDeduplicated += 1 }
        if context.direction == .unknown { stats.unknownDirection += 1 }

        // Read orientation back from the flow, not from this packet.
        guard let flowOriginatorIsLow = table[slot]?.originatorIsLow else { return }
        let fromOriginator = (sourceIsLow == flowOriginatorIsLow)

        table.withEntry(slot) { entry in
            entry.lastSeen = context.timestamp
            entry.lossEpochAtEnd = lossEpoch
            if l3.clamped { entry.anyClamped = true }

            if countBytes {
                if fromOriginator {
                    entry.originatorPackets += 1
                    entry.originatorIPBytes += Int64(l3.ipBytes)
                    entry.originatorPayloadBytes += Int64(l4?.payloadLength ?? l3.payloadLength)
                } else {
                    entry.responderPackets += 1
                    entry.responderIPBytes += Int64(l3.ipBytes)
                    entry.responderPayloadBytes += Int64(l4?.payloadLength ?? l3.payloadLength)
                }
            }

            if let info = l4 {
                switch l3.proto {
                case TransportParser.tcp:
                    entry.tcp.observe(flags: info.flags,
                                      payloadLength: info.payloadLength,
                                      window: info.window,
                                      fromOriginator: fromOriginator,
                                      isRetransmit: context.isRetransmit)
                case TransportParser.udp:
                    entry.datagram.observe(fromOriginator: fromOriginator,
                                           payloadLength: info.payloadLength)
                default:
                    break
                }
            }

            attribute(&entry, context)

            if let segment = context.pcapSegment {
                if entry.firstSegment == nil { entry.firstSegment = segment }
                entry.lastSegment = segment
            }
        }

        // Application-layer analysis, on payload-bearing packets only.
        if let info = l4, info.payloadLength > 0, !detachedFlows.contains(entry_uid(slot)) {
            runAnalyzer(slot: slot, context: context, l3: l3, l4: info,
                        reader: reader, fromOriginator: fromOriginator,
                        key: key, sourcePort: sourcePort,
                        destinationPort: destinationPort)
        }

        stats.bytes += Int64(l3.ipBytes)
        table.touch(slot, now: context.timestamp)

        // A cleanly closed TCP connection is finalised at once rather than
        // waiting out the linger, but only once both sides have finished AND
        // the flow actually carried a handshake.
        if l3.proto == TransportParser.tcp, let entry = table[slot] {
            let state = entry.tcp.connectionState
            if state == .rsto || state == .rstr {
                table.close(slot, reason: .closed) { e, r in self.emit(e, r) }
            }
        }

        // Expiry runs at most once a second: it is cheap, but not free, and
        // there is no benefit to running it between two packets of the same
        // burst.
        if context.timestamp - lastExpiryCheck >= Time.microsPerSecond {
            lastExpiryCheck = context.timestamp
            table.expire(now: context.timestamp) { entry, reason in self.emit(entry, reason) }
        }
        if context.timestamp - lastAnalyzerTick >= Time.microsPerSecond {
            lastAnalyzerTick = context.timestamp
            tickAnalyzers(now: context.timestamp)
        }
    }

    private func entry_uid(_ slot: Int32) -> UInt64 {
        table[slot]?.uid.raw ?? 0
    }

    private func runAnalyzer(slot: Int32, context: PacketContext,
                             l3: L3Info, l4: L4Info, reader: ByteReader,
                             fromOriginator: Bool, key: FlowKey,
                             sourcePort: UInt16, destinationPort: UInt16) {
        guard let analyzer = analyzers.analyzer(proto: l3.proto,
                                                sourcePort: sourcePort,
                                                destinationPort: destinationPort) else { return }
        guard let entry = table[slot] else { return }
        guard let payload = try? reader.reader(at: l4.payloadOffset,
                                               count: l4.payloadLength) else { return }

        let analyzerContext = AnalyzerContext(
            flowUID: entry.uid, key: key, packet: context,
            fromOriginator: fromOriginator,
            sourceAddress: l3.source, sourcePort: sourcePort,
            destinationAddress: l3.destination, destinationPort: destinationPort,
            proto: l3.proto)

        stats.analyzerInvocations += 1
        var service: String?
        let verdict = analyzer.analyze(analyzerContext, payload: payload) { output in
            switch output {
            case .dns(let record): self.onDNSRecord?(record)
            case .ssl(let record): self.onSSLRecord?(record)
            case .service(let name): service = name
            case .resolvedName(let address, let name, let ttl, let pid):
                self.onResolvedName?(address, name, ttl, pid)
            }
        }

        if let service {
            table.withEntry(slot) { $0.serviceHint = service }
        }

        switch verdict {
        case .notMine, .satisfied, .failed:
            // Detaching is per flow and permanent. Re-running a misidentified
            // analyzer on every packet of a long flow would be pure waste.
            stats.analyzerDetached += 1
            if detachedFlows.count < 65_536 { detachedFlows.insert(entry.uid.raw) }
        case .wantMore:
            break
        }
    }

    private func tickAnalyzers(now: Timestamp) {
        analyzers.forEach { analyzer in
            analyzer.tick(now: now) { output in
                switch output {
                case .dns(let record): self.onDNSRecord?(record)
                case .ssl(let record): self.onSSLRecord?(record)
                case .service: break
                case .resolvedName(let address, let name, let ttl, let pid):
                    self.onResolvedName?(address, name, ttl, pid)
                }
            }
        }
    }

    /// Finalises everything still open. For shutdown and for tests.
    public func flush() {
        table.drain { entry, reason in self.emit(entry, reason) }
        flushEvictionAggregates()
        detachedFlows.removeAll(keepingCapacity: true)
    }

    /// Drives analyzer maintenance without a packet to trigger it, so an
    /// unanswered DNS query is reported even if traffic stops entirely.
    public func tick(now: Timestamp) {
        tickAnalyzers(now: now)
    }

    /// Emits the accumulated shed-flow summaries.
    public func flushEvictionAggregates() {
        guard !evictionAggregates.isEmpty else { return }
        for (_, aggregate) in evictionAggregates {
            var record = aggregate.record
            record.aggregatedFlows = aggregate.count
            stats.recordsEmitted += 1
            onConnectionRecord?(record, .evictedUnderPressure)
        }
        evictionAggregates.removeAll(keepingCapacity: true)
    }

    /// Runs expiry without a packet to trigger it.
    public func expire(now: Timestamp) {
        table.expire(now: now) { entry, reason in self.emit(entry, reason) }
    }

    // MARK: - Attribution

    /// Latches process attribution onto the flow.
    ///
    /// First packet with a real pid wins: re-evaluating per packet would put a
    /// branch and a write on the hot path for no benefit. Two exceptions --
    /// packets with no attribution at all are skipped until a real one arrives,
    /// and a latched PROXY is promoted once if the kernel later names the
    /// application the traffic actually belongs to.
    private func attribute(_ entry: inout FlowEntry, _ context: PacketContext) {
        guard let pid = context.pid else {
            if !entry.attributionLatched { stats.unattributed += 1 }
            return
        }

        if !entry.attributionLatched {
            entry.pid = pid
            entry.processName = context.processName
            entry.uuidHi = context.uuidHi
            entry.uuidLo = context.uuidLo
            entry.attributionLatched = true
            if let effective = context.effectivePID {
                entry.effectivePID = effective
                entry.effectiveProcessName = context.effectiveProcessName
                entry.wasDelegated = context.isDelegated
            }
            return
        }

        if !entry.promotedOnce,
           Self.proxyProcesses.contains(entry.processName),
           let effective = context.effectivePID,
           !Self.proxyProcesses.contains(context.effectiveProcessName) {
            entry.effectivePID = effective
            entry.effectiveProcessName = context.effectiveProcessName
            entry.wasDelegated = true
            entry.promotedOnce = true
        }
    }

    // MARK: - Record emission

    private func emit(_ entry: FlowEntry, _ reason: FlowEndReason) {
        detachedFlows.remove(entry.uid.raw)
        analyzers.forEach { analyzer in
            analyzer.flowClosed(entry.uid) { output in
                switch output {
                case .dns(let record): self.onDNSRecord?(record)
                case .ssl(let record): self.onSSLRecord?(record)
                case .service: break
                case .resolvedName(let address, let name, let ttl, let pid):
                    self.onResolvedName?(address, name, ttl, pid)
                }
            }
        }
        if reason == .evictedUnderPressure {
            aggregateEviction(entry)
            return
        }
        emitRecord(entry, reason)
    }

    private func aggregateEviction(_ entry: FlowEntry) {
        let responder = entry.originatorIsLow ? entry.key.highAddress : entry.key.lowAddress
        let responderPort = entry.originatorIsLow ? entry.key.highPort : entry.key.lowPort
        let isTCP = entry.key.proto == TransportParser.tcp
        let state = isTCP ? entry.tcp.connectionState : entry.datagram.connectionState

        let key = EvictionKey(pid: entry.pid,
                              responderHi: responder.hi, responderLo: responder.lo,
                              responderPort: responderPort,
                              state: state, proto: entry.key.proto)

        if var existing = evictionAggregates[key] {
            existing.count += 1
            existing.record.origPkts += entry.originatorPackets
            existing.record.origBytes += entry.originatorPayloadBytes
            existing.record.origIPBytes += entry.originatorIPBytes
            existing.record.respPkts += entry.responderPackets
            existing.record.respBytes += entry.responderPayloadBytes
            existing.record.respIPBytes += entry.responderIPBytes
            existing.record.tsEnd = max(existing.record.tsEnd ?? 0, entry.lastSeen)
            evictionAggregates[key] = existing
            return
        }

        // At the cap, emit the whole batch rather than silently dropping the
        // new key -- a wide scan produces many distinct destinations and the
        // aggregate must not become the unbounded thing it was meant to bound.
        if evictionAggregates.count >= Self.maxEvictionAggregates {
            flushEvictionAggregates()
        }
        evictionAggregates[key] = EvictionAggregate(record: buildRecord(entry, state: state),
                                                    count: 1)
    }

    private func emitRecord(_ entry: FlowEntry, _ reason: FlowEndReason) {
        let originator = entry.originatorIsLow ? entry.key.lowAddress : entry.key.highAddress
        let originatorPort = entry.originatorIsLow ? entry.key.lowPort : entry.key.highPort
        let responder = entry.originatorIsLow ? entry.key.highAddress : entry.key.lowAddress
        let responderPort = entry.originatorIsLow ? entry.key.highPort : entry.key.lowPort

        let isTCP = entry.key.proto == TransportParser.tcp
        let state = isTCP ? entry.tcp.connectionState : entry.datagram.connectionState

        stats.recordsEmitted += 1
        onConnectionRecord?(buildRecord(entry, state: state), reason)
    }

    private func buildRecord(_ entry: FlowEntry, state: ConnState) -> ConnRecord {
        let originator = entry.originatorIsLow ? entry.key.lowAddress : entry.key.highAddress
        let originatorPort = entry.originatorIsLow ? entry.key.lowPort : entry.key.highPort
        let responder = entry.originatorIsLow ? entry.key.highAddress : entry.key.lowAddress
        let responderPort = entry.originatorIsLow ? entry.key.highPort : entry.key.lowPort

        let isTCP = entry.key.proto == TransportParser.tcp
        let history = isTCP ? entry.tcp.history : entry.datagram.history

        var record = ConnRecord(uid: entry.uid,
                                ts: entry.firstSeen,
                                proto: entry.key.proto,
                                origAddr: originator, origPort: originatorPort,
                                respAddr: responder, respPort: responderPort,
                                iface: table.interfaces.name(at: entry.key.interfaceIndex),
                                state: state,
                                history: history,
                                pid: entry.pid)
        record.tsEnd = entry.lastSeen
        record.durationUs = entry.lastSeen - entry.firstSeen
        record.origPkts = entry.originatorPackets
        record.origBytes = entry.originatorPayloadBytes
        record.origIPBytes = entry.originatorIPBytes
        record.respPkts = entry.responderPackets
        record.respBytes = entry.responderPayloadBytes
        record.respIPBytes = entry.responderIPBytes
        record.missedBytes = entry.missedBytes
        record.captureLossSuspected = entry.captureLossSuspected
        record.firstPcapSegment = entry.firstSegment
        record.lastPcapSegment = entry.lastSegment
        record.service = entry.serviceHint

        // The application, not the proxy. A user wants to see "Safari", not
        // "nsurlsessiond" -- but the proxy is preserved alongside rather than
        // discarded, because it is what the detail pane needs.
        if entry.wasDelegated && entry.effectivePID > 0 {
            record.pid = entry.effectivePID
            record.exec = ExecInfo(path: "", name: entry.effectiveProcessName,
                                   uuidHi: entry.uuidHi, uuidLo: entry.uuidLo)
            record.proxyPid = entry.pid
            record.proxyExec = ExecInfo(path: "", name: entry.processName)
        } else if entry.attributionLatched {
            record.exec = ExecInfo(path: "", name: entry.processName,
                                   uuidHi: entry.uuidHi, uuidLo: entry.uuidLo)
        }

        return record
    }
}
