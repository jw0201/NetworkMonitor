//
//  FlowTable.swift
//
//  The flow arena, its index, and O(1) expiry.
//
//  Structure: a Dictionary from FlowKey to an INDEX into a contiguous array of
//  entries, not a Dictionary of entries. A FlowEntry is a few hundred bytes, and
//  a Dictionary of them memcpys every entry on every rehash. The arena also
//  gives stable indices, which the expiry wheel's intrusive linked lists need.
//
//  Expiry is a timing wheel rather than a periodic scan. With a quarter of a
//  million flows, scanning the table for expired entries every second is a
//  quarter-million pointless comparisons per second; a wheel is one unlink and
//  one relink per packet and a walk of only the slots that actually came due.
//
//  The memory bounds are not decoration. A SYN flood creates flows as fast as
//  packets arrive, so "grow as needed" means "the attacker chooses how much RAM
//  this daemon uses".
//

import NMCore

public struct FlowEntry: Sendable {
    public var key: FlowKey
    public var uid: FlowID

    /// True when the originator is the endpoint stored as "low" in the key.
    /// The key sorts its endpoints so both directions hash alike; this is how
    /// orientation is recovered.
    public var originatorIsLow: Bool

    public var firstSeen: Timestamp
    public var lastSeen: Timestamp

    public var originatorPackets: Int64 = 0
    public var originatorPayloadBytes: Int64 = 0
    public var originatorIPBytes: Int64 = 0
    public var responderPackets: Int64 = 0
    public var responderPayloadBytes: Int64 = 0
    public var responderIPBytes: Int64 = 0
    public var missedBytes: Int64 = 0

    public var tcp = TCPStateMachine()
    public var datagram = DatagramState()

    // Process attribution, latched from the first packet that carries one.
    public var pid: Int32 = 0
    public var processName: String = ""
    public var effectivePID: Int32 = 0
    public var effectiveProcessName: String = ""
    public var uuidHi: UInt64 = 0
    public var uuidLo: UInt64 = 0
    public var attributionLatched = false
    public var promotedOnce = false
    public var wasDelegated = false

    /// Loss epoch at the flow's first and last packet. If they differ, packets
    /// were dropped somewhere in this flow's lifetime and its byte counts are
    /// approximate. This is the packet-level analogue of Zeek's missed_bytes
    /// and it is what keeps the numbers honest.
    public var lossEpochAtStart: UInt64 = 0
    public var lossEpochAtEnd: UInt64 = 0

    public var serviceHint: String?
    public var anyClamped = false

    /// The name the connecting application asked for, resolved at flow
    /// creation so it reflects what was known at the moment of connection
    /// rather than minutes later when the flow closes.
    public var hostname: String?
    public var hostnameSource: HostnameSource = .none
    public var hostnameAmbiguous = false
    /// Enrichment is attempted at most twice -- once when the flow is created,
    /// and once more when process attribution latches, since the pid is what
    /// makes the per-process lookup possible.
    public var hostnameAttempts: UInt8 = 0

    /// pcap ring segment range: two integers instead of a row per packet.
    public var firstSegment: UInt32?
    public var lastSegment: UInt32?

    // Intrusive expiry-wheel links. -1 means unlinked.
    var wheelPrevious: Int32 = -1
    var wheelNext: Int32 = -1
    var wheelSlot: Int32 = -1
    /// Free-list link when the slot is unused.
    var nextFree: Int32 = -1
    var inUse = false

    public var captureLossSuspected: Bool { lossEpochAtStart != lossEpochAtEnd }
    public var totalPackets: Int64 { originatorPackets + responderPackets }
    public var isTCP: Bool { key.proto == TransportParser.tcp }

    init(key: FlowKey, uid: FlowID, originatorIsLow: Bool, now: Timestamp) {
        self.key = key
        self.uid = uid
        self.originatorIsLow = originatorIsLow
        self.firstSeen = now
        self.lastSeen = now
    }
}

/// Why a flow left the table. The UI distinguishes these: a flow that was
/// evicted under pressure is not the same as one that closed normally, and
/// presenting them identically would hide the fact that data was shed.
public enum FlowEndReason: Sendable {
    case closed
    case idleTimeout
    case absoluteTimeout
    case evictedUnderPressure
    case shutdown
}

public struct FlowTableStats: Sendable, Equatable {
    public var created: Int64 = 0
    public var finalized: Int64 = 0
    public var evicted: Int64 = 0
    public var active: Int = 0
    public var peakActive: Int = 0
    public var floodModeEntries: Int64 = 0
    public var nonInitialFragments: Int64 = 0
}

public final class FlowTable {

    // MARK: Configuration

    /// Hard cap on concurrent flows. At roughly 300 bytes per entry this is
    /// about 75 MB, and it is what stops a SYN flood from choosing our memory
    /// footprint for us.
    public let capacity: Int

    /// Idle timeouts, in seconds. Chosen to match how the protocols behave, not
    /// to be round numbers: 300s for established TCP matches typical NAT
    /// keepalive expectations, and DNS gets 30s because it is request/response.
    public var establishedTimeout: Int64 = 300
    public var halfOpenTimeout: Int64 = 60
    public var datagramTimeout: Int64 = 60
    public var dnsTimeout: Int64 = 30
    public var otherTimeout: Int64 = 30
    /// Grace period after a TCP close before the entry is released. Catches the
    /// final ACK, and stops a client that immediately reuses the ephemeral port
    /// from being merged into the connection that just ended.
    public var closeLingerSeconds: Int64 = 2
    /// Nothing lives longer than this. A twelve-hour SSH session that produces
    /// one record at the very end is useless for a live view, so long flows are
    /// cut and continued.
    public var absoluteMaximumSeconds: Int64 = 3600

    // MARK: Storage

    private var entries: [FlowEntry?]
    private var index: [FlowKey: Int32] = [:]
    /// Released slots, reused before growing the arena. A plain stack rather
    /// than an intrusive list: the entry is nil once released, so there is
    /// nowhere in it to store a link.
    private var freeSlots: [Int32] = []
    private var nextUID: UInt64 = 1

    // MARK: Expiry wheel
    //
    // 512 one-second slots. Every timeout above is under 512s, so a single
    // level suffices; the absolute cap is enforced separately when a flow is
    // rescheduled, which happens on every packet anyway.

    private static let wheelSlots = 512
    private var wheel: [Int32]
    private var wheelCursor: Int64 = 0

    /// Called just before a slot is reused, so side tables keyed on the slot
    /// can drop their entry. Without this the reassembly pool fills with
    /// buffers belonging to flows that ended and then refuses new ones.
    public var onSlotReleased: ((Int32) -> Void)?

    public private(set) var stats = FlowTableStats()
    public private(set) var interfaces = InterfaceTable()

    /// Set while the table is near capacity. Shortens every timeout and starts
    /// shedding the least valuable entries first.
    public private(set) var floodMode = false

    public init(capacity: Int = Limits.maxConcurrentFlows) {
        self.capacity = capacity
        self.entries = []
        self.entries.reserveCapacity(min(capacity, 8192))
        self.wheel = [Int32](repeating: -1, count: Self.wheelSlots)
    }

    public var count: Int { index.count }

    /// Visits currently-open flows, newest activity first, up to `limit`.
    ///
    /// For the live view only. Bounded because a saturated table holds a
    /// quarter of a million flows and nobody is going to read them -- the point
    /// is to show what is busy now, not to enumerate everything.
    public func forEachActive(limit: Int, _ body: (FlowEntry) -> Void) {
        var visited = 0
        for (_, slot) in index {
            guard visited < limit else { return }
            guard let entry = self[slot] else { continue }
            visited += 1
            body(entry)
        }
    }

    /// Non-initial fragments have no L4 header, so they cannot be keyed to a
    /// flow. Counted rather than silently discarded: a sudden rise in fragments
    /// is itself a signal.
    public func countNonInitialFragment() {
        stats.nonInitialFragments += 1
    }

    // MARK: - Lookup and creation

    public func interfaceIndex(for name: String) -> UInt8 {
        interfaces.index(of: name)
    }

    /// Returns the index of the flow for this key, creating it if necessary.
    /// Returns nil only when the table is full and nothing could be evicted.
    public func lookupOrCreate(key: FlowKey,
                               originatorIsLow: Bool,
                               now: Timestamp,
                               lossEpoch: UInt64,
                               finalize: (FlowEntry, FlowEndReason) -> Void) -> Int32? {
        if let existing = index[key] { return existing }

        // Hysteresis: enter flood mode at 90% and leave at 70%, so a table
        // hovering at the threshold does not flap between timeout regimes.
        if index.count >= (capacity * 9) / 10 {
            floodMode = true
        } else if floodMode && index.count < (capacity * 7) / 10 {
            floodMode = false
        }

        if index.count >= capacity {
            // Shed a large batch. Choosing victims walks the index, so a small
            // batch means walking it again almost immediately -- measured, a
            // capacity/64 batch cost more in scanning than in shedding.
            shed(target: max(1, capacity / 8), now: now, finalize)
            guard index.count < capacity else { return nil }
        }

        let slot = allocate()
        var entry = FlowEntry(key: key, uid: FlowID(raw: nextUID),
                              originatorIsLow: originatorIsLow, now: now)
        entry.lossEpochAtStart = lossEpoch
        entry.lossEpochAtEnd = lossEpoch
        entry.inUse = true
        nextUID += 1
        entries[Int(slot)] = entry
        index[key] = slot

        schedule(slot, at: now + timeout(for: entry) * Time.microsPerSecond)

        stats.created += 1
        stats.active = index.count
        stats.peakActive = max(stats.peakActive, stats.active)
        if floodMode { stats.floodModeEntries += 1 }
        return slot
    }

    public subscript(slot: Int32) -> FlowEntry? {
        get { Int(slot) < entries.count ? entries[Int(slot)] : nil }
        set { if Int(slot) < entries.count { entries[Int(slot)] = newValue } }
    }

    /// Applies `body` to a flow in place, avoiding a struct copy on the hot path.
    public func withEntry(_ slot: Int32, _ body: (inout FlowEntry) -> Void) {
        guard Int(slot) < entries.count, entries[Int(slot)] != nil else { return }
        body(&entries[Int(slot)]!)
    }

    /// Re-arms a flow's expiry after activity.
    public func touch(_ slot: Int32, now: Timestamp) {
        guard let entry = self[slot] else { return }
        unlink(slot)
        schedule(slot, at: now + timeout(for: entry) * Time.microsPerSecond)
    }

    // MARK: - Timeouts

    private func timeout(for entry: FlowEntry) -> Int64 {
        let scale: Int64 = floodMode ? 4 : 1

        if entry.isTCP {
            let state = entry.tcp.connectionState
            switch state {
            case .sf, .rsto, .rstr, .rej, .rstos0, .rstrh, .sh, .shr:
                return closeLingerSeconds
            case .s0:
                // Half-open flows are the bulk of a SYN flood and the least
                // valuable thing in the table, so they go first under pressure.
                return floodMode ? 5 : halfOpenTimeout
            default:
                return max(1, establishedTimeout / scale)
            }
        }

        if entry.key.proto == TransportParser.udp {
            let isDNS = entry.key.lowPort == 53 || entry.key.highPort == 53
                || entry.key.lowPort == 5353 || entry.key.highPort == 5353
            return max(1, (isDNS ? dnsTimeout : datagramTimeout) / scale)
        }
        return max(1, otherTimeout / scale)
    }

    // MARK: - Expiry wheel

    private func schedule(_ slot: Int32, at deadline: Timestamp) {
        let deadlineSecond = deadline / Time.microsPerSecond
        let target = Int((deadlineSecond % Int64(Self.wheelSlots) + Int64(Self.wheelSlots))
                         % Int64(Self.wheelSlots))
        entries[Int(slot)]?.wheelSlot = Int32(target)
        entries[Int(slot)]?.wheelPrevious = -1
        entries[Int(slot)]?.wheelNext = wheel[target]
        if wheel[target] >= 0 { entries[Int(wheel[target])]?.wheelPrevious = slot }
        wheel[target] = slot
    }

    private func unlink(_ slot: Int32) {
        guard let entry = self[slot], entry.wheelSlot >= 0 else { return }
        let previous = entry.wheelPrevious
        let next = entry.wheelNext
        if previous >= 0 { entries[Int(previous)]?.wheelNext = next }
        else { wheel[Int(entry.wheelSlot)] = next }
        if next >= 0 { entries[Int(next)]?.wheelPrevious = previous }
        entries[Int(slot)]?.wheelPrevious = -1
        entries[Int(slot)]?.wheelNext = -1
        entries[Int(slot)]?.wheelSlot = -1
    }

    /// Advances the wheel to `now`, finalising everything that came due.
    ///
    /// Each expired flow is handed to `finalize` and then released. The caller
    /// turns it into a record; the table does not know about storage.
    public func expire(now: Timestamp, _ finalize: (FlowEntry, FlowEndReason) -> Void) {
        let nowSecond = now / Time.microsPerSecond
        if wheelCursor == 0 { wheelCursor = nowSecond }

        // Never walk more than a full revolution: after a long stall, every
        // slot is due exactly once, and walking the elapsed seconds literally
        // would take proportionally longer the longer we were stalled.
        let elapsed = min(nowSecond - wheelCursor, Int64(Self.wheelSlots))
        guard elapsed > 0 else { return }

        for step in 0..<elapsed {
            let second = wheelCursor + step
            let slotIndex = Int((second % Int64(Self.wheelSlots) + Int64(Self.wheelSlots))
                                % Int64(Self.wheelSlots))
            var slot = wheel[slotIndex]
            while slot >= 0 {
                let next = entries[Int(slot)]?.wheelNext ?? -1
                if let entry = self[slot] {
                    let idleSeconds = (now - entry.lastSeen) / Time.microsPerSecond
                    let ageSeconds = (now - entry.firstSeen) / Time.microsPerSecond
                    let due = timeout(for: entry)

                    if ageSeconds >= absoluteMaximumSeconds {
                        release(slot, entry, .absoluteTimeout, finalize)
                    } else if idleSeconds >= due {
                        let reason: FlowEndReason =
                            entry.isTCP && entry.tcp.connectionState != .s0
                                && entry.tcp.connectionState != .s1
                            ? .closed : .idleTimeout
                        release(slot, entry, reason, finalize)
                    } else {
                        // Woken early: the flow was touched after being
                        // scheduled. Re-arm rather than finalising it.
                        unlink(slot)
                        schedule(slot, at: entry.lastSeen + due * Time.microsPerSecond)
                    }
                }
                slot = next
            }
        }
        wheelCursor = nowSecond
        stats.active = index.count
    }

    /// Finalises every remaining flow, for shutdown.
    public func drain(_ finalize: (FlowEntry, FlowEndReason) -> Void) {
        for (_, slot) in index {
            if let entry = self[slot] { finalize(entry, .shutdown) }
        }
        index.removeAll(keepingCapacity: true)
        for i in entries.indices { entries[i] = nil }
        wheel = [Int32](repeating: -1, count: Self.wheelSlots)
        freeSlots = Array(0..<Int32(entries.count))
        stats.active = 0
    }

    /// Finalises one flow immediately -- used when a TCP connection closes
    /// cleanly and there is no reason to wait for the linger period.
    public func close(_ slot: Int32, reason: FlowEndReason,
                      _ finalize: (FlowEntry, FlowEndReason) -> Void) {
        guard let entry = self[slot] else { return }
        release(slot, entry, reason, finalize)
    }

    private func release(_ slot: Int32, _ entry: FlowEntry, _ reason: FlowEndReason,
                         _ finalize: (FlowEntry, FlowEndReason) -> Void) {
        finalize(entry, reason)
        onSlotReleased?(slot)
        unlink(slot)
        index.removeValue(forKey: entry.key)
        entries[Int(slot)] = nil
        pushFree(slot)
        stats.finalized += 1
        if reason == .evictedUnderPressure { stats.evicted += 1 }
        stats.active = index.count
    }

    // MARK: - Flood mode

    /// Sheds flows when the table is full, least valuable first.
    ///
    /// Half-open flows go before anything else: a SYN flood is thousands of
    /// them and they carry almost no information. Only if that is not enough do
    /// we touch flows that actually carried data.
    @discardableResult
    public func shed(target: Int, now: Timestamp,
                     _ finalize: (FlowEntry, FlowEndReason) -> Void) -> Int {
        guard target > 0 else { return 0 }

        // Choose victims BEFORE releasing any: release() mutates `index`, and
        // mutating a Dictionary while iterating it is undefined behaviour.
        var halfOpen: [Int32] = []
        var others: [(slot: Int32, lastSeen: Timestamp)] = []
        for (_, slot) in index {
            guard let entry = self[slot] else { continue }
            if entry.isTCP && entry.tcp.connectionState == .s0 {
                halfOpen.append(slot)
                if halfOpen.count >= target { break }
            } else {
                others.append((slot, entry.lastSeen))
            }
        }

        var victims = Array(halfOpen.prefix(target))
        if victims.count < target {
            // Least recently seen first: a flow nothing has touched in a while
            // is the least costly thing to lose.
            others.sort { $0.lastSeen < $1.lastSeen }
            victims.append(contentsOf: others.prefix(target - victims.count).map(\.slot))
        }

        for slot in victims {
            guard let entry = self[slot] else { continue }
            release(slot, entry, .evictedUnderPressure, finalize)
        }
        return victims.count
    }

    // MARK: - Arena

    private func allocate() -> Int32 {
        if let slot = freeSlots.popLast() { return slot }
        entries.append(nil)
        return Int32(entries.count - 1)
    }

    private func pushFree(_ slot: Int32) {
        freeSlots.append(slot)
    }
}
