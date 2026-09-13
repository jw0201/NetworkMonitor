//
//  StreamBuffer.swift
//
//  Just enough TCP reassembly, and deliberately no more.
//
//  Full reassembly -- out-of-order queues, overlap resolution, the whole TCP
//  evasion literature -- is a large body of subtle code and a large attack
//  surface. What the analyzers actually need is narrower: the first K bytes of
//  each direction, in order, with an explicit flag when in-order-ness was lost.
//  That one mechanism covers a ClientHello spanning two or three segments, a
//  TLS 1.2 certificate chain spanning many, and the "first N bytes of payload"
//  product requirement.
//
//  Overlaps resolve to FIRST-SEEN bytes. That is the conservative, BSD-like
//  policy, and it matters because it is also what macOS itself does -- so our
//  view of a stream matches the endpoint's view rather than diverging from it,
//  which is exactly the divergence TCP evasion attacks exploit.
//
//  Buffers live in a side pool rather than in FlowEntry. A quarter of a million
//  flow entries each carrying an 8 KB buffer would be two gigabytes; only flows
//  an analyzer has attached to get one, and the pool is capped so a flood that
//  creates flows cannot reach this budget at all.
//

import NMCore

public struct StreamDirection: Sendable {
    /// Sequence number the next in-order byte should carry.
    public private(set) var expectedSequence: UInt32 = 0
    public private(set) var initialised = false
    public private(set) var bytes: [UInt8] = []
    /// Offset at which the stream stopped being contiguous, if it did.
    public private(set) var gapAt: Int?
    /// Bytes known to be missing. Feeds the conn record's missed_bytes.
    public private(set) var missedBytes: Int64 = 0
    /// The buffer filled up. Not an error -- the analyzers only need a prefix.
    public private(set) var full = false

    public var hasGap: Bool { gapAt != nil }
    public var count: Int { bytes.count }

    /// Result of offering a segment.
    public enum Outcome: Sendable, Equatable {
        case appended(Int)
        /// Wholly or partly already seen. First-seen bytes are kept.
        case duplicate
        /// A hole opened; buffering for this direction stops here.
        case gap(missing: Int)
        case ignored
    }

    mutating func accept(sequence: UInt32, payload: UnsafeRawBufferPointer,
                         limit: Int) -> Outcome {
        guard !payload.isEmpty else { return .ignored }

        if !initialised {
            expectedSequence = sequence
            initialised = true
            bytes.reserveCapacity(min(limit, 2048))
        }

        // Once a gap opens, the rest of this direction is untrustworthy and
        // buffering stops. An analyzer that gets a truncated prefix knows it;
        // one that gets a silently spliced stream does not.
        if gapAt != nil || full { return .ignored }

        // Sequence numbers wrap, so compare as a signed difference rather than
        // with < or >. At 2^32 bytes a wrap happens on any long-lived transfer.
        let delta = Int32(bitPattern: sequence &- expectedSequence)

        if delta > 0 {
            let missing = Int(delta)
            gapAt = bytes.count
            missedBytes += Int64(missing)
            return .gap(missing: missing)
        }

        if delta < 0 {
            // Retransmission or overlap. Keep what was seen first and take only
            // the tail that is genuinely new.
            let alreadySeen = Int(-delta)
            guard alreadySeen < payload.count else { return .duplicate }
            let newBytes = payload.count - alreadySeen
            let appended = append(payload.suffix(newBytes), limit: limit)
            expectedSequence = expectedSequence &+ UInt32(newBytes)
            return appended > 0 ? .appended(appended) : .duplicate
        }

        let appended = append(payload, limit: limit)
        expectedSequence = expectedSequence &+ UInt32(payload.count)
        return .appended(appended)
    }

    private mutating func append<S: Sequence>(_ source: S, limit: Int) -> Int
    where S.Element == UInt8 {
        let room = limit - bytes.count
        guard room > 0 else { full = true; return 0 }
        var added = 0
        for byte in source {
            if added >= room { full = true; break }
            bytes.append(byte)
            added += 1
        }
        return added
    }

    public mutating func reset() {
        expectedSequence = 0
        initialised = false
        bytes.removeAll(keepingCapacity: true)
        gapAt = nil
        full = false
    }
}

/// Per-flow reassembly buffers, bounded.
///
/// The cap is what makes this safe under load: flows are created at packet
/// rate under a scan, but only analyzer-attached flows reach the pool, and the
/// pool refuses to grow past its limit rather than letting an attacker choose
/// how much memory reassembly uses.
public final class ReassemblyPool {

    public struct Pair {
        public var originator = StreamDirection()
        public var responder = StreamDirection()
    }

    private var buffers: [Int32: Pair] = [:]
    public let capacity: Int
    public let bytesPerDirection: Int

    public private(set) var refusedForCapacity: Int64 = 0

    public init(capacity: Int = Limits.maxReassemblyFlows,
                bytesPerDirection: Int = Limits.reassemblyBufferBytes) {
        self.capacity = capacity
        self.bytesPerDirection = bytesPerDirection
    }

    public var count: Int { buffers.count }

    /// Offers a segment. Returns the cumulative in-order bytes for that
    /// direction, or nil when there is nothing new to look at.
    @discardableResult
    public func accept(slot: Int32, fromOriginator: Bool,
                       sequence: UInt32,
                       payload: UnsafeRawBufferPointer) -> StreamDirection.Outcome {
        if buffers[slot] == nil {
            guard buffers.count < capacity else {
                refusedForCapacity += 1
                return .ignored
            }
            buffers[slot] = Pair()
        }

        var pair = buffers[slot]!
        let outcome: StreamDirection.Outcome
        if fromOriginator {
            outcome = pair.originator.accept(sequence: sequence, payload: payload,
                                             limit: bytesPerDirection)
        } else {
            outcome = pair.responder.accept(sequence: sequence, payload: payload,
                                            limit: bytesPerDirection)
        }
        buffers[slot] = pair
        return outcome
    }

    public func direction(slot: Int32, fromOriginator: Bool) -> StreamDirection? {
        guard let pair = buffers[slot] else { return nil }
        return fromOriginator ? pair.originator : pair.responder
    }

    /// Runs `body` over the cumulative in-order bytes without copying them out.
    public func withBytes<R>(slot: Int32, fromOriginator: Bool,
                             _ body: (ByteReader) -> R) -> R? {
        guard let direction = direction(slot: slot, fromOriginator: fromOriginator),
              !direction.bytes.isEmpty else { return nil }
        return direction.bytes.withUnsafeBytes { buffer in
            guard let reader = ByteReader(buffer) else { return nil }
            return body(reader)
        }
    }

    public func release(slot: Int32) {
        buffers.removeValue(forKey: slot)
    }

    public func removeAll() {
        buffers.removeAll(keepingCapacity: true)
    }
}
