//
//  TCPStateMachine.swift
//
//  Derives Zeek's `conn_state` and `history` from the flags we observe.
//
//  These two fields are what make a connection log worth querying. "Which
//  processes are talking to hosts that never answer" is `state = 'S0'`; "what
//  got refused" is `REJ`; a stealth scan is `SH`. Reducing all of that to
//  "connected / not connected" throws away most of the diagnostic value.
//
//  We are a passive observer, so this is NOT the TCP state machine an endpoint
//  runs. It is a record of what was seen, which is a different and much simpler
//  problem -- and one where being wrong should mean "OTH", never a confident
//  wrong answer.
//

import NMCore

/// Per-direction record of what has been observed.
public struct DirectionObservations: Sendable {
    public var sawSyn = false
    public var sawSynAck = false
    public var sawAck = false
    public var sawData = false
    public var sawFin = false
    public var sawRst = false
    public var sawZeroWindow = false
    public var sawRetransmit = false
    public var sawGap = false
    public var sawInconsistentFlags = false

    public var isEmpty: Bool {
        !(sawSyn || sawSynAck || sawAck || sawData || sawFin || sawRst)
    }
}

/// Accumulates connection state and the history string.
///
/// The history buffer is a fixed 64-byte inline array rather than a String.
/// Zeek has been bitten by an unbounded history: a flow that alternates states
/// can grow it without limit, which is a memory-exhaustion vector reachable by
/// anyone who can send packets.
public struct TCPStateMachine: Sendable {

    public private(set) var originator = DirectionObservations()
    public private(set) var responder = DirectionObservations()

    /// Bitmask of history letters already emitted, per direction, so each
    /// letter appears at most once per side.
    private var originatorEmitted: UInt32 = 0
    private var responderEmitted: UInt32 = 0

    private var historyBytes = [UInt8]()
    private var historyTruncated = false

    /// True once the three-way handshake has been observed.
    public private(set) var established = false
    /// True when no SYN was ever seen, so the flow was picked up mid-stream.
    public private(set) var midstream = false

    public init() {}

    // History letters. The index in this list is the bit used in the
    // already-emitted mask.
    private enum Letter: Int, CaseIterable {
        case syn = 0, synAck, ack, data, fin, rst
        case inconsistent, retransmit, zeroWindow, gap, multiFlag

        var character: UInt8 {
            switch self {
            case .syn: return UInt8(ascii: "S")
            case .synAck: return UInt8(ascii: "H")
            case .ack: return UInt8(ascii: "A")
            case .data: return UInt8(ascii: "D")
            case .fin: return UInt8(ascii: "F")
            case .rst: return UInt8(ascii: "R")
            case .inconsistent: return UInt8(ascii: "I")
            case .retransmit: return UInt8(ascii: "T")
            case .zeroWindow: return UInt8(ascii: "W")
            case .gap: return UInt8(ascii: "G")
            case .multiFlag: return UInt8(ascii: "Q")
            }
        }
    }

    private mutating func emit(_ letter: Letter, fromOriginator: Bool) {
        let bit = UInt32(1) << UInt32(letter.rawValue)
        if fromOriginator {
            guard originatorEmitted & bit == 0 else { return }
            originatorEmitted |= bit
        } else {
            guard responderEmitted & bit == 0 else { return }
            responderEmitted |= bit
        }
        guard historyBytes.count < Limits.maxHistoryCharacters else {
            historyTruncated = true
            return
        }
        // Uppercase is the originator, lowercase the responder -- Zeek's
        // convention, and worth keeping because it makes the string readable
        // at a glance.
        let c = letter.character
        historyBytes.append(fromOriginator ? c : c + 0x20)
    }

    /// Feeds one TCP segment.
    ///
    /// `isRetransmit` comes from the pktap header's PTH_FLAG_REXMIT rather than
    /// from sequence-number inference: the kernel already knows, and taking its
    /// word is both cheaper and more accurate than reconstructing it.
    public mutating func observe(flags: TCPFlags,
                                 payloadLength: Int,
                                 window: UInt16,
                                 fromOriginator: Bool,
                                 isRetransmit: Bool) {
        var d = fromOriginator ? originator : responder

        if flags.isInconsistent {
            d.sawInconsistentFlags = true
            emit(.inconsistent, fromOriginator: fromOriginator)
        }

        // A segment carrying several state-changing flags at once.
        let stateFlags = flags.intersection([.syn, .fin, .rst])
        if stateFlags.rawValue.nonzeroBitCount > 1 {
            emit(.multiFlag, fromOriginator: fromOriginator)
        }

        if flags.isSynAck {
            d.sawSynAck = true
            emit(.synAck, fromOriginator: fromOriginator)
            // A SYN-ACK from the side we called the originator means we guessed
            // orientation wrong -- for a midstream pickup, the first packet we
            // happened to see is not necessarily the initiator.
            if !fromOriginator { established = originator.sawSyn || established }
        } else if flags.isSynOnly {
            d.sawSyn = true
            emit(.syn, fromOriginator: fromOriginator)
        }

        if flags.contains(.rst) {
            d.sawRst = true
            emit(.rst, fromOriginator: fromOriginator)
        }
        if flags.contains(.fin) {
            d.sawFin = true
            emit(.fin, fromOriginator: fromOriginator)
        }
        if payloadLength > 0 {
            d.sawData = true
            emit(.data, fromOriginator: fromOriginator)
        } else if flags.contains(.ack) && !flags.contains(.syn) && !flags.contains(.fin) {
            d.sawAck = true
            emit(.ack, fromOriginator: fromOriginator)
        }
        if window == 0 && !flags.contains(.rst) && flags.contains(.ack) {
            d.sawZeroWindow = true
            emit(.zeroWindow, fromOriginator: fromOriginator)
        }
        if isRetransmit {
            d.sawRetransmit = true
            emit(.retransmit, fromOriginator: fromOriginator)
        }

        if fromOriginator { originator = d } else { responder = d }

        if originator.sawSyn && responder.sawSynAck && (originator.sawAck || originator.sawData) {
            established = true
        }
        if !originator.sawSyn && !responder.sawSynAck {
            midstream = true
        } else {
            midstream = false
        }
    }

    /// Records a gap in the sequence space -- bytes we know we did not see.
    public mutating func observeGap(fromOriginator: Bool) {
        if fromOriginator { originator.sawGap = true } else { responder.sawGap = true }
        emit(.gap, fromOriginator: fromOriginator)
    }

    public var history: String {
        String(decoding: historyBytes, as: UTF8.self)
    }

    public var wasHistoryTruncated: Bool { historyTruncated }

    /// The final `conn_state`, evaluated when the flow is finalised.
    ///
    /// Ordered most-specific first. Anything unrecognised lands on OTH rather
    /// than being forced into a nearby state.
    public var connectionState: ConnState {
        let o = originator, r = responder

        // Never saw a handshake at all: picked up mid-stream.
        if !o.sawSyn && !r.sawSynAck {
            if o.sawRst || r.sawRst { return .oth }
            return .oth
        }

        // Originator SYN, nothing meaningful back.
        if o.sawSyn && !r.sawSynAck && !r.sawRst {
            if o.sawRst { return .rstos0 }              // SYN then RST from the originator
            if o.sawFin { return .sh }                  // SYN then FIN: stealth-scan shape
            return .s0
        }

        // Originator SYN answered with RST: refused.
        if o.sawSyn && !r.sawSynAck && r.sawRst { return .rej }

        // Responder SYN-ACK without ever seeing the originator's SYN.
        if !o.sawSyn && r.sawSynAck {
            if r.sawRst { return .rstrh }
            if r.sawFin { return .shr }
            return .oth
        }

        // Handshake seen. Classify how it ended.
        if o.sawRst { return .rsto }
        if r.sawRst { return .rstr }
        if o.sawFin && r.sawFin { return .sf }
        if o.sawFin { return .s2 }
        if r.sawFin { return .s3 }
        return established ? .s1 : .s1
    }
}

/// UDP and other connectionless protocols get a much simpler treatment: one
/// direction seen is S0, both is SF. That matches Zeek and is genuinely all the
/// information a datagram protocol offers.
public struct DatagramState: Sendable {
    public private(set) var originatorSeen = false
    public private(set) var responderSeen = false
    private var historyBytes = [UInt8]()

    public init() {}

    public mutating func observe(fromOriginator: Bool, payloadLength: Int) {
        if fromOriginator {
            if !originatorSeen {
                originatorSeen = true
                historyBytes.append(UInt8(ascii: "D"))
            }
        } else if !responderSeen {
            responderSeen = true
            historyBytes.append(UInt8(ascii: "d"))
        }
    }

    public var connectionState: ConnState {
        originatorSeen && responderSeen ? .sf : .s0
    }

    public var history: String { String(decoding: historyBytes, as: UTF8.self) }
}
