//
//  SeededHash.swift
//
//  A fast, seeded 64-bit hash for the flow table, and a deterministic PRNG for
//  synthetic traffic and tests.
//
//  The seed is a SECURITY requirement, not a performance tweak. With a fixed,
//  publicly known hash function, an attacker can craft packets whose 5-tuples
//  all collide into one bucket, degrading the flow table to a linked list --
//  an algorithmic-complexity denial of service that needs very little traffic
//  to be effective. Seeding per process makes the bucket assignment
//  unpredictable and the attack impractical.
//
//  Swift's synthesized Hashable is also unsuitable here for a plainer reason:
//  it calls into SipHash once per field, which is measurable at hundreds of
//  thousands of packets per second.
//

/// SplitMix64. Small, fast, good avalanche, trivially seedable.
public struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    public init(seed: UInt64) { self.state = seed }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Per-process random seed for flow hashing. Generated once at startup from the
/// system CSPRNG.
public enum FlowHashSeed {
    nonisolated(unsafe) public static let value: UInt64 = {
        var g = SystemRandomNumberGenerator()
        return g.next()
    }()
}

/// A single-pass mixing hash over 64-bit words, seeded per process.
@inlinable
public func seededHash(_ words: UInt64..., seed: UInt64 = FlowHashSeed.value) -> UInt64 {
    var h = seed ^ 0x9E37_79B9_7F4A_7C15
    for w in words {
        h ^= w
        h = (h ^ (h >> 30)) &* 0xBF58_476D_1CE4_E5B9
        h = (h ^ (h >> 27)) &* 0x94D0_49BB_1331_11EB
        h ^= h >> 31
    }
    return h
}
