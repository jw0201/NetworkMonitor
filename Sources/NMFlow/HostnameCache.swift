//
//  HostnameCache.swift
//
//  Maps an address back to the name an application asked for.
//
//  Keyed on (requesting pid, address), not on address alone. That is the whole
//  point, and it falls out of having pktap: DNS is resolved by mDNSResponder,
//  but the pktap header on the query names the process that REQUESTED it. So
//  when Safari later connects to a CDN address, we can prefer the name Safari
//  itself looked up, even if Mail resolved the same shared address to a
//  different name two hundred milliseconds earlier.
//
//  An IP-only cache cannot distinguish those cases at all. It picks whichever
//  name was cached last and presents it as fact.
//
//  Fed by DNS today; TLS SNI and HTTP Host will feed it too, which is why this
//  lives in NMFlow under a protocol-neutral name rather than inside the DNS
//  analyzer.
//

import NMCore

public struct HostnameLookup: Sendable {
    public var name: String
    public var source: HostnameSource
    /// More than one plausible name was on file for this address at this
    /// moment. Recorded and surfaced rather than silently resolved -- admitting
    /// ambiguity beats presenting a coin flip as a fact.
    public var ambiguous: Bool
    /// The TTL the server actually gave, as opposed to the clamped lifetime we
    /// keep internally. Shown so the UI never misreports what DNS said.
    public var originalTTL: UInt32
}

public final class HostnameCache {

    /// Wildcard entries -- learned without a requesting pid, or used as the
    /// fallback when the connecting process never did its own lookup.
    public static let wildcardPID: Int32 = 0

    private struct Key: Hashable {
        var pid: Int32
        var addressHi: UInt64
        var addressLo: UInt64
    }

    private struct Entry {
        var name: String
        var insertedAt: Timestamp
        var expiresAt: Timestamp
        var originalTTL: UInt32
        var hits: UInt32
    }

    /// Candidates per key, newest first. Several names legitimately share one
    /// address, so keeping only the latest would silently discard the others.
    private var entries: [Key: [Entry]] = [:]
    private var lastSweep: Timestamp = 0

    public var capacity = Limits.dnsCacheEntries
    /// CDNs hand out five to thirty second TTLs, so honouring them literally
    /// would miss the connection that immediately follows the lookup.
    public var minimumLifetimeSeconds: Int64 = 60
    /// And an hour bounds how stale an answer can get.
    public var maximumLifetimeSeconds: Int64 = 3600
    public var maximumCandidates = Limits.maxHostnameCandidatesPerAddress

    public private(set) var stats = Stats()

    public struct Stats: Sendable, Equatable {
        public var inserted: Int64 = 0
        public var perProcessHits: Int64 = 0
        public var wildcardHits: Int64 = 0
        public var misses: Int64 = 0
        public var ambiguousHits: Int64 = 0
        public var expired: Int64 = 0
        public var evicted: Int64 = 0
    }

    public init() {}

    public var count: Int { entries.count }

    // MARK: - Insert

    public func insert(address: IPAddress, name: String, ttl: UInt32,
                       requestingPID: Int32, now: Timestamp) {
        guard !name.isEmpty, name != "." else { return }

        let clamped = min(max(Int64(ttl), minimumLifetimeSeconds), maximumLifetimeSeconds)
        let expiresAt = now + clamped * Time.microsPerSecond
        let entry = Entry(name: name, insertedAt: now, expiresAt: expiresAt,
                          originalTTL: ttl, hits: 0)

        if requestingPID > 0 {
            store(Key(pid: requestingPID, addressHi: address.hi, addressLo: address.lo), entry)
        }
        // Always store a wildcard copy as well: the process that connects is
        // often not the one that resolved, and a fallback is better than an
        // unresolved address.
        store(Key(pid: Self.wildcardPID, addressHi: address.hi, addressLo: address.lo), entry)

        stats.inserted += 1
        if entries.count > capacity { evict(now: now) }
    }

    private func store(_ key: Key, _ entry: Entry) {
        var candidates = entries[key] ?? []
        // Refresh rather than duplicate when the same name is seen again.
        if let index = candidates.firstIndex(where: { $0.name == entry.name }) {
            candidates[index].expiresAt = entry.expiresAt
            candidates[index].insertedAt = entry.insertedAt
            candidates[index].originalTTL = entry.originalTTL
            let refreshed = candidates.remove(at: index)
            candidates.insert(refreshed, at: 0)
        } else {
            candidates.insert(entry, at: 0)
            if candidates.count > maximumCandidates { candidates.removeLast() }
        }
        entries[key] = candidates
    }

    // MARK: - Lookup

    /// Resolves an address to a name as of `at`.
    ///
    /// The timestamp matters: enrichment happens at flow creation, so the
    /// answer must reflect what was known when the connection was made, not
    /// what is known when the flow finally closes minutes later.
    public func lookup(address: IPAddress, pid: Int32, at: Timestamp) -> HostnameLookup? {
        if pid > 0,
           let hit = best(Key(pid: pid, addressHi: address.hi, addressLo: address.lo), at: at) {
            stats.perProcessHits += 1
            if hit.ambiguous { stats.ambiguousHits += 1 }
            return HostnameLookup(name: hit.entry.name, source: .dnsPerProcess,
                                  ambiguous: hit.ambiguous, originalTTL: hit.entry.originalTTL)
        }

        if let hit = best(Key(pid: Self.wildcardPID,
                              addressHi: address.hi, addressLo: address.lo), at: at) {
            stats.wildcardHits += 1
            if hit.ambiguous { stats.ambiguousHits += 1 }
            return HostnameLookup(name: hit.entry.name, source: .dnsWildcard,
                                  ambiguous: hit.ambiguous, originalTTL: hit.entry.originalTTL)
        }

        stats.misses += 1
        return nil
    }

    private func best(_ key: Key, at: Timestamp) -> (entry: Entry, ambiguous: Bool)? {
        guard let candidates = entries[key] else { return nil }
        // Valid means: learned no later than the moment we are asking about,
        // and not yet expired as of that moment.
        let valid = candidates.filter { $0.insertedAt <= at && $0.expiresAt >= at }
        guard let first = valid.first else { return nil }
        let distinctNames = Set(valid.map(\.name))
        return (first, distinctNames.count > 1)
    }

    // MARK: - Maintenance

    /// Drops expired entries. Amortised: a fraction of the table per call, so
    /// there is never a stall proportional to the cache size.
    public func sweep(now: Timestamp) {
        guard now - lastSweep >= 30 * Time.microsPerSecond else { return }
        lastSweep = now

        var emptied: [Key] = []
        for (key, candidates) in entries {
            let live = candidates.filter { $0.expiresAt >= now }
            if live.count != candidates.count {
                stats.expired += Int64(candidates.count - live.count)
                if live.isEmpty { emptied.append(key) } else { entries[key] = live }
            }
        }
        for key in emptied { entries.removeValue(forKey: key) }
    }

    private func evict(now: Timestamp) {
        // Expired entries first -- they are free to lose.
        var emptied: [Key] = []
        for (key, candidates) in entries {
            let live = candidates.filter { $0.expiresAt >= now }
            if live.isEmpty { emptied.append(key) } else if live.count != candidates.count {
                entries[key] = live
            }
        }
        for key in emptied { entries.removeValue(forKey: key) }
        stats.expired += Int64(emptied.count)
        guard entries.count > capacity else { return }

        // Still over: drop the oldest tenth. Sorting the whole table would be
        // O(n log n) at exactly the moment the cache is under pressure, so this
        // takes a bounded sample instead.
        let excess = entries.count - capacity + capacity / 10
        let oldest = entries
            .map { (key: $0.key, age: $0.value.first?.insertedAt ?? 0) }
            .sorted { $0.age < $1.age }
            .prefix(excess)
        for item in oldest { entries.removeValue(forKey: item.key) }
        stats.evicted += Int64(oldest.count)
    }

    public func removeAll() {
        entries.removeAll(keepingCapacity: true)
    }
}
