//
//  Schema.swift
//
//  Four databases, each with a different lifetime. That split is the design,
//  not an implementation detail:
//
//    live.db                 today's raw records. Minimum indices, maximum
//                            write speed. Renamed to an archive at midnight.
//    archive/nm-YYYY-MM-DD.db  a sealed day. Never written again, so it can
//                            carry extra read indices at zero cost to the hot
//                            path, and it has no -wal/-shm at all.
//    meta.db                 the exec dimension, alerts, file catalog, config.
//                            Outlives every day file.
//    rollup.db               time-bucketed aggregates. The Overview screen
//                            reads ONLY from here.
//    pcap.db                 the packet ring index. Independent lifetime from
//                            the log day files.
//
//  Retention is then `unlink()` on a day file: O(1), no lock, no VACUUM, no
//  2x free-space requirement. A single database with nightly DELETE would
//  write every freed page to the WAL (a delete costs more I/O than the insert
//  did), never shrink, and if fixed with VACUUM would take an exclusive lock
//  for minutes every night on a laptop SSD.
//

import Foundation
import NMCore
import SQLite3

public enum Schema {

    /// Bumped whenever the DDL changes. Stored in `PRAGMA user_version`.
    public static let version: Int32 = 2

    // MARK: - Pragmas

    /// Applied to the writer's connection. `page_size` MUST be set before the
    /// first table is created or it is silently ignored.
    public static func configureWriter(_ db: SQLiteConnection) throws {
        try db.exec("PRAGMA page_size = 8192")
        _ = try db.pragma("journal_mode = WAL")
        try db.exec("PRAGMA synchronous = NORMAL")
        // The daemon checkpoints deliberately (at rotation, at shutdown) rather
        // than letting a checkpoint land in the middle of a write batch.
        try db.exec("PRAGMA wal_autocheckpoint = 0")
        // 16 MB, not 64. This is the size the WAL is trimmed back to AFTER a
        // checkpoint, so it is the steady-state footprint rather than a
        // ceiling on growth -- a limit above the WAL's working size never
        // fires at all.
        try db.exec("PRAGMA journal_size_limit = 16777216")
        try db.exec("PRAGMA cache_size = -32768")          // 32 MiB
        try db.exec("PRAGMA mmap_size = 268435456")        // 256 MiB (build cap is 1 GiB)
        // ENABLE_SETLK_TIMEOUT is compiled in, so this is a real blocking wait
        // rather than a retry-spin.
        try db.exec("PRAGMA busy_timeout = 5000")
        try db.exec("PRAGMA temp_store = MEMORY")
        // The writer is the only mutator; invariants are enforced in Swift,
        // where the error messages are useful.
        try db.exec("PRAGMA foreign_keys = OFF")
        // live.db only ever holds one day, so unbounded growth is bounded by
        // definition and we skip auto-vacuum's permanent per-write tax.
        try db.exec("PRAGMA auto_vacuum = NONE")
    }

    /// Applied to a read-only connection.
    public static func configureReader(_ db: SQLiteConnection) throws {
        try db.exec("PRAGMA query_only = 1")
        try db.exec("PRAGMA mmap_size = 268435456")
        try db.exec("PRAGMA busy_timeout = 5000")
        try db.exec("PRAGMA temp_store = MEMORY")
    }

    /// URI for a sealed archive.
    ///
    /// `immutable=1` is correct and safe here precisely because a sealed file
    /// is never written again: it disables locking and change detection, which
    /// measurably speeds archive queries. Using it on a live file would be a
    /// serious bug.
    public static func archiveURI(path: String) -> String {
        "file:\(path)?mode=ro&immutable=1"
    }

    // MARK: - Day partition (live.db and every archive)

    public static let dayPartitionDDL = """
    -- Connection records. Zeek's conn.log vocabulary plus macOS process
    -- attribution, which is the part Zeek cannot produce.
    CREATE TABLE IF NOT EXISTS conn (
      id            INTEGER PRIMARY KEY,   -- rowid; monotonic in INSERTION order
      uid           INTEGER NOT NULL,      -- flow id; joins to dns/ssl/payload/pcap
      ts            INTEGER NOT NULL,      -- first packet, unix micros UTC
      ts_end        INTEGER,               -- NULL while the flow is still open
      duration_us   INTEGER,

      af            INTEGER NOT NULL,      -- 2 = AF_INET, 30 = AF_INET6
      proto         INTEGER NOT NULL,      -- IPPROTO_*
      saddr         BLOB    NOT NULL,      -- native width: 4 bytes v4, 16 v6
      sport         INTEGER,
      daddr         BLOB    NOT NULL,
      dport         INTEGER,

      iface         TEXT,
      service       TEXT,                  -- inferred app protocol
      state         TEXT,                  -- Zeek conn_state
      history       TEXT,                  -- Zeek history, hard-capped at 64 chars

      opkts         INTEGER NOT NULL DEFAULT 0,
      obytes        INTEGER NOT NULL DEFAULT 0,   -- L4 payload
      oipbytes      INTEGER NOT NULL DEFAULT 0,   -- on-wire; what throughput uses
      ipkts         INTEGER NOT NULL DEFAULT 0,
      ibytes        INTEGER NOT NULL DEFAULT 0,
      iipbytes      INTEGER NOT NULL DEFAULT 0,
      missed_bytes  INTEGER NOT NULL DEFAULT 0,

      local_orig    INTEGER NOT NULL DEFAULT 0,
      local_resp    INTEGER NOT NULL DEFAULT 0,

      exec_id       INTEGER,               -- -> meta.exec(id)
      pid           INTEGER,
      puid          INTEGER,               -- owning user, for per-user filtering
      proxy_exec_id INTEGER,               -- nsurlsessiond et al, when delegated
      proxy_pid     INTEGER,

      host_id       INTEGER,               -- -> meta.name(id)
      host_src      INTEGER NOT NULL DEFAULT 0,   -- HostnameSource
      host_ambig    INTEGER NOT NULL DEFAULT 0,

      first_seg     INTEGER,               -- pcap ring segment range
      last_seg      INTEGER,
      pcap_ok       INTEGER NOT NULL DEFAULT 1,   -- cleared when segments are reclaimed

      loss          INTEGER NOT NULL DEFAULT 0    -- byte counts are approximate
    ) STRICT;

    -- Only what the dashboard actually queries. Insert throughput falls off
    -- roughly linearly with index count, and the default browser sort is
    -- `id DESC`, which is the rowid btree and therefore free.
    CREATE INDEX IF NOT EXISTS ix_conn_ts       ON conn(ts);
    CREATE INDEX IF NOT EXISTS ix_conn_exec_ts  ON conn(exec_id, ts);
    CREATE INDEX IF NOT EXISTS ix_conn_daddr_ts ON conn(daddr, ts);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_conn_uid ON conn(uid);

    CREATE TABLE IF NOT EXISTS dns (
      id        INTEGER PRIMARY KEY,
      uid       INTEGER,
      ts        INTEGER NOT NULL,
      proto     INTEGER NOT NULL,
      af        INTEGER NOT NULL,
      saddr     BLOB, sport INTEGER, daddr BLOB, dport INTEGER,
      trans_id  INTEGER,
      rtt_us    INTEGER,                   -- NULL when unanswered
      qname_id  INTEGER,                   -- -> meta.name(id); the reversed form
                                           -- lives there once, not per row
      qtype     INTEGER, qclass INTEGER, rcode INTEGER,
      dnsflags  INTEGER,
      answers   TEXT,                      -- JSON array
      ttls      TEXT,                      -- JSON array
      rejected  INTEGER NOT NULL DEFAULT 0,
      exec_id   INTEGER, pid INTEGER, puid INTEGER
    ) STRICT;

    CREATE INDEX IF NOT EXISTS ix_dns_ts    ON dns(ts);
    CREATE INDEX IF NOT EXISTS ix_dns_qname ON dns(qname_id, ts);

    CREATE TABLE IF NOT EXISTS ssl (
      id        INTEGER PRIMARY KEY,
      uid       INTEGER,
      ts        INTEGER NOT NULL,
      af        INTEGER NOT NULL,
      saddr     BLOB, sport INTEGER, daddr BLOB, dport INTEGER,
      version   INTEGER, cipher INTEGER, curve INTEGER,
      sni_id    INTEGER,                   -- -> meta.name(id)
      sni_outer INTEGER NOT NULL DEFAULT 0,   -- ECH: the visible SNI is NOT the destination
      alpn      TEXT,
      ssl_hist  TEXT,
      established INTEGER NOT NULL DEFAULT 0,
      resumed   INTEGER NOT NULL DEFAULT 0,
      fp_id     INTEGER,                   -- -> meta.fingerprint(id)
      certs_encrypted INTEGER NOT NULL DEFAULT 0,   -- TLS 1.3: cert is unavailable, not unknown
      subject   TEXT, issuer TEXT,
      not_before INTEGER, not_after INTEGER,
      chain_fps TEXT,
      exec_id   INTEGER, pid INTEGER, puid INTEGER
    ) STRICT;

    CREATE INDEX IF NOT EXISTS ix_ssl_ts  ON ssl(ts);
    CREATE INDEX IF NOT EXISTS ix_ssl_sni ON ssl(sni_id, ts);
    CREATE INDEX IF NOT EXISTS ix_ssl_fp  ON ssl(fp_id, ts);

    -- First N bytes of payload, kept OUT of the conn row so conn stays narrow
    -- and cheap to scan. Off by default; shortest retention of anything here.
    CREATE TABLE IF NOT EXISTS payload (
      uid    INTEGER NOT NULL,
      dir    INTEGER NOT NULL,            -- 0 = orig->resp, 1 = resp->orig
      nbytes INTEGER NOT NULL,            -- bytes captured
      total  INTEGER NOT NULL,            -- bytes seen, so the UI can say "512 of 2.1 MB"
      data   BLOB    NOT NULL,
      PRIMARY KEY (uid, dir)
    ) WITHOUT ROWID;
    """

    /// Extra indices built at seal time. Free, because a sealed file is never
    /// written again -- this is the main structural payoff of day partitioning.
    public static let archiveSealDDL = """
    CREATE INDEX IF NOT EXISTS ix_conn_dport   ON conn(dport, ts);
    CREATE INDEX IF NOT EXISTS ix_conn_service ON conn(service, ts);
    CREATE INDEX IF NOT EXISTS ix_conn_host    ON conn(host_id) WHERE host_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS ix_conn_state   ON conn(state, ts);
    CREATE INDEX IF NOT EXISTS ix_dns_rcode    ON dns(rcode, ts);
    CREATE INDEX IF NOT EXISTS ix_ssl_version  ON ssl(version, ts);
    """

    // MARK: - meta.db

    public static let metaDDL = """
    -- Process/binary dimension. Interned so every conn/dns/ssl row carries a
    -- small integer instead of a repeated executable path.
    CREATE TABLE IF NOT EXISTS exec (
      id          INTEGER PRIMARY KEY,
      path        TEXT    NOT NULL,
      name        TEXT    NOT NULL,
      bundle_id   TEXT,
      signing_id  TEXT,
      team_id     TEXT,
      uuid_hi     INTEGER NOT NULL DEFAULT 0,   -- Mach-O UUID from pktap
      uuid_lo     INTEGER NOT NULL DEFAULT 0,
      is_platform INTEGER NOT NULL DEFAULT 0,
      first_seen  INTEGER NOT NULL,
      last_seen   INTEGER NOT NULL
    ) STRICT;

    -- Identity is (path, Mach-O UUID, name), not path alone: the UUID is what
    -- makes pid reuse and binary updates distinguishable rather than silently
    -- conflated.
    --
    -- `name` is in the key as a safety net, and it was earned. A caller that
    -- supplies an identity with no path and no UUID -- which an analyzer did --
    -- otherwise collides with every other such caller, and one process's name
    -- lands on every other process's records. Observed live: every DNS query
    -- from Chrome was attributed to an unrelated helper.
    CREATE UNIQUE INDEX IF NOT EXISTS ux_exec_ident
        ON exec(path, uuid_hi, uuid_lo, name);
    CREATE INDEX IF NOT EXISTS ix_exec_name ON exec(name);

    -- Domain names, interned.
    --
    -- Measured: storing hostnames inline cost ~40 bytes per row across conn,
    -- dns and ssl, and storing BOTH the forward and reversed spelling doubled
    -- that. A machine contacts a few thousand distinct names, over and over --
    -- so they belong in a dimension, with the reversed form stored ONCE here.
    --
    -- host, TLS SNI and DNS query names are literally the same namespace, so
    -- they share one table. That also makes "which process resolved this name
    -- and then connected to it" a join rather than a string comparison.
    CREATE TABLE IF NOT EXISTS name (
      id         INTEGER PRIMARY KEY,
      text       TEXT NOT NULL,
      text_rev   TEXT NOT NULL,            -- "com.example.www" for suffix search
      first_seen INTEGER NOT NULL,
      last_seen  INTEGER NOT NULL
    ) STRICT;

    CREATE UNIQUE INDEX IF NOT EXISTS ux_name_text ON name(text);
    -- Suffix search is a RANGE over this index, never LIKE: measured, LIKE
    -- produces a full index SCAN (SQLite will not use an index for a LIKE
    -- prefix under the default case-insensitive collation) while
    -- `>= 'com.apple.' AND < 'com.apple/'` produces a SEARCH.
    CREATE INDEX IF NOT EXISTS ix_name_rev ON name(text_rev);

    -- TLS fingerprints, interned.
    --
    -- The single largest storage win measured: ja4 + ja4_r + ja3 inline cost
    -- ~146 bytes on EVERY ssl row, and a machine sees only a few hundred
    -- distinct fingerprints. ja4_r (the unhashed string) is kept because a
    -- fingerprint mismatch against another tool is undebuggable without it --
    -- here it costs nothing.
    CREATE TABLE IF NOT EXISTS fingerprint (
      id         INTEGER PRIMARY KEY,
      ja4        TEXT,
      ja4_r      TEXT,
      ja3        TEXT,
      ja4s       TEXT,
      ja3s       TEXT,
      first_seen INTEGER NOT NULL,
      last_seen  INTEGER NOT NULL
    ) STRICT;

    CREATE UNIQUE INDEX IF NOT EXISTS ux_fp    ON fingerprint(ja4, ja3, ja4s, ja3s);
    CREATE INDEX IF NOT EXISTS        ix_fp_ja4 ON fingerprint(ja4);

    -- Catalog of day files, so the query layer knows what exists and what time
    -- range each covers without opening them.
    CREATE TABLE IF NOT EXISTS file_catalog (
      path       TEXT PRIMARY KEY,
      day        TEXT NOT NULL,            -- "2026-09-13", UTC
      first_ts   INTEGER, last_ts INTEGER,
      bytes      INTEGER NOT NULL DEFAULT 0,
      conn_rows  INTEGER NOT NULL DEFAULT 0,
      dns_rows   INTEGER NOT NULL DEFAULT 0,
      ssl_rows   INTEGER NOT NULL DEFAULT 0,
      sealed     INTEGER NOT NULL DEFAULT 0,
      created    INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS alert_rule (
      id       TEXT PRIMARY KEY,
      enabled  INTEGER NOT NULL DEFAULT 1,
      severity INTEGER NOT NULL,
      kind     TEXT    NOT NULL,
      spec     TEXT    NOT NULL,           -- JSON: filter expression + params
      notify   INTEGER NOT NULL DEFAULT 1,
      created  INTEGER NOT NULL,
      updated  INTEGER NOT NULL
    ) STRICT;

    -- Alerts live in meta so they OUTLIVE the rows that produced them: `detail`
    -- carries a JSON snapshot, so an alert stays meaningful after its source
    -- day file has been reclaimed.
    CREATE TABLE IF NOT EXISTS alert (
      id        INTEGER PRIMARY KEY,
      ts        INTEGER NOT NULL,
      rule_id   TEXT    NOT NULL,
      severity  INTEGER NOT NULL,
      title     TEXT    NOT NULL,
      detail    TEXT,
      src_day   TEXT, src_table TEXT, src_id INTEGER,
      uid       INTEGER,
      exec_id   INTEGER, puid INTEGER,
      state     INTEGER NOT NULL DEFAULT 0,   -- 0 new, 1 acked, 2 muted
      acked_by  TEXT, acked_at INTEGER
    ) STRICT;

    CREATE INDEX IF NOT EXISTS ix_alert_ts   ON alert(ts);
    -- Partial index: the open-alert list is the hot query and this keeps the
    -- index tiny regardless of history size.
    CREATE INDEX IF NOT EXISTS ix_alert_open ON alert(ts) WHERE state = 0;

    -- System-wide configuration. The authoritative copy is config.json; this
    -- mirror lets queries and the audit trail see it.
    CREATE TABLE IF NOT EXISTS config_audit (
      id       INTEGER PRIMARY KEY,
      ts       INTEGER NOT NULL,
      key      TEXT NOT NULL,
      old_value TEXT, new_value TEXT,
      changed_by_uid INTEGER
    ) STRICT;
    """

    // MARK: - rollup.db

    /// Every Overview query reads from here and nowhere else.
    ///
    /// The benchmark on this machine measured a GROUP BY over 5M rows at 4.4
    /// seconds. One day of conn at 50k rows/minute is 72M rows, so an Overview
    /// screen backed by raw rows would take over a minute to draw. These tables
    /// are what make it instant, and they are maintained by the writer from
    /// counters it already keeps in memory -- never derived by scanning.
    public static let rollupDDL = """
    CREATE TABLE IF NOT EXISTS roll_min (
      bucket     INTEGER NOT NULL,        -- ts / 60_000_000
      exec_id    INTEGER NOT NULL,
      proto      INTEGER NOT NULL,
      iface_id   INTEGER NOT NULL,
      dir        INTEGER NOT NULL,        -- 0 = out, 1 = in
      bytes      INTEGER NOT NULL,
      pkts       INTEGER NOT NULL,
      flows_new  INTEGER NOT NULL,
      PRIMARY KEY (bucket, exec_id, proto, iface_id, dir)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS roll_hour (
      bucket     INTEGER NOT NULL,
      exec_id    INTEGER NOT NULL,
      proto      INTEGER NOT NULL,
      iface_id   INTEGER NOT NULL,
      dir        INTEGER NOT NULL,
      bytes      INTEGER NOT NULL,
      pkts       INTEGER NOT NULL,
      flows_new  INTEGER NOT NULL,
      PRIMARY KEY (bucket, exec_id, proto, iface_id, dir)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS roll_day (
      bucket     INTEGER NOT NULL,
      exec_id    INTEGER NOT NULL,
      proto      INTEGER NOT NULL,
      iface_id   INTEGER NOT NULL,
      dir        INTEGER NOT NULL,
      bytes      INTEGER NOT NULL,
      pkts       INTEGER NOT NULL,
      flows_new  INTEGER NOT NULL,
      PRIMARY KEY (bucket, exec_id, proto, iface_id, dir)
    ) WITHOUT ROWID;

    -- Top talkers, per hour.
    CREATE TABLE IF NOT EXISTS roll_peer_hour (
      bucket    INTEGER NOT NULL,
      exec_id   INTEGER NOT NULL,
      daddr     BLOB    NOT NULL,
      host      TEXT,
      bytes_out INTEGER NOT NULL,
      bytes_in  INTEGER NOT NULL,
      flows     INTEGER NOT NULL,
      PRIMARY KEY (bucket, exec_id, daddr)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS roll_dns_hour (
      bucket    INTEGER NOT NULL,
      exec_id   INTEGER NOT NULL,
      qname_rev TEXT    NOT NULL,
      hits      INTEGER NOT NULL,
      nxdomain  INTEGER NOT NULL,
      unanswered INTEGER NOT NULL,
      PRIMARY KEY (bucket, exec_id, qname_rev)
    ) WITHOUT ROWID;

    -- Interface name dimension, so rollup rows carry an integer.
    CREATE TABLE IF NOT EXISTS iface (
      id   INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    ) STRICT;
    """

    // MARK: - pcap.db

    /// The packet ring index.
    ///
    /// Note what is NOT here: a row per packet. At 100k pps that would be
    /// 100,000 inserts a second and an index larger than the pcap itself. A
    /// flow instead records the RANGE of segments it appears in -- two integers,
    /// updated with one comparison per packet -- and extraction rescans those
    /// one to three files. O(1) per packet, ~60 index rows for a 4 GB ring.
    public static let pcapDDL = """
    CREATE TABLE IF NOT EXISTS pcap_file (
      id       INTEGER PRIMARY KEY,
      path     TEXT    NOT NULL UNIQUE,
      linktype INTEGER NOT NULL,          -- 258 (LINKTYPE_PKTAP), never 149
      snaplen  INTEGER NOT NULL,
      first_ts INTEGER, last_ts INTEGER,
      bytes    INTEGER NOT NULL DEFAULT 0,
      pkts     INTEGER NOT NULL DEFAULT 0,
      sealed   INTEGER NOT NULL DEFAULT 0,
      created  INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS ix_pcap_file_ts ON pcap_file(first_ts);

    CREATE TABLE IF NOT EXISTS pcap_seg (
      uid       INTEGER NOT NULL,
      file_id   INTEGER NOT NULL,
      first_off INTEGER NOT NULL,         -- byte offset of the flow's first packet
      last_off  INTEGER NOT NULL,
      first_ts  INTEGER NOT NULL, last_ts INTEGER NOT NULL,
      pkts      INTEGER NOT NULL, bytes INTEGER NOT NULL,
      PRIMARY KEY (uid, file_id)
    ) WITHOUT ROWID;

    CREATE INDEX IF NOT EXISTS ix_pcap_seg_file ON pcap_seg(file_id);
    """

    // MARK: - Creation

    public static func createDayPartition(_ db: SQLiteConnection) throws {
        try db.exec(dayPartitionDDL)
        try db.exec("PRAGMA user_version = \(version)")
    }

    public static func createMeta(_ db: SQLiteConnection) throws {
        try db.exec(metaDDL)
        try migrateMeta(db)
        try db.exec("PRAGMA user_version = \(version)")
    }

    public static func createRollup(_ db: SQLiteConnection) throws {
        try db.exec(rollupDDL)
        try db.exec("PRAGMA user_version = \(version)")
    }

    public static func createPcapIndex(_ db: SQLiteConnection) throws {
        try db.exec(pcapDDL)
        try db.exec("PRAGMA user_version = \(version)")
    }

    // MARK: - Migration

    /// Brings an existing `meta.db` up to `version`.
    ///
    /// **`user_version` cannot be the signal here, and that is the whole
    /// reason this function inspects the file instead.** Every `create*`
    /// stamps the current version after running DDL built from
    /// `CREATE ... IF NOT EXISTS`, and that form does *not* replace an object
    /// whose definition changed. A file carrying the v1 index therefore gets
    /// stamped v2 and then reports itself migrated -- so any machine that
    /// restarted the daemon after the schema bump already has a stamp that
    /// lies. Reading what is actually on disk is the only check that survives
    /// that, and it makes the migration idempotent for free.
    static func migrateMeta(_ db: SQLiteConnection) throws {
        try migrateExecIdentity(db)
    }

    /// v1 -> v2: the exec identity index gained `name`.
    ///
    /// Analyzer-produced identities carry neither a path nor a UUID, so under
    /// the three-column index every one of them collided on `("", 0, 0)` and
    /// inherited the name of whichever process was interned first. Widening a
    /// unique index can never fail against existing rows: anything unique on
    /// three columns is still unique on four.
    ///
    /// This repairs **future writes only**. Rows already written point at the
    /// merged `exec` row, and the identity that lost the collision was never
    /// stored anywhere, so it cannot be recovered. `dns.pid` and `ssl.pid` are
    /// unaffected and are the only sound basis for re-attributing old rows.
    private static func migrateExecIdentity(_ db: SQLiteConnection) throws {
        let columns = try db.scalarInt(
            "SELECT count(*) FROM pragma_index_info('ux_exec_ident')") ?? 0
        // 0 means the index is absent, which cannot happen after the DDL above
        // and must not be "repaired" by guessing. 4 is current.
        guard columns > 0, columns < 4 else { return }
        try db.exec("""
            DROP INDEX ux_exec_ident;
            CREATE UNIQUE INDEX ux_exec_ident ON exec(path, uuid_hi, uuid_lo, name);
            """)
    }

    /// Reads the stored schema version, or 0 for a fresh file.
    public static func storedVersion(_ db: SQLiteConnection) throws -> Int32 {
        Int32(try db.scalarInt("PRAGMA user_version") ?? 0)
    }
}
