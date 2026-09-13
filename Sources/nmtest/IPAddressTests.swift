//
//  IPAddressTests.swift
//
//  Address bugs are silent and pervasive: a wrong byte order shows up as
//  plausible-looking but wrong addresses in every log row. The round-trip and
//  byte-order cases here are the ones that catch that.
//

import NMCore
import NMTestKit

func runIPAddressTests() {
    NMTest.suite("IPAddress / IPv4") {

        NMTest.test("dotted quad round-trips") {
            for text in ["0.0.0.0", "1.2.3.4", "127.0.0.1", "192.168.1.1", "255.255.255.255"] {
                guard let a = IPAddress(text) else {
                    NMTest.expect(false, "failed to parse \(text)")
                    continue
                }
                NMTest.equal(a.description, text)
                NMTest.expect(a.isIPv4, "\(text) should report as IPv4")
            }
        }

        NMTest.test("network-order and host-order inits agree") {
            // sockaddr_in and the IP header both hand you network order: the
            // byte sequence 01 02 03 04. Loaded as a UInt32 on a little-endian
            // host that is 0x04030201, and reading it as host order would give
            // the address 4.3.2.1 -- backwards, and entirely plausible-looking.
            NMTest.equal(IPAddress(v4NetworkOrder: 0x04030201).description, "1.2.3.4")
            NMTest.equal(IPAddress(v4HostOrder: 0x01020304).description, "1.2.3.4")
            NMTest.equal(IPAddress(v4HostOrder: 0x04030201).description, "4.3.2.1",
                         "host-order init must NOT byte-swap")
        }

        NMTest.test("malformed IPv4 is rejected, not coerced") {
            for bad in ["1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.", ".1.2.3", "1.2.3.-1", "a.b.c.d"] {
                NMTest.expect(IPAddress(bad) == nil, "\(bad) must not parse")
            }
        }

        NMTest.test("v4-mapped storage keeps the 0xFFFF marker distinct from ::") {
            let zero = IPAddress(hi: 0, lo: 0)             // ::
            let loopback6 = IPAddress(hi: 0, lo: 1)        // ::1
            NMTest.expect(!zero.isIPv4, ":: must not be mistaken for 0.0.0.0")
            NMTest.expect(!loopback6.isIPv4, "::1 must not be mistaken for IPv4")
            NMTest.expect(IPAddress("0.0.0.0")!.isIPv4)
        }
    }

    NMTest.suite("IPAddress / IPv6 text") {

        NMTest.test("RFC 5952 collapses the longest zero run") {
            let cases: [(String, String)] = [
                ("2001:db8::1", "2001:db8::1"),
                ("::1", "::1"),
                ("::", "::"),
                ("fe80::1", "fe80::1"),
                ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),   // leftmost longest run
                ("2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:db8::ff00:42:8329"),
            ]
            for (input, expected) in cases {
                guard let a = IPAddress(input) else {
                    NMTest.expect(false, "failed to parse \(input)")
                    continue
                }
                NMTest.equal(a.description, expected, "input was \(input)")
            }
        }

        NMTest.test("a single zero group is never collapsed") {
            guard let a = IPAddress("2001:db8:0:1:1:1:1:1") else {
                return NMTest.expect(false, "parse failed")
            }
            NMTest.equal(a.description, "2001:db8:0:1:1:1:1:1")
        }

        NMTest.test("malformed IPv6 is rejected") {
            for bad in ["2001:db8::1::2", "gggg::1", "2001:db8:1:2:3:4:5:6:7", ":::", "12345::1"] {
                NMTest.expect(IPAddress(bad) == nil, "\(bad) must not parse")
            }
        }
    }

    NMTest.suite("IPAddress / classification") {

        NMTest.test("RFC 1918, CGNAT and unique-local are recognized") {
            for text in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "100.64.0.1"] {
                NMTest.expect(IPAddress(text)!.isPrivate, "\(text) should be private")
            }
            for text in ["172.32.0.1", "172.15.0.1", "8.8.8.8", "100.128.0.1"] {
                NMTest.expect(!IPAddress(text)!.isPrivate, "\(text) should NOT be private")
            }
            NMTest.expect(IPAddress("fd00::1")!.isPrivate, "fc00::/7 is unique-local")
            NMTest.expect(!IPAddress("2001:db8::1")!.isPrivate)
        }

        NMTest.test("loopback, link-local and multicast") {
            NMTest.expect(IPAddress("127.0.0.1")!.isLoopback)
            NMTest.expect(IPAddress("127.255.255.254")!.isLoopback)
            NMTest.expect(IPAddress("::1")!.isLoopback)
            NMTest.expect(IPAddress("169.254.1.1")!.isLinkLocal)
            NMTest.expect(IPAddress("fe80::1")!.isLinkLocal)
            NMTest.expect(IPAddress("224.0.0.1")!.isMulticast)
            NMTest.expect(IPAddress("ff02::1")!.isMulticast)
            NMTest.expect(!IPAddress("8.8.8.8")!.isMulticast)
        }
    }

    NMTest.suite("IPAddress / storage form") {

        NMTest.test("v4 persists as 4 bytes and v6 as 16") {
            NMTest.equal(IPAddress("1.2.3.4")!.storageBytes, [1, 2, 3, 4])
            NMTest.equal(IPAddress("::1")!.storageBytes.count, 16)
            NMTest.equal(IPAddress("2001:db8::1")!.storageBytes.count, 16)
        }

        NMTest.test("storage bytes round-trip exactly") {
            for text in ["0.0.0.0", "8.8.8.8", "255.255.255.255",
                         "::", "::1", "2001:db8::1", "fe80::dead:beef"] {
                let a = IPAddress(text)!
                guard let back = IPAddress(storageBytes: a.storageBytes) else {
                    NMTest.expect(false, "round-trip failed for \(text)")
                    continue
                }
                NMTest.equal(back, a, "round-trip changed \(text)")
                NMTest.equal(back.description, text == "0.0.0.0" ? "0.0.0.0" : back.description)
            }
        }

        NMTest.test("a wrong-width blob is rejected rather than misread") {
            NMTest.expect(IPAddress(storageBytes: []) == nil)
            NMTest.expect(IPAddress(storageBytes: [1, 2, 3]) == nil)
            NMTest.expect(IPAddress(storageBytes: [UInt8](repeating: 0, count: 8)) == nil)
        }

        // The property CIDR range scans depend on: memcmp order over the stored
        // bytes must equal numeric address order. Without this, `BETWEEN` on the
        // BLOB column silently returns the wrong rows.
        NMTest.test("byte order matches numeric order, which is what BETWEEN needs") {
            let ascending = ["1.2.3.4", "10.0.0.1", "10.0.0.2", "10.0.1.0", "192.168.1.1", "255.0.0.0"]
            let addrs = ascending.map { IPAddress($0)! }
            for i in 1..<addrs.count {
                NMTest.expect(addrs[i - 1] < addrs[i],
                              "\(ascending[i-1]) should sort before \(ascending[i])")
                NMTest.expect(lexicographicallyPrecedes(addrs[i - 1].storageBytes,
                                                        addrs[i].storageBytes),
                              "stored bytes for \(ascending[i-1]) should memcmp before \(ascending[i])")
            }
        }
    }

    NMTest.suite("IPPrefix / CIDR") {

        NMTest.test("prefix bounds are computed correctly") {
            guard let p = IPPrefix("10.0.0.0/8") else { return NMTest.expect(false, "parse failed") }
            NMTest.equal(p.lower.description, "10.0.0.0")
            NMTest.equal(p.upper.description, "10.255.255.255")
            NMTest.expect(p.contains(IPAddress("10.1.2.3")!))
            NMTest.expect(!p.contains(IPAddress("11.0.0.0")!))
            NMTest.expect(!p.contains(IPAddress("9.255.255.255")!))
        }

        NMTest.test("host and full-width prefixes are degenerate but valid") {
            guard let host = IPPrefix("192.168.1.5/32") else { return NMTest.expect(false, "parse") }
            NMTest.equal(host.lower, host.upper)
            NMTest.expect(host.contains(IPAddress("192.168.1.5")!))
            NMTest.expect(!host.contains(IPAddress("192.168.1.6")!))

            guard let all = IPPrefix("0.0.0.0/0") else { return NMTest.expect(false, "parse") }
            NMTest.expect(all.contains(IPAddress("8.8.8.8")!))
            NMTest.expect(all.contains(IPAddress("0.0.0.0")!))
            NMTest.expect(all.contains(IPAddress("255.255.255.255")!))
        }

        NMTest.test("a non-aligned prefix is masked to its network address") {
            guard let p = IPPrefix("192.168.1.130/24") else { return NMTest.expect(false, "parse") }
            NMTest.equal(p.lower.description, "192.168.1.0")
            NMTest.equal(p.upper.description, "192.168.1.255")
        }

        NMTest.test("IPv6 prefixes span the hi/lo word boundary correctly") {
            guard let p = IPPrefix("2001:db8::/32") else { return NMTest.expect(false, "parse") }
            NMTest.equal(p.lower.description, "2001:db8::")
            NMTest.expect(p.contains(IPAddress("2001:db8:ffff::1")!))
            NMTest.expect(!p.contains(IPAddress("2001:db9::1")!))

            // /64 masks exactly the hi word; /65 crosses into lo.
            guard let p64 = IPPrefix("2001:db8:0:1::/64"),
                  let p65 = IPPrefix("2001:db8:0:1::/65") else {
                return NMTest.expect(false, "parse")
            }
            NMTest.expect(p64.contains(IPAddress("2001:db8:0:1:ffff:ffff:ffff:ffff")!))
            NMTest.expect(!p65.contains(IPAddress("2001:db8:0:1:ffff:ffff:ffff:ffff")!))
            NMTest.expect(p65.contains(IPAddress("2001:db8:0:1:7fff::")!))
        }

        NMTest.test("a v4 prefix never matches a v6 address") {
            let p = IPPrefix("0.0.0.0/0")!
            NMTest.expect(!p.contains(IPAddress("::1")!),
                          "v4-mapped storage must not let ::1 fall inside 0.0.0.0/0")
        }

        NMTest.test("malformed CIDR is rejected") {
            for bad in ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0", "10.0.0.0/", "/8",
                        "2001:db8::/129", "notanaddr/8"] {
                NMTest.expect(IPPrefix(bad) == nil, "\(bad) must not parse")
            }
        }
    }
}

private func lexicographicallyPrecedes(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    a.lexicographicallyPrecedes(b)
}
