//
//  PeerPinning.swift
//
//  The daemon's code-signing requirement, read from peers.plist.
//
//  Neither binary can contain the other's cdhash -- embedding one would change
//  the other's -- so the installer computes both after signing and writes them
//  to a file both sides read at startup. This is the app's half.
//
//  When the file is absent (a development build that was never installed) the
//  requirement is nil and the connection is unauthenticated. That is stated
//  rather than silently tolerated: the app shows demo data in that case anyway,
//  so there is nothing to impersonate.
//

import Foundation
import NMCore

enum PeerPinning {
    static func daemonRequirement(paths: Paths = Paths()) -> String? {
        guard let data = FileManager.default.contents(atPath: paths.peersFile),
              let plist = try? PropertyListSerialization.propertyList(from: data,
                                                                     format: nil)
                as? [String: String],
              let hash = plist["daemonCDHash"], !hash.isEmpty,
              let identifier = plist["daemonIdentifier"] else {
            return nil
        }
        return "identifier \"\(identifier)\" and cdhash H\"\(hash)\""
    }
}
