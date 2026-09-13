//
//  Authorization.swift
//
//  Who is allowed to change system-wide settings.
//
//  The daemon decides, never the client. A GUI can render a lock icon as a
//  convenience, but the lock has to be enforced on the far side of the
//  boundary: the client is a separate binary that a user can replace, patch or
//  impersonate, and a privilege check it performs on itself is decoration.
//
//  Authorization Services is used rather than a home-made group check because
//  the decision is then made by `authd`, not by us. The client obtains an
//  external form, the daemon converts it back and re-evaluates the right
//  itself. A patched client cannot forge that -- it would have to forge authd's
//  answer, which it cannot reach.
//
//  A group-membership fallback exists for unsigned development builds where the
//  custom right has not been installed. It is strictly weaker and says so.
//

import Darwin
import Foundation
import Security

public enum NMAuthorization {

    /// The right an administrator must hold to change collection policy.
    /// Installed into the policy database by the install script:
    ///     security authorizationdb write com.narusec.networkmonitor.admin authenticate-admin
    public static let adminRight = "com.narusec.networkmonitor.admin"

    public enum Failure: Error, CustomStringConvertible {
        case cannotCreate(OSStatus)
        case denied(OSStatus)
        case malformedExternalForm

        public var description: String {
            switch self {
            case .cannotCreate(let status): return "AuthorizationCreate failed (\(status))"
            case .denied(let status): return "authorization denied (\(status))"
            case .malformedExternalForm: return "authorization blob was malformed"
            }
        }
    }

    // MARK: - Client side

    /// Asks the user to authorize, producing a blob to send with the request.
    ///
    /// This is what raises the standard macOS administrator prompt. It runs in
    /// the CLIENT, because only a process with a UI session can present one --
    /// but the result is meaningless until the daemon re-evaluates it.
    public static func requestAdminRights(allowUserInteraction: Bool = true) throws -> Data {
        var authorization: AuthorizationRef?
        let created = AuthorizationCreate(nil, nil, [], &authorization)
        guard created == errAuthorizationSuccess, let authorization else {
            throw Failure.cannotCreate(created)
        }
        defer { AuthorizationFree(authorization, []) }

        var name = Array(adminRight.utf8CString)
        let status: OSStatus = name.withUnsafeMutableBufferPointer { buffer in
            var item = AuthorizationItem(name: buffer.baseAddress!, valueLength: 0,
                                         value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                var flags: AuthorizationFlags = [.extendRights, .preAuthorize]
                if allowUserInteraction { flags.insert(.interactionAllowed) }
                return AuthorizationCopyRights(authorization, &rights, nil, flags, nil)
            }
        }
        guard status == errAuthorizationSuccess else { throw Failure.denied(status) }

        var external = AuthorizationExternalForm()
        let exported = AuthorizationMakeExternalForm(authorization, &external)
        guard exported == errAuthorizationSuccess else { throw Failure.denied(exported) }

        return withUnsafeBytes(of: &external) { Data($0) }
    }

    // MARK: - Daemon side

    /// Re-evaluates an authorization blob. This is the check that counts.
    public static func verifyAdminRights(_ blob: Data) -> Bool {
        guard blob.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }

        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { destination in
            blob.copyBytes(to: destination.bindMemory(to: UInt8.self))
        }

        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &authorization)
                == errAuthorizationSuccess, let authorization else {
            return false
        }
        defer { AuthorizationFree(authorization, []) }

        var name = Array(adminRight.utf8CString)
        let status: OSStatus = name.withUnsafeMutableBufferPointer { buffer in
            var item = AuthorizationItem(name: buffer.baseAddress!, valueLength: 0,
                                         value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                // No interaction: the daemon has no UI session and must not
                // block waiting for a prompt that can never appear.
                return AuthorizationCopyRights(authorization, &rights, nil,
                                               [.extendRights], nil)
            }
        }
        return status == errAuthorizationSuccess
    }

    // MARK: - Group membership

    /// Whether a uid is in the admin group.
    ///
    /// Used for the READ side -- deciding whether a caller may open the
    /// databases directly -- and as the development fallback for writes when
    /// the custom right is not installed. It is weaker than an authorization:
    /// it proves who the caller is, not that a human just approved this action.
    public static func isAdministrator(uid: uid_t) -> Bool {
        guard let passwd = getpwuid(uid) else { return false }
        if passwd.pointee.pw_gid == 80 { return true }          // the admin gid

        guard let group = getgrnam("admin"), let members = group.pointee.gr_mem else {
            return false
        }
        let name = String(cString: passwd.pointee.pw_name)
        var index = 0
        while let member = members[index] {
            if String(cString: member) == name { return true }
            index += 1
        }
        return false
    }

    /// Whether a uid can read the store directly, i.e. is in the readers group.
    public static func isInReadersGroup(uid: uid_t, groupName: String = "_networkmonitor") -> Bool {
        guard let passwd = getpwuid(uid) else { return false }
        guard let group = getgrnam(groupName) else { return false }
        if passwd.pointee.pw_gid == group.pointee.gr_gid { return true }
        guard let members = group.pointee.gr_mem else { return false }
        let name = String(cString: passwd.pointee.pw_name)
        var index = 0
        while let member = members[index] {
            if String(cString: member) == name { return true }
            index += 1
        }
        return false
    }
}
