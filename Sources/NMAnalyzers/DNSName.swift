//
//  DNSName.swift
//
//  Domain name decoding, including compression pointers.
//
//  This is the single most dangerous piece of parsing in the project. DNS name
//  compression lets a name reference an earlier offset in the message, and a
//  naive decoder following those references will happily run forever on a
//  packet that points at itself -- a two-byte denial of service against a root
//  process. Every rule below exists to close a specific hole:
//
//    * A pointer must target a STRICTLY SMALLER offset. This is the one that
//      matters: forward and self-referential pointers are the classic infinite
//      loop, and a jump counter alone only bounds how long the loop runs before
//      it produces garbage.
//    * Jumps are capped anyway, as a second line.
//    * Label length bytes with the top two bits 01 or 10 are RESERVED. Treating
//      them as literals is how parsers end up reading a length that means
//      something else entirely.
//    * Names are capped at 255 bytes, labels at 63, label count at 127 -- all
//      protocol limits, all worth enforcing rather than trusting.
//

import NMCore

public enum DNSNameError: Error, Equatable {
    case forwardPointer(from: Int, to: Int)
    case tooManyJumps
    case reservedLabelType(UInt8)
    case labelTooLong(Int)
    case nameTooLong(Int)
    case tooManyLabels
    case truncated
}

public enum DNSName {

    /// The two high bits of a length byte select the label kind.
    private static let pointerMask: UInt8 = 0xC0
    private static let literalKind: UInt8 = 0x00
    private static let pointerKind: UInt8 = 0xC0

    /// Decodes a name starting at `offset` within `message`.
    ///
    /// `message` must span the whole DNS message, because compression offsets
    /// are relative to its start. On return `offset` points just past the name
    /// *in the original stream* -- following a pointer consumes only the two
    /// pointer bytes, not the length of whatever it pointed at.
    public static func decode(from message: ByteReader, offset: inout Int) throws -> String {
        var labels: [String] = []
        var totalLength = 0
        var jumps = 0
        var cursor = offset
        /// Where to resume in the original stream. Set once, at the first jump.
        var resumeAt: Int?

        while true {
            guard cursor >= 0, cursor < message.count else { throw DNSNameError.truncated }
            var r = try message.reader(at: cursor, count: message.count - cursor)
            let lengthByte = try r.u8()

            switch lengthByte & pointerMask {
            case literalKind:
                let labelLength = Int(lengthByte)
                if labelLength == 0 {
                    // Root label: the name ends here.
                    cursor += 1
                    offset = resumeAt ?? cursor
                    return labels.isEmpty ? "." : labels.joined(separator: ".")
                }
                guard labelLength <= Limits.maxDNSLabelLength else {
                    throw DNSNameError.labelTooLong(labelLength)
                }
                // +1 for the dot this label will contribute.
                totalLength += labelLength + 1
                guard totalLength <= Limits.maxDNSNameLength else {
                    throw DNSNameError.nameTooLong(totalLength)
                }
                guard labels.count < Limits.maxDNSLabels else {
                    throw DNSNameError.tooManyLabels
                }
                let bytes = try r.bytes(labelLength)
                labels.append(renderLabel(bytes))
                cursor += 1 + labelLength

            case pointerKind:
                let high = UInt16(lengthByte & 0x3F) << 8
                let low = UInt16(try r.u8())
                let target = Int(high | low)

                // The rule that actually prevents the loop. A pointer that does
                // not move backwards can always be arranged into a cycle.
                guard target < cursor else {
                    throw DNSNameError.forwardPointer(from: cursor, to: target)
                }
                jumps += 1
                guard jumps <= Limits.maxDNSCompressionJumps else {
                    throw DNSNameError.tooManyJumps
                }
                if resumeAt == nil { resumeAt = cursor + 2 }
                cursor = target

            default:
                // 0b01 and 0b10 are reserved. Historically 0b01 was an
                // experimental extended-label type; treating either as a
                // literal length misreads the rest of the message.
                throw DNSNameError.reservedLabelType(lengthByte >> 6)
            }
        }
    }

    /// Renders a label, escaping anything that would make the name ambiguous or
    /// unsafe to display.
    ///
    /// Names reach the UI and the database, so a label containing a dot, a
    /// backslash or a control character must not be able to impersonate a
    /// different name or corrupt a log line.
    private static func renderLabel(_ bytes: UnsafeRawBufferPointer) -> String {
        var out = ""
        out.reserveCapacity(bytes.count)
        for byte in bytes {
            switch byte {
            case UInt8(ascii: "."): out += "\\."
            case UInt8(ascii: "\\"): out += "\\\\"
            case 0x20...0x7E: out.append(Character(UnicodeScalar(byte)))
            default:
                // Non-printable or non-ASCII: keep it visible and reversible
                // rather than dropping it. Punycode names arrive as ASCII
                // already, so this is genuinely unusual input.
                out += "\\x" + hex(byte)
            }
        }
        return out
    }

    private static func hex(_ byte: UInt8) -> String {
        let digits = "0123456789abcdef"
        let hi = digits[digits.index(digits.startIndex, offsetBy: Int(byte >> 4))]
        let lo = digits[digits.index(digits.startIndex, offsetBy: Int(byte & 0x0F))]
        return String([hi, lo])
    }
}
