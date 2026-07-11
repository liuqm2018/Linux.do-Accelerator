import Foundation

/// DNS record type numbers used by the resolver. Ports Android LinuxdoDnsResolver.
enum DnsType {
    static let a = 1
    static let cname = 5
    static let aaaa = 28
    static let svcb = 64
    static let https = 65

    static func name(_ type: Int) -> String {
        switch type {
        case a: return "A"
        case aaaa: return "AAAA"
        case svcb: return "SVCB"
        case https: return "HTTPS"
        default: return String(type)
        }
    }

    static func isSupportedManaged(_ type: Int) -> Bool {
        type == a || type == aaaa || type == svcb || type == https
    }

    static func isJsonFriendly(_ type: Int) -> Bool {
        type == a || type == aaaa
    }
}

struct ParsedDnsQuery {
    let id: Int
    let flags: Int
    let name: String
    let type: Int
    let questionBytes: [UInt8]
}

struct DnsAnswerRecord {
    let type: Int
    let ttl: Int
    let data: [UInt8]
}

struct DnsResolution {
    let answers: [DnsAnswerRecord]
    var responseCode: Int = 0
}

enum DnsCodecError: Error { case malformed(String) }

/// Ports Android `DnsPacketCodec`: wire query builder, query parser, response
/// builder, and answer-section parser (with name-compression handling).
enum DnsPacketCodec {
    // MARK: Query building / parsing

    static func buildWireQuery(domain: String, type: Int) -> [UInt8] {
        var out: [UInt8] = []
        writeU16(&out, 0)         // id
        writeU16(&out, 0x0100)    // RD
        writeU16(&out, 1)         // qdcount
        writeU16(&out, 0)         // ancount
        writeU16(&out, 0)         // nscount
        writeU16(&out, 0)         // arcount
        out.append(contentsOf: encodeDomainName(domain))
        writeU16(&out, type)
        writeU16(&out, 1)         // class IN
        return out
    }

    static func parseDnsQuery(_ payload: [UInt8]) -> ParsedDnsQuery? {
        if payload.count < 12 { return nil }
        let id = readU16(payload, 0)
        let flags = readU16(payload, 2)
        let qdCount = readU16(payload, 4)
        if qdCount < 1 { return nil }

        var offset = 12
        var labels: [String] = []
        while offset < payload.count {
            let length = Int(payload[offset]) & 0xff
            offset += 1
            if length == 0 { break }
            if (length & 0xc0) != 0 || offset + length > payload.count { return nil }
            let slice = Array(payload[offset..<offset + length])
            labels.append(String(decoding: slice, as: UTF8.self))
            offset += length
        }

        if offset + 4 > payload.count { return nil }
        let questionEnd = offset + 4
        let questionBytes = Array(payload[12..<questionEnd])
        return ParsedDnsQuery(
            id: id,
            flags: flags,
            name: labels.joined(separator: "."),
            type: readU16(payload, offset),
            questionBytes: questionBytes
        )
    }

    static func buildResponse(query: ParsedDnsQuery, resolution: DnsResolution) -> [UInt8] {
        var out: [UInt8] = []
        writeU16(&out, query.id)
        // QR=1, copy RD, RA=1, rcode.
        let responseFlags = 0x8000 | (query.flags & 0x0100) | 0x0080 | (resolution.responseCode & 0x000f)
        writeU16(&out, responseFlags)
        writeU16(&out, 1)                        // qdcount
        writeU16(&out, resolution.answers.count) // ancount
        writeU16(&out, 0)                        // nscount
        writeU16(&out, 0)                        // arcount
        out.append(contentsOf: query.questionBytes)

        for answer in resolution.answers {
            writeU16(&out, 0xc00c)               // pointer to the question name
            writeU16(&out, answer.type)
            writeU16(&out, 1)                    // class IN
            writeU32(&out, answer.ttl)
            writeU16(&out, answer.data.count)
            out.append(contentsOf: answer.data)
        }
        return out
    }

    static func encodeDomainName(_ domain: String) -> [UInt8] {
        var out: [UInt8] = []
        let normalized = domain.trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if normalized.isEmpty {
            out.append(0)
            return out
        }
        for label in normalized.split(separator: ".") {
            let bytes = Array(label.utf8)
            out.append(UInt8(bytes.count & 0xff))
            out.append(contentsOf: bytes)
        }
        out.append(0)
        return out
    }
}
