import Foundation

/// Answer-section parsing for raw dns-message responses, ported from Android
/// `DnsPacketCodec.parseWireResponse` / `readDnsName`.
extension DnsPacketCodec {
    static func parseWireResponse(_ payload: [UInt8], requestedType: Int) throws -> [DnsAnswerRecord] {
        if payload.count < 12 { throw DnsCodecError.malformed("short dns-message response") }
        let answerCount = readU16(payload, 6)
        var offset = 12
        let questionCount = readU16(payload, 4)
        for _ in 0..<questionCount {
            offset = try skipDnsName(payload, offset)
            if offset + 4 > payload.count { throw DnsCodecError.malformed("truncated dns question") }
            offset += 4
        }

        var records: [DnsAnswerRecord] = []
        for _ in 0..<answerCount {
            offset = try skipDnsName(payload, offset)
            if offset + 10 > payload.count { throw DnsCodecError.malformed("truncated dns answer") }
            let type = readU16(payload, offset)
            let ttl = readU32(payload, offset + 4)
            let dataLength = readU16(payload, offset + 8)
            offset += 10
            if offset + dataLength > payload.count { throw DnsCodecError.malformed("truncated dns rdata") }
            let rdata = Array(payload[offset..<offset + dataLength])
            switch type {
            case DnsType.a:
                if requestedType == DnsType.a { records.append(DnsAnswerRecord(type: type, ttl: ttl, data: rdata)) }
            case DnsType.aaaa:
                if requestedType == DnsType.aaaa { records.append(DnsAnswerRecord(type: type, ttl: ttl, data: rdata)) }
            case DnsType.cname:
                let (cname, _) = try readDnsName(payload, offset)
                records.append(DnsAnswerRecord(type: type, ttl: ttl, data: encodeDomainName(cname)))
            default:
                if type == requestedType { records.append(DnsAnswerRecord(type: type, ttl: ttl, data: rdata)) }
            }
            offset += dataLength
        }
        return records
    }

    static func skipDnsName(_ buffer: [UInt8], _ start: Int) throws -> Int {
        let (_, next) = try readDnsName(buffer, start)
        return next
    }

    static func readDnsName(_ buffer: [UInt8], _ start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var offset = start
        var jumped = false
        var nextOffset = start
        var visited = Set<Int>()

        while offset < buffer.count {
            if !visited.insert(offset).inserted {
                throw DnsCodecError.malformed("dns name compression loop")
            }
            let length = Int(buffer[offset]) & 0xff
            if length == 0 {
                if !jumped { nextOffset = offset + 1 }
                break
            }
            if (length & 0xc0) == 0xc0 {
                if offset + 1 >= buffer.count { throw DnsCodecError.malformed("truncated dns compression pointer") }
                let pointer = ((length & 0x3f) << 8) | (Int(buffer[offset + 1]) & 0xff)
                if !jumped { nextOffset = offset + 2 }
                offset = pointer
                jumped = true
                continue
            }
            let labelStart = offset + 1
            let labelEnd = labelStart + length
            if labelEnd > buffer.count { throw DnsCodecError.malformed("truncated dns label") }
            labels.append(String(decoding: buffer[labelStart..<labelEnd], as: UTF8.self))
            offset = labelEnd
            if !jumped { nextOffset = offset }
        }
        return (labels.joined(separator: "."), nextOffset)
    }

    // MARK: - Byte helpers

    static func readU16(_ buffer: [UInt8], _ offset: Int) -> Int {
        (Int(buffer[offset]) & 0xff) << 8 | (Int(buffer[offset + 1]) & 0xff)
    }

    static func readU32(_ buffer: [UInt8], _ offset: Int) -> Int {
        (Int(buffer[offset]) & 0xff) << 24
            | (Int(buffer[offset + 1]) & 0xff) << 16
            | (Int(buffer[offset + 2]) & 0xff) << 8
            | (Int(buffer[offset + 3]) & 0xff)
    }

    static func writeU16(_ out: inout [UInt8], _ value: Int) {
        out.append(UInt8((value >> 8) & 0xff))
        out.append(UInt8(value & 0xff))
    }

    static func writeU32(_ out: inout [UInt8], _ value: Int) {
        out.append(UInt8((value >> 24) & 0xff))
        out.append(UInt8((value >> 16) & 0xff))
        out.append(UInt8((value >> 8) & 0xff))
        out.append(UInt8(value & 0xff))
    }
}
