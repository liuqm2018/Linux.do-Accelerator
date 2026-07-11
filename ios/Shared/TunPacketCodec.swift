import Foundation

struct UdpDnsPacket {
    let sourceIp: [UInt8]
    let destIp: [UInt8]
    let sourcePort: Int
    let payload: [UInt8]
}

/// Parses IPv4/UDP DNS request packets from the TUN and builds IPv4/UDP DNS
/// responses. Ports Android `TunPacketCodec`.
enum TunPacketCodec {
    static func parseIpv4UdpDns(_ packet: [UInt8], length: Int, expectedDestIp: [UInt8]) -> UdpDnsPacket? {
        if length < 28 { return nil }
        let version = (Int(packet[0]) >> 4) & 0x0f
        let ihl = (Int(packet[0]) & 0x0f) * 4
        if version != 4 || ihl < 20 || length < ihl + 8 { return nil }
        let totalLength = (Int(packet[2]) & 0xff) << 8 | (Int(packet[3]) & 0xff)
        if totalLength > length || Int(packet[9]) != 17 { return nil } // UDP protocol
        let destIp = Array(packet[16..<20])
        if destIp != expectedDestIp { return nil }
        let udpOffset = ihl
        let destPort = (Int(packet[udpOffset + 2]) & 0xff) << 8 | (Int(packet[udpOffset + 3]) & 0xff)
        if destPort != 53 { return nil }
        let udpLength = (Int(packet[udpOffset + 4]) & 0xff) << 8 | (Int(packet[udpOffset + 5]) & 0xff)
        if udpLength < 8 || udpOffset + udpLength > totalLength { return nil }
        return UdpDnsPacket(
            sourceIp: Array(packet[12..<16]),
            destIp: destIp,
            sourcePort: (Int(packet[udpOffset]) & 0xff) << 8 | (Int(packet[udpOffset + 1]) & 0xff),
            payload: Array(packet[(udpOffset + 8)..<(udpOffset + udpLength)])
        )
    }

    static func buildIpv4UdpResponse(request: UdpDnsPacket, responsePayload: [UInt8]) -> [UInt8] {
        let ipHeaderLength = 20
        let udpHeaderLength = 8
        let totalLength = ipHeaderLength + udpHeaderLength + responsePayload.count
        var packet = [UInt8](repeating: 0, count: totalLength)
        packet[0] = 0x45                              // version 4, IHL 5
        packet[1] = 0
        packet[2] = UInt8((totalLength >> 8) & 0xff)
        packet[3] = UInt8(totalLength & 0xff)
        packet[8] = 64                                // TTL
        packet[9] = 17                                // UDP
        // Swap src/dst: response goes from the queried DNS IP back to the client.
        copyInto(&packet, request.destIp, at: 12)
        copyInto(&packet, request.sourceIp, at: 16)
        writeU16(&packet, at: 20, 53)                 // src port 53
        writeU16(&packet, at: 22, request.sourcePort) // dst port = client port
        writeU16(&packet, at: 24, udpHeaderLength + responsePayload.count)
        writeU16(&packet, at: 26, 0)                  // UDP checksum 0 (optional for IPv4)
        for (i, b) in responsePayload.enumerated() { packet[28 + i] = b }
        writeU16(&packet, at: 10, ipv4Checksum(packet, offset: 0, length: ipHeaderLength))
        return packet
    }

    private static func writeU16(_ buffer: inout [UInt8], at offset: Int, _ value: Int) {
        buffer[offset] = UInt8((value >> 8) & 0xff)
        buffer[offset + 1] = UInt8(value & 0xff)
    }

    private static func copyInto(_ buffer: inout [UInt8], _ source: [UInt8], at offset: Int) {
        for (i, b) in source.enumerated() { buffer[offset + i] = b }
    }

    private static func ipv4Checksum(_ buffer: [UInt8], offset: Int, length: Int) -> Int {
        var sum = 0
        var index = offset
        while index < offset + length {
            if index == offset + 10 { // skip the checksum field itself
                index += 2
                continue
            }
            sum += (Int(buffer[index]) & 0xff) << 8 | (Int(buffer[index + 1]) & 0xff)
            while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
            index += 2
        }
        return ~sum & 0xffff
    }
}
