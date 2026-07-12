import NetworkExtension
import os.log

/// TLS-terminating ECH proxy tunnel.
///
/// Managed domains (linux.do / idcflare.com) resolve to 127.0.0.1 via the
/// tunnel's DNS; the browser then connects to 127.0.0.1:443, which — because
/// loopback is shared device-wide on iOS — reaches the Rust ECH proxy running
/// inside this extension. The proxy terminates TLS with a local CA-signed cert
/// and re-originates the connection to Cloudflare using ECH. This matches the
/// desktop architecture and works for every browser, not just Safari.
///
/// Only DNS goes through the tunnel (matchDomains). Real traffic — including the
/// proxy's own upstream to Cloudflare — stays direct.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "io.linuxdo.accelerator", category: "tunnel")

    private let tunnelClientIp = "10.77.0.1"
    private let dnsServerIp = "10.77.0.2"

    private let core = RustCore()
    private var config = LinuxdoConfig.bundledDefault
    private var running = false
    private let workQueue = DispatchQueue(label: "io.linuxdo.accelerator.tunnel", qos: .userInitiated)

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        config = ConfigStore.load()

        // Start the in-extension ECH proxy (binds config listen_host = 127.0.0.1).
        if !core.start() {
            os_log("failed to start Rust ECH proxy", log: log, type: .error)
            completionHandler(NSError(domain: "io.linuxdo.accelerator", code: 2,
                                      userInfo: [NSLocalizedDescriptionKey: "本地 ECH 代理启动失败"]))
            return
        }
        os_log("ECH proxy started on %{public}@", log: log, type: .info, LinuxdoConfig.loopbackHost)

        let settings = makeTunnelSettings()
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log("setTunnelNetworkSettings failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                self.core.stop()
                completionHandler(error)
                return
            }
            self.running = true
            self.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        core.stop()
        os_log("tunnel stopping, reason=%{public}@", log: log, type: .info, "\(reason.rawValue)")
        completionHandler()
    }

    // MARK: - Network settings

    private func makeTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: dnsServerIp)

        let ipv4 = NEIPv4Settings(addresses: [tunnelClientIp], subnetMasks: ["255.255.255.0"])
        // Only claim the DNS server address; TCP to 127.0.0.1 is loopback and
        // the proxy's upstream to Cloudflare stays off the tunnel.
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: dnsServerIp, subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [dnsServerIp])
        dns.matchDomains = config.tunnelMatchDomains
        settings.dnsSettings = dns

        settings.mtu = 1500
        return settings
    }

    // MARK: - Packet loop (DNS only)

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.running else { return }
            self.workQueue.async {
                self.handle(packets: packets, protocols: protocols)
            }
            if self.running { self.readPackets() }
        }
    }

    private func handle(packets: [Data], protocols: [NSNumber]) {
        let dnsIpBytes = IpParsing.ipv4Bytes(dnsServerIp) ?? []
        var responses: [Data] = []
        var responseProtocols: [NSNumber] = []

        for (index, packet) in packets.enumerated() {
            let proto = index < protocols.count ? protocols[index].int32Value : AF_INET
            guard proto == AF_INET else { continue }

            let bytes = [UInt8](packet)
            guard let request = TunPacketCodec.parseIpv4UdpDns(bytes, length: bytes.count, expectedDestIp: dnsIpBytes),
                  let query = DnsPacketCodec.parseDnsQuery(request.payload) else {
                continue
            }

            let responsePayload = resolveLoopback(query: query)
            let responsePacket = TunPacketCodec.buildIpv4UdpResponse(request: request, responsePayload: responsePayload)
            responses.append(Data(responsePacket))
            responseProtocols.append(NSNumber(value: AF_INET))
        }

        if !responses.isEmpty {
            packetFlow.writePackets(responses, withProtocols: responseProtocols)
        }
    }

    /// Answers managed domains with the loopback proxy address: A → 127.0.0.1,
    /// AAAA → NODATA so browsers fall back to IPv4 loopback.
    private func resolveLoopback(query: ParsedDnsQuery) -> [UInt8] {
        let managed = config.shouldUseManagedDoh(query.name) || config.findDnsHostOverride(query.name) != nil
        guard managed else {
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: [], responseCode: 2))
        }

        switch query.type {
        case DnsType.a:
            let ip = IpParsing.ipv4Bytes(LinuxdoConfig.loopbackHost) ?? [127, 0, 0, 1]
            let answer = DnsAnswerRecord(type: DnsType.a, ttl: 60, data: ip)
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: [answer]))
        default:
            // AAAA / HTTPS / others: NODATA (NOERROR, no answers) → IPv4 path used.
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: []))
        }
    }
}
