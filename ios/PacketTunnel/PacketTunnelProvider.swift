import NetworkExtension
import os.log

/// DNS-only packet tunnel. Only managed domains (linux.do / idcflare.com) are
/// routed here via NEDNSSettings matchDomains; their queries are answered from a
/// private DoH endpoint that returns ECH-bearing HTTPS records. Everything else
/// bypasses the tunnel entirely. This is the iOS counterpart of the Android
/// LinuxdoVpnService.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "io.linuxdo.accelerator", category: "tunnel")

    // Private tunnel addressing. The DNS server IP is the only route we claim,
    // so real traffic never enters the tunnel.
    private let tunnelClientIp = "10.77.0.1"
    private let dnsServerIp = "10.77.0.2"

    private var resolver: DohResolver?
    private var config = LinuxdoConfig.bundledDefault
    private var running = false
    private let workQueue = DispatchQueue(label: "io.linuxdo.accelerator.tunnel", qos: .userInitiated, attributes: .concurrent)

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        config = ConfigStore.load()
        resolver = DohResolver(config: config)

        // Phase 2a probe: prove the Rust core links and runs on-device by
        // generating/exporting the CA. Does not change DNS behaviour yet.
        if let der = RustCore.exportCaDer() {
            os_log("rust core OK: CA DER %d bytes", log: log, type: .info, der.count)
        } else {
            os_log("rust core probe FAILED (export_ca_der returned nil)", log: log, type: .error)
        }

        guard !config.dohEndpoints.isEmpty else {
            os_log("no DoH endpoints configured", log: log, type: .error)
            completionHandler(NSError(domain: "io.linuxdo.accelerator", code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: "没有可用的 DoH 端点"]))
            return
        }

        let settings = makeTunnelSettings()
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log("setTunnelNetworkSettings failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            self.running = true
            os_log("tunnel established, DoH=%{public}@", log: self.log, type: .info, self.resolver?.primaryEndpointDescription ?? "-")
            self.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        os_log("tunnel stopping, reason=%{public}@", log: log, type: .info, "\(reason.rawValue)")
        completionHandler()
    }

    // MARK: - Network settings

    private func makeTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: dnsServerIp)

        let ipv4 = NEIPv4Settings(addresses: [tunnelClientIp], subnetMasks: ["255.255.255.0"])
        // Claim only the fake DNS server address, nothing else.
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: dnsServerIp, subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [dnsServerIp])
        // Only queries for these suffixes are sent to our DNS server.
        dns.matchDomains = config.tunnelMatchDomains
        settings.dnsSettings = dns

        settings.mtu = 1500
        return settings
    }

    // MARK: - Packet loop

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.running else { return }
            self.workQueue.async {
                self.handle(packets: packets, protocols: protocols)
            }
            // Continue reading.
            if self.running { self.readPackets() }
        }
    }

    private func handle(packets: [Data], protocols: [NSNumber]) {
        let dnsIpBytes = IpParsing.ipv4Bytes(dnsServerIp) ?? []
        var responses: [Data] = []
        var responseProtocols: [NSNumber] = []

        for (index, packet) in packets.enumerated() {
            // Only IPv4 UDP DNS is routed here (settings claim IPv4 /32 only).
            let proto = index < protocols.count ? protocols[index].int32Value : AF_INET
            guard proto == AF_INET else { continue }

            let bytes = [UInt8](packet)
            guard let request = TunPacketCodec.parseIpv4UdpDns(bytes, length: bytes.count, expectedDestIp: dnsIpBytes),
                  let query = DnsPacketCodec.parseDnsQuery(request.payload) else {
                continue
            }

            let responsePayload = resolvePayload(request: request, query: query)
            let responsePacket = TunPacketCodec.buildIpv4UdpResponse(request: request, responsePayload: responsePayload)
            responses.append(Data(responsePacket))
            responseProtocols.append(NSNumber(value: AF_INET))
        }

        if !responses.isEmpty {
            packetFlow.writePackets(responses, withProtocols: responseProtocols)
        }
    }

    private func resolvePayload(request: UdpDnsPacket, query: ParsedDnsQuery) -> [UInt8] {
        guard let resolver = resolver else {
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: [], responseCode: 2))
        }
        guard config.shouldUseManagedDoh(query.name) || config.findDnsHostOverride(query.name) != nil else {
            // Not a managed host: return SERVFAIL so the client retries via system DNS.
            // (In practice matchDomains means only managed hosts reach us.)
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: [], responseCode: 2))
        }
        do {
            return try resolver.resolveManagedPayload(requestPayload: request.payload, query: query)
        } catch {
            os_log("DoH resolve failed for %{public}@ type=%{public}@: %{public}@",
                   log: log, type: .error, query.name, "\(query.type)", "\(error)")
            return DnsPacketCodec.buildResponse(query: query, resolution: DnsResolution(answers: [], responseCode: 2))
        }
    }
}
