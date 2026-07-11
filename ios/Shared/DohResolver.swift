import Foundation

enum DohError: Error {
    case noEndpoint
    case httpStatus(Int)
    case emptyBody
    case emptyAnswer
    case unsupported(String)
    case transport(String)
}

private struct CacheEntry {
    let resolution: DnsResolution
    let expiresAt: Date
}

/// Resolves managed domains through a private DoH endpoint. Ports Android
/// `LinuxdoDnsResolver`: local overrides, TTL cache, raw dns-message and JSON
/// query paths. Network calls run synchronously via a semaphore so the packet
/// loop can stay a simple read/resolve/write cycle.
final class DohResolver {
    private let config: LinuxdoConfig
    private let endpoints: [URL]
    private let rawEndpoints: [String]
    private var cache: [String: CacheEntry] = [:]
    private let cacheLock = NSLock()
    // Not private: accessed by the query methods in DohResolver+Query.swift.
    let session: URLSession

    init(config: LinuxdoConfig) {
        self.config = config
        self.rawEndpoints = config.dohEndpoints
        self.endpoints = config.dohEndpoints.compactMap { URL(string: $0) }
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = 10
        sessionConfig.timeoutIntervalForResource = 10
        // Avoid the system DNS cache biasing the DoH host lookup.
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: sessionConfig)
    }

    var primaryEndpointDescription: String { rawEndpoints.first ?? "未配置" }

    /// Resolves and returns a full DNS response payload for the given query.
    func resolveManagedPayload(requestPayload: [UInt8], query: ParsedDnsQuery) throws -> [UInt8] {
        let host = query.name.lowercased()

        if let cached = readCached(host: host, type: query.type) {
            return DnsPacketCodec.buildResponse(query: query, resolution: cached)
        }

        if let local = (try? resolveLocal(host: host, type: query.type)) ?? nil {
            let resolution = DnsResolution(answers: local)
            writeCache(host: host, type: query.type, resolution: resolution)
            return DnsPacketCodec.buildResponse(query: query, resolution: resolution)
        }

        guard let endpoint = endpoints.first, let rawEndpoint = rawEndpoints.first else {
            throw DohError.noEndpoint
        }

        if supportsDnsMessage(endpoint) {
            let answers = try queryDohDnsMessageRaw(rawEndpoint: rawEndpoint, endpoint: endpoint, payload: requestPayload, type: query.type)
            let resolution = DnsResolution(answers: answers)
            writeCache(host: host, type: query.type, resolution: resolution)
            return DnsPacketCodec.buildResponse(query: query, resolution: resolution)
        }

        if DnsType.isJsonFriendly(query.type) {
            let answers = try queryDohJson(rawEndpoint: rawEndpoint, endpoint: endpoint, host: host, type: query.type)
            if answers.isEmpty { throw DohError.emptyAnswer }
            let resolution = DnsResolution(answers: answers)
            writeCache(host: host, type: query.type, resolution: resolution)
            return DnsPacketCodec.buildResponse(query: query, resolution: resolution)
        }

        throw DohError.unsupported("endpoint does not support dns-message for type \(query.type)")
    }

    // MARK: - Local overrides

    private func resolveLocal(host: String, type: Int) throws -> [DnsAnswerRecord]? {
        guard let override = config.findDnsHostOverride(host) else { return nil }
        return try resolveOverride(override, type: type)
    }

    private func resolveOverride(_ raw: String, type: Int) throws -> [DnsAnswerRecord] {
        let value = raw.trimmingCharacters(in: .whitespaces)
        if value.hasPrefix("domain:") {
            let alias = String(value.dropFirst("domain:".count)).trimmingCharacters(in: .whitespaces)
            if alias.isEmpty { return [] }
            return (try? queryAlias(alias, type: type)) ?? []
        }
        if let literal = ipLiteralAnswer(value, type: type) { return literal }
        return (try? queryAlias(value, type: type)) ?? []
    }

    private func queryAlias(_ alias: String, type: Int) throws -> [DnsAnswerRecord] {
        guard let endpoint = endpoints.first, let rawEndpoint = rawEndpoints.first else { return [] }
        if supportsDnsMessage(endpoint) {
            return try queryDohDnsMessage(rawEndpoint: rawEndpoint, endpoint: endpoint, host: alias, type: type)
        }
        return try queryDohJson(rawEndpoint: rawEndpoint, endpoint: endpoint, host: alias, type: type)
    }

    private func ipLiteralAnswer(_ value: String, type: Int) -> [DnsAnswerRecord]? {
        if type == DnsType.a, let bytes = IpParsing.ipv4Bytes(value) {
            return [DnsAnswerRecord(type: DnsType.a, ttl: 60, data: bytes)]
        }
        if type == DnsType.aaaa, let bytes = IpParsing.ipv6Bytes(value) {
            return [DnsAnswerRecord(type: DnsType.aaaa, ttl: 60, data: bytes)]
        }
        // Value is an IP but wrong family for this query: no answer, not an alias.
        if IpParsing.ipv4Bytes(value) != nil || IpParsing.ipv6Bytes(value) != nil {
            return []
        }
        return nil
    }

    // MARK: - Cache

    private func readCached(host: String, type: Int) -> DnsResolution? {
        cacheLock.lock(); defer { cacheLock.unlock() }
        let key = "\(host)#\(type)"
        guard let entry = cache[key] else { return nil }
        if Date() >= entry.expiresAt {
            cache.removeValue(forKey: key)
            return nil
        }
        return entry.resolution
    }

    private func writeCache(host: String, type: Int, resolution: DnsResolution) {
        guard let minTtl = resolution.answers.map({ $0.ttl }).min() else { return }
        cacheLock.lock(); defer { cacheLock.unlock() }
        let key = "\(host)#\(type)"
        if minTtl <= 0 {
            cache.removeValue(forKey: key)
            return
        }
        cache = cache.filter { Date() < $0.value.expiresAt }
        cache[key] = CacheEntry(resolution: resolution, expiresAt: Date().addingTimeInterval(TimeInterval(minTtl)))
    }

    private func supportsDnsMessage(_ url: URL) -> Bool {
        !url.path.lowercased().hasSuffix("/resolve")
    }
}
