import Foundation

extension DohResolver {
    /// Synchronous GET returning raw body bytes; wraps URLSession with a semaphore.
    func syncGet(_ request: URLRequest) throws -> (Data, Int) {
        var resultData: Data?
        var resultStatus = 0
        var resultError: Error?
        let semaphore = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: request) { data, response, error in
            if let error = error { resultError = error }
            if let http = response as? HTTPURLResponse { resultStatus = http.statusCode }
            resultData = data
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + 12)
        if let error = resultError { throw DohError.transport(error.localizedDescription) }
        guard let data = resultData else { throw DohError.emptyBody }
        return (data, resultStatus)
    }

    func queryDohDnsMessage(rawEndpoint: String, endpoint: URL, host: String, type: Int) throws -> [DnsAnswerRecord] {
        let wire = DnsPacketCodec.buildWireQuery(domain: host, type: type)
        return try queryDohDnsMessageRaw(rawEndpoint: rawEndpoint, endpoint: endpoint, payload: wire, type: type)
    }

    func queryDohDnsMessageRaw(rawEndpoint: String, endpoint: URL, payload: [UInt8], type: Int) throws -> [DnsAnswerRecord] {
        let encoded = Data(payload).base64URLEncodedString()
        let separator = (endpoint.query?.isEmpty ?? true) ? "?" : "&"
        guard let url = URL(string: rawEndpoint + separator + "dns=" + encoded) else {
            throw DohError.transport("invalid DoH url")
        }
        var request = URLRequest(url: url)
        request.setValue("application/dns-message", forHTTPHeaderField: "accept")
        let (data, status) = try syncGet(request)
        if status != 0 && !(200...299).contains(status) { throw DohError.httpStatus(status) }
        if data.isEmpty { throw DohError.emptyBody }
        return try DnsPacketCodec.parseWireResponse([UInt8](data), requestedType: type)
    }

    func queryDohJson(rawEndpoint: String, endpoint: URL, host: String, type: Int) throws -> [DnsAnswerRecord] {
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
        var items = components?.queryItems ?? []
        items.append(URLQueryItem(name: "name", value: host))
        items.append(URLQueryItem(name: "type", value: DnsType.name(type)))
        components?.queryItems = items
        guard let url = components?.url else { throw DohError.transport("invalid DoH url") }

        var request = URLRequest(url: url)
        request.setValue("application/dns-json", forHTTPHeaderField: "accept")
        let (data, status) = try syncGet(request)
        if status != 0 && !(200...299).contains(status) { throw DohError.httpStatus(status) }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DohError.emptyBody
        }
        if let statusCode = json["Status"] as? Int, statusCode != 0 {
            throw DohError.httpStatus(statusCode)
        }
        guard let answers = json["Answer"] as? [[String: Any]] else { return [] }

        var records: [DnsAnswerRecord] = []
        for answer in answers {
            let answerType = (answer["type"] as? Int) ?? 0
            let ttl = (answer["TTL"] as? Int) ?? 60
            let dataString = (answer["data"] as? String) ?? ""
            switch answerType {
            case DnsType.a where type == DnsType.a:
                if let bytes = IpParsing.ipv4Bytes(dataString) {
                    records.append(DnsAnswerRecord(type: DnsType.a, ttl: ttl, data: bytes))
                }
            case DnsType.aaaa where type == DnsType.aaaa:
                if let bytes = IpParsing.ipv6Bytes(dataString) {
                    records.append(DnsAnswerRecord(type: DnsType.aaaa, ttl: ttl, data: bytes))
                }
            case DnsType.cname:
                records.append(DnsAnswerRecord(type: DnsType.cname, ttl: ttl, data: DnsPacketCodec.encodeDomainName(dataString)))
            default:
                break
            }
        }
        return records
    }
}

extension Data {
    /// URL-safe base64 without padding (RFC 4648 §5), as required for GET ?dns=.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// IPv4/IPv6 text → wire bytes using the C runtime's inet_pton.
enum IpParsing {
    static func ipv4Bytes(_ text: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, text, &addr) == 1 else { return nil }
        var value = addr.s_addr // network byte order already
        return withUnsafeBytes(of: &value) { Array($0) }
    }

    static func ipv6Bytes(_ text: String) -> [UInt8]? {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, text, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }
}
