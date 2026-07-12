import Foundation

/// Mirrors the fields the Android `LinuxdoConfig` consumes from
/// `linuxdo-accelerator.toml`. Only the subset needed for DNS takeover is kept.
struct LinuxdoConfig {
    var listenHost: String
    var dohEndpoints: [String]
    var preferManagedIpv6: Bool
    var dnsHosts: [String: String]
    var proxyDomains: [String]

    static let appGroupId = "group.io.linuxdo.accelerator"
    static let configFileName = "linuxdo-accelerator.toml"

    /// The proxy binds here and managed domains resolve here. Plain 127.0.0.1 is
    /// the only loopback address guaranteed bindable on iOS, and loopback is
    /// shared device-wide so the browser reaches the in-extension proxy directly.
    static let loopbackHost = "127.0.0.1"

    /// Baked-in fallback, kept in sync with `assets/defaults/linuxdo-accelerator.toml`
    /// except listen_host, which is forced to loopback for the on-device proxy.
    static let bundledDefault = LinuxdoConfig(
        listenHost: loopbackHost,
        dohEndpoints: ["https://aaa.ddd.oaifree.com/query-dns"],
        preferManagedIpv6: false,
        dnsHosts: [:],
        proxyDomains: ["linux.do", "*.linux.do", "idcflare.com", "*.idcflare.com"]
    )

    // MARK: - Domain matching (ports Android LinuxdoConfig)

    func shouldUseManagedDoh(_ host: String) -> Bool { matchesProxyHost(host) }

    func matchesProxyHost(_ host: String) -> Bool {
        let candidate = host.lowercased()
        return proxyDomains.contains { pattern in
            let normalized = pattern.lowercased()
            if normalized.hasPrefix("*.") {
                return candidate.hasSuffix("." + String(normalized.dropFirst(2)))
            }
            return candidate == normalized
        }
    }

    func findDnsHostOverride(_ host: String) -> String? {
        let candidate = host.lowercased()
        if let direct = dnsHosts[candidate] { return direct }

        return dnsHosts
            .compactMap { (pattern, target) -> (Int, String)? in
                let normalized = pattern.lowercased()
                guard normalized.hasPrefix("*.") else { return nil }
                let suffix = String(normalized.dropFirst(2))
                return candidate.hasSuffix("." + suffix) ? (suffix.count, target) : nil
            }
            .max(by: { $0.0 < $1.0 })?
            .1
    }

    /// The set of apex/wildcard domains routed into the tunnel. `NEDNSSettings`
    /// matchDomains use suffix matching, so `*.` prefixes are stripped and the
    /// bare apex covers itself.
    var tunnelMatchDomains: [String] {
        var result = Set<String>()
        for pattern in proxyDomains {
            let normalized = pattern.lowercased()
            result.insert(normalized.hasPrefix("*.") ? String(normalized.dropFirst(2)) : normalized)
        }
        return Array(result).sorted()
    }
}
