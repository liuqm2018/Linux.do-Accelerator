import Foundation

/// Loads/saves the shared config from the App Group container so the app and the
/// packet-tunnel extension read the same file. Falls back to the bundled default.
enum ConfigStore {
    static func containerURL() -> URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: LinuxdoConfig.appGroupId
        )
    }

    /// Location of the persisted config. Prefers the App Group container, but
    /// falls back to this process's own Application Support dir when the App
    /// Group entitlement is absent (self-signed with lcsign). Without App Group
    /// the app and extension have separate homes, so the edited config also
    /// travels to the extension via `providerConfiguration` (see TunnelManager).
    static func configURL() -> URL? {
        if let container = containerURL() {
            return container.appendingPathComponent(LinuxdoConfig.configFileName)
        }
        guard let support = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ) else { return nil }
        return support.appendingPathComponent(LinuxdoConfig.configFileName)
    }

    /// Reads the config, preferring the persisted file, else the bundled default.
    static func load() -> LinuxdoConfig {
        if let url = configURL(),
           let text = try? String(contentsOf: url, encoding: .utf8),
           let parsed = try? MiniToml.parse(text) {
            return apply(parsed, onto: .bundledDefault)
        }
        return .bundledDefault
    }

    /// Parses a TOML string (e.g. one delivered via providerConfiguration) into
    /// a config, falling back to the bundled default on parse failure.
    static func from(toml text: String) -> LinuxdoConfig {
        guard let parsed = try? MiniToml.parse(text) else { return .bundledDefault }
        return apply(parsed, onto: .bundledDefault)
    }

    /// Writes raw TOML to the persisted config location. Used by the extension to
    /// mirror the config delivered via providerConfiguration into its own file,
    /// so the Rust core (which reads via load()) sees the user's DoH edits.
    @discardableResult
    static func persist(toml text: String) -> Bool {
        guard let url = configURL() else { return false }
        return (try? text.write(to: url, atomically: true, encoding: .utf8)) != nil
    }

    /// Ensures a config file exists in the App Group container on first launch.
    @discardableResult
    static func ensureSeeded() -> Bool {
        guard let url = configURL() else { return false }
        if FileManager.default.fileExists(atPath: url.path) { return true }
        return save(.bundledDefault)
    }

    /// Serializes the currently persisted config to TOML, for delivery to the
    /// extension via providerConfiguration (works without an App Group).
    static func serializedCurrent() -> String {
        serialize(load())
    }

    /// TOML handed to the Rust proxy core. Forces listen_host to loopback so the
    /// core binds 127.0.0.1 regardless of what a stale container file contains.
    /// Fields not written here fall back to the core's serde defaults.
    static func proxyToml() -> String {
        var config = load()
        config.listenHost = LinuxdoConfig.loopbackHost
        return serialize(config)
    }

    @discardableResult
    static func save(_ config: LinuxdoConfig) -> Bool {
        guard let url = configURL() else { return false }
        let text = serialize(config)
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Mapping

    private static func apply(_ table: [String: MiniTomlValue], onto base: LinuxdoConfig) -> LinuxdoConfig {
        var cfg = base
        if let v = table["listen_host"]?.asString { cfg.listenHost = v }
        if let v = table["doh_endpoints"]?.asStringArray { cfg.dohEndpoints = v }
        if let v = table["managed_prefer_ipv6"]?.asBool { cfg.preferManagedIpv6 = v }
        if let v = table["proxy_domains"]?.asStringArray { cfg.proxyDomains = v }
        if let v = table["dns_hosts"]?.asStringMap { cfg.dnsHosts = v }
        return cfg
    }

    private static func serialize(_ config: LinuxdoConfig) -> String {
        var lines: [String] = []
        lines.append("listen_host = \(quote(config.listenHost))")
        lines.append("managed_prefer_ipv6 = \(config.preferManagedIpv6)")
        lines.append("")
        lines.append("doh_endpoints = [")
        for endpoint in config.dohEndpoints {
            lines.append("    \(quote(endpoint)),")
        }
        lines.append("]")
        lines.append("")
        lines.append("proxy_domains = [")
        for domain in config.proxyDomains {
            lines.append("    \(quote(domain)),")
        }
        lines.append("]")
        if !config.dnsHosts.isEmpty {
            lines.append("")
            let pairs = config.dnsHosts
                .map { "\(quote($0.key)) = \(quote($0.value))" }
                .sorted()
                .joined(separator: ", ")
            lines.append("dns_hosts = { \(pairs) }")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func quote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
