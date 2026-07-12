import Foundation
import LinuxdoCore

/// Swift wrapper over the Rust ECH proxy core (liblinuxdo_accelerator.a).
/// See ios/Vendor/linuxdo_core.h for the C ABI.
final class RustCore {
    /// Opaque handle to a running proxy, or nil when stopped.
    private var handle: OpaquePointer?

    /// Writable home for the core (config + certs). Prefers the App Group
    /// container, but falls back to this process's own Application Support dir
    /// when the App Group entitlement is absent (e.g. self-signed with lcsign).
    /// Without App Group the app and extension have separate homes, so the CA
    /// is shared from the extension to the app over IPC, not via a shared file.
    static func homeDirectory() -> String? {
        if let url = ConfigStore.containerURL() {
            return url.path
        }
        if let support = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ) {
            return support.appendingPathComponent("linuxdo-accelerator").path
        }
        return NSTemporaryDirectory() + "linuxdo-accelerator"
    }

    /// Serializes the current shared config to TOML text for the core, with
    /// listen_host forced to loopback so the proxy binds 127.0.0.1.
    static func configToml() -> String {
        ConfigStore.proxyToml()
    }

    /// Bundle PEMs the app generates and shares with the extension.
    struct Bundle {
        let caPem: String
        let serverCertPem: String
        let serverKeyPem: String
    }

    var isRunning: Bool { handle != nil }

    /// Starts the proxy using caller-provided cert PEMs (shared from the app via
    /// providerConfiguration). Returns false on failure.
    @discardableResult
    func startWithCerts(_ bundle: Bundle) -> Bool {
        guard handle == nil, let home = RustCore.homeDirectory() else { return false }
        let toml = RustCore.configToml()
        handle = toml.withCString { tomlPtr in
            home.withCString { homePtr in
                bundle.caPem.withCString { caPtr in
                    bundle.serverCertPem.withCString { certPtr in
                        bundle.serverKeyPem.withCString { keyPtr in
                            linuxdo_proxy_start_with_certs(
                                toml.isEmpty ? nil : tomlPtr, homePtr, caPtr, certPtr, keyPtr)
                        }
                    }
                }
            }
        }
        return handle != nil
    }

    func stop() {
        guard let handle = handle else { return }
        linuxdo_proxy_stop(handle)
        self.handle = nil
    }

    /// Ensures the bundle and returns the CA DER (for install) plus the three
    /// PEMs (for sharing with the extension). Generated in the app's own home,
    /// so it works without a running tunnel and without App Group.
    static func exportBundle() -> (caDer: Data, bundle: Bundle)? {
        guard let home = homeDirectory() else { return nil }
        let toml = configToml()
        let ptr: UnsafeMutablePointer<CChar>? = toml.withCString { tomlPtr in
            home.withCString { homePtr in
                linuxdo_export_bundle(toml.isEmpty ? nil : tomlPtr, homePtr)
            }
        }
        guard let ptr = ptr else { return nil }
        let text = String(cString: ptr)
        linuxdo_free_cstr(ptr)

        guard let bundle = parseBundle(text),
              let caDer = pemToDer(bundle.caPem) else { return nil }
        return (caDer, bundle)
    }

    /// Splits the sentinel-delimited export into the three PEM sections.
    private static func parseBundle(_ text: String) -> Bundle? {
        guard let caPem = between(text, "-----LDA-CA-----\n", "\n-----LDA-CERT-----\n"),
              let certPem = between(text, "-----LDA-CERT-----\n", "\n-----LDA-KEY-----\n"),
              let keyPem = after(text, "-----LDA-KEY-----\n") else { return nil }
        return Bundle(caPem: caPem, serverCertPem: certPem, serverKeyPem: keyPem)
    }

    private static func between(_ text: String, _ a: String, _ b: String) -> String? {
        guard let r1 = text.range(of: a), let r2 = text.range(of: b, range: r1.upperBound..<text.endIndex)
        else { return nil }
        return String(text[r1.upperBound..<r2.lowerBound])
    }

    private static func after(_ text: String, _ a: String) -> String? {
        guard let r = text.range(of: a) else { return nil }
        return String(text[r.upperBound...])
    }

    /// Decodes a single-cert PEM into DER bytes.
    private static func pemToDer(_ pem: String) -> Data? {
        let body = pem.split(separator: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
        return Data(base64Encoded: body)
    }

    /// The last error recorded by the Rust core, for diagnostics.
    static func lastError() -> String? {
        guard let ptr = linuxdo_last_error() else { return nil }
        let message = String(cString: ptr)
        linuxdo_free_cstr(ptr)
        return message.isEmpty ? nil : message
    }
}
