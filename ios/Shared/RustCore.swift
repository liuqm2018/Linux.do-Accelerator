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

    var isRunning: Bool { handle != nil }

    /// Starts the local ECH proxy. Returns false on failure.
    @discardableResult
    func start() -> Bool {
        guard handle == nil, let home = RustCore.homeDirectory() else { return false }
        let toml = RustCore.configToml()
        handle = toml.withCString { tomlPtr in
            home.withCString { homePtr in
                linuxdo_proxy_start(toml.isEmpty ? nil : tomlPtr, homePtr)
            }
        }
        return handle != nil
    }

    func stop() {
        guard let handle = handle else { return }
        linuxdo_proxy_stop(handle)
        self.handle = nil
    }

    /// Ensures the CA exists and returns its DER bytes for trust installation.
    static func exportCaDer() -> Data? {
        guard let home = homeDirectory() else { return nil }
        let toml = configToml()
        var length: Int = 0
        let ptr: UnsafeMutablePointer<UInt8>? = toml.withCString { tomlPtr in
            home.withCString { homePtr in
                linuxdo_export_ca_der(toml.isEmpty ? nil : tomlPtr, homePtr, &length)
            }
        }
        guard let ptr = ptr, length > 0 else { return nil }
        let data = Data(bytes: ptr, count: length)
        linuxdo_free_bytes(ptr, length)
        return data
    }
}
