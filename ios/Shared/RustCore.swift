import Foundation
import LinuxdoCore

/// Swift wrapper over the Rust ECH proxy core (liblinuxdo_accelerator.a).
/// See ios/Vendor/linuxdo_core.h for the C ABI.
final class RustCore {
    /// Opaque handle to a running proxy, or nil when stopped.
    private var handle: OpaquePointer?

    /// The writable App Group container the core uses for config + certs.
    static func homeDirectory() -> String? {
        ConfigStore.containerURL()?.path
    }

    /// Serializes the current shared config to TOML text for the core.
    static func configToml() -> String {
        // ConfigStore already persists TOML into the container; read it back so
        // the core and the app agree on one file.
        if let url = ConfigStore.configURL(),
           let text = try? String(contentsOf: url, encoding: .utf8) {
            return text
        }
        return ""
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
