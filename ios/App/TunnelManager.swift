import Foundation
import NetworkExtension
import Combine

/// Installs and controls the packet-tunnel VPN configuration. Mirrors the
/// start/stop role of the Android MainActivity + VpnService.prepare flow.
@MainActor
final class TunnelManager: ObservableObject {
    enum Status: Equatable {
        case notReady
        case disconnected
        case connecting
        case connected
        case disconnecting
        case failed(String)

        var text: String {
            switch self {
            case .notReady: return "未就绪"
            case .disconnected: return "未启动"
            case .connecting: return "正在启动"
            case .connected: return "加速中"
            case .disconnecting: return "正在停止"
            case .failed(let m): return "启动失败：\(m)"
            }
        }

        var isRunning: Bool { self == .connected || self == .connecting }
    }

    @Published private(set) var status: Status = .notReady
    @Published var detail: String = "接管域名走本地 ECH 代理（需信任根证书）；其它流量直连。"

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private let tunnelBundleId = "io.linuxdo.accelerator.PacketTunnel"

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first ?? NETunnelProviderManager()
            observeStatus()
            syncStatus()
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func start() async {
        do {
            try await ensureInstalled()
            try manager?.connection.startVPNTunnel()
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    /// Asks the running extension for the CA DER over IPC. Requires the tunnel
    /// to be connected (the extension owns the cert in its own sandbox).
    func fetchCaDer(completion: @escaping (Data?) -> Void) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected else {
            completion(nil)
            return
        }
        let message = Data("export-ca".utf8)
        do {
            try session.sendProviderMessage(message) { response in
                DispatchQueue.main.async { completion(response) }
            }
        } catch {
            completion(nil)
        }
    }

    // MARK: - Configuration

    private func ensureInstalled() async throws {
        let manager = self.manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelBundleId
        // Required by NE even for on-device tunnels; value is cosmetic here.
        proto.serverAddress = "linux.do Accelerator"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Linux.do 加速器"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        // Reload so the connection object reflects the saved config.
        try await manager.loadFromPreferences()
        self.manager = manager
        observeStatus()
    }

    // MARK: - Status

    private func observeStatus() {
        guard let connection = manager?.connection else { return }
        if let observer = observer { NotificationCenter.default.removeObserver(observer) }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.syncStatus() }
        }
    }

    private func syncStatus() {
        guard let connection = manager?.connection else {
            status = .notReady
            return
        }
        switch connection.status {
        case .invalid: status = .notReady
        case .disconnected: status = .disconnected
        case .connecting, .reasserting: status = .connecting
        case .connected: status = .connected
        case .disconnecting: status = .disconnecting
        @unknown default: status = .disconnected
        }
    }

    deinit {
        if let observer = observer { NotificationCenter.default.removeObserver(observer) }
    }
}
