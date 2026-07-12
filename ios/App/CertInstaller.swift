import Foundation
import Network
import UIKit

/// Serves the CA `.mobileconfig` from a short-lived local HTTP server and opens
/// it in Safari, which triggers the iOS "Install Profile" flow. A local server
/// is used because iOS only presents the profile-install UI for profiles opened
/// via Safari (not from arbitrary in-app file handles).
final class CertInstaller {
    enum InstallError: LocalizedError {
        case noContainer
        case exportFailed
        case badProfile
        case server(String)

        var errorDescription: String? {
            switch self {
            case .noContainer:
                return "App Group 容器不可用。自签时请确认签名包含 App Group 权限 (group.io.linuxdo.accelerator)。"
            case .exportFailed:
                return "Rust 核心导出根证书失败（生成/写入证书出错）。"
            case .badProfile:
                return "构建描述文件失败。"
            case .server(let detail):
                return "本地服务器错误：\(detail)"
            }
        }
    }

    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private let queue = DispatchQueue(label: "io.linuxdo.accelerator.certserver")

    /// Builds a profile from the CA bytes (obtained from the running extension),
    /// serves it, and opens Safari. Calls back on the main thread.
    func installCA(caDer: Data, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let profile = MobileConfig.build(caDer: caDer) else {
            DispatchQueue.main.async { completion(.failure(InstallError.badProfile)) }
            return
        }

        do {
            let port = try startServer(profile: profile)
            guard let url = URL(string: "http://127.0.0.1:\(port)/linuxdo-accelerator.mobileconfig") else {
                throw InstallError.server("bad url")
            }
            DispatchQueue.main.async {
                UIApplication.shared.open(url, options: [:]) { opened in
                    completion(opened ? .success(()) : .failure(InstallError.server("无法打开 Safari")))
                }
            }
        } catch {
            DispatchQueue.main.async { completion(.failure(error)) }
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        connections.forEach { $0.cancel() }
        connections.removeAll()
    }

    // MARK: - Minimal HTTP server

    private func startServer(profile: Data) throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        let listener = try NWListener(using: params, on: .any)
        self.listener = listener

        listener.newConnectionHandler = { [weak self] connection in
            guard let self = self else { return }
            self.connections.append(connection)
            connection.start(queue: self.queue)
            self.serve(profile: profile, over: connection)
        }

        let sem = DispatchSemaphore(value: 0)
        var boundPort: UInt16 = 0
        var startError: Error?
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                boundPort = listener.port?.rawValue ?? 0
                sem.signal()
            case .failed(let error):
                startError = error
                sem.signal()
            default:
                break
            }
        }
        listener.start(queue: queue)

        if sem.wait(timeout: .now() + 5) == .timedOut {
            throw InstallError.server("本地服务器启动超时")
        }
        if let startError = startError { throw startError }
        if boundPort == 0 { throw InstallError.server("未能分配端口") }
        return boundPort
    }

    /// Reads (and ignores) the request, then writes the profile with the
    /// content type iOS expects for a config profile.
    private func serve(profile: Data, over connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] _, _, _, _ in
            guard let self = self else { return }
            var response = Data()
            let header = """
            HTTP/1.1 200 OK\r
            Content-Type: application/x-apple-aspen-config\r
            Content-Length: \(profile.count)\r
            Connection: close\r
            \r

            """
            response.append(header.data(using: .utf8) ?? Data())
            response.append(profile)
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.cancel()
                // One-shot: tear down shortly after serving.
                self.queue.asyncAfter(deadline: .now() + 1) { self.stop() }
            })
        }
    }
}
