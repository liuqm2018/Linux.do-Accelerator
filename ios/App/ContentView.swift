import SwiftUI

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()
    @State private var config = ConfigStore.load()
    @State private var showConfig = false
    @State private var certMessage: String?
    private let certInstaller = CertInstaller()

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    statusCard
                    actionButton
                    certCard
                    infoCard
                }
                .padding()
            }
            .navigationTitle("Linux.do 加速器")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showConfig = true } label: { Image(systemName: "gearshape") }
                }
            }
            .sheet(isPresented: $showConfig) {
                ConfigView(config: $config)
            }
        }
        .navigationViewStyle(.stack)
        .task { await tunnel.load() }
    }

    private var statusCard: some View {
        VStack(spacing: 10) {
            Image(systemName: tunnel.status.isRunning ? "bolt.horizontal.circle.fill" : "bolt.slash.circle")
                .font(.system(size: 56))
                .foregroundColor(tunnel.status.isRunning ? .green : .secondary)
            Text(tunnel.status.text)
                .font(.title2).bold()
            Text(tunnel.detail)
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    private var actionButton: some View {
        Button {
            Task {
                if tunnel.status.isRunning { tunnel.stop() }
                else { await tunnel.start() }
            }
        } label: {
            Text(tunnel.status.isRunning ? "停止加速" : "开始加速")
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(tunnel.status.isRunning ? Color.red : Color.accentColor)
                .foregroundColor(.white)
                .cornerRadius(12)
        }
    }

    private var certCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("根证书").font(.headline)
            Text("加速依赖本地 HTTPS 接管，需安装并信任根证书（一次性）。")
                .font(.footnote).foregroundColor(.secondary)
            Button {
                guard tunnel.status.isRunning else {
                    certMessage = "请先「开始加速」，证书由加速服务提供。"
                    return
                }
                certMessage = "正在从加速服务获取证书…"
                tunnel.fetchCaDer { result in
                    switch result {
                    case .failure(let reason):
                        certMessage = "获取证书失败：\(reason)"
                    case .success(let der):
                        certInstaller.installCA(caDer: der) { installResult in
                            switch installResult {
                            case .success:
                                certMessage = "已打开 Safari。按提示安装描述文件后，再到\n设置 → 通用 → VPN 与设备管理 → 安装，\n然后设置 → 通用 → 关于本机 → 证书信任设置 里打开信任开关。"
                            case .failure(let error):
                                certMessage = "安装失败：\(error.localizedDescription)"
                            }
                        }
                    }
                }
            } label: {
                Text("安装根证书")
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color.accentColor.opacity(0.15))
                    .foregroundColor(.accentColor)
                    .cornerRadius(10)
            }
            if let certMessage = certMessage {
                Text(certMessage).font(.caption).foregroundColor(.secondary)
            }
            Text("提示：安装后务必在「证书信任设置」里为本证书打开完全信任，否则浏览器会报证书错误。")
                .font(.caption2).foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    private var infoCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            row("接管域名", config.proxyDomains.joined(separator: ", "))
            Divider()
            row("DoH", config.dohEndpoints.first ?? "未配置")
            Divider()
            row("方式", "接管域名解析到本地 ECH 代理，代理用私人 DoH 取 ECH 记录后直连 Cloudflare；其它流量直连。需信任本地根证书。")
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    private func row(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundColor(.secondary)
            Text(value).font(.callout)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
