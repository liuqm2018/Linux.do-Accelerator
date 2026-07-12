import SwiftUI

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()
    @State private var config = ConfigStore.load()
    @State private var showConfig = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    statusCard
                    actionButton
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
