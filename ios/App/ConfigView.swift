import SwiftUI

/// Editing surface for the DoH endpoint and managed domains. Persists back into
/// the App Group config so the tunnel extension picks it up on next start.
struct ConfigView: View {
    @Binding var config: LinuxdoConfig
    @Environment(\.dismiss) private var dismiss

    @State private var dohText: String = ""
    @State private var domainsText: String = ""

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("DoH 端点（每行一个）"),
                        footer: Text("私人 DoH，需返回带 ECH 的 HTTPS/SVCB 记录。")) {
                    TextEditor(text: $dohText)
                        .frame(minHeight: 90)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                Section(header: Text("接管域名（每行一个）"),
                        footer: Text("支持 *.example.com 通配。只有这些域名的 DNS 会进入隧道。")) {
                    TextEditor(text: $domainsText)
                        .frame(minHeight: 120)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
            }
            .navigationTitle("配置")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save() }
                }
            }
            .onAppear {
                dohText = config.dohEndpoints.joined(separator: "\n")
                domainsText = config.proxyDomains.joined(separator: "\n")
            }
        }
    }

    private func save() {
        let endpoints = dohText
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let domains = domainsText
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }

        config.dohEndpoints = endpoints.isEmpty ? config.dohEndpoints : endpoints
        config.proxyDomains = domains.isEmpty ? config.proxyDomains : domains
        ConfigStore.save(config)
        dismiss()
    }
}
