import Foundation

/// Builds a `.mobileconfig` profile embedding the local root CA so iOS can
/// install it. After install the user must still enable full trust under
/// Settings → General → About → Certificate Trust Settings.
enum MobileConfig {
    static func build(caDer: Data) -> Data? {
        let certBase64 = caDer.base64EncodedString()
        // Stable-ish UUIDs derived from the cert so re-installs replace cleanly.
        let payloadUuid = deterministicUuid(caDer, salt: "payload")
        let certUuid = deterministicUuid(caDer, salt: "cert")

        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadCertificateFileName</key>
                    <string>linuxdo-accelerator-root-ca.cer</string>
                    <key>PayloadContent</key>
                    <data>
                    \(certBase64)
                    </data>
                    <key>PayloadDescription</key>
                    <string>Linux.do Accelerator 本地根证书</string>
                    <key>PayloadDisplayName</key>
                    <string>Linux.do Accelerator Root CA</string>
                    <key>PayloadIdentifier</key>
                    <string>io.linuxdo.accelerator.ca</string>
                    <key>PayloadType</key>
                    <string>com.apple.security.root</string>
                    <key>PayloadUUID</key>
                    <string>\(certUuid)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Linux.do Accelerator</string>
            <key>PayloadDescription</key>
            <string>安装并信任 Linux.do Accelerator 本地根证书，用于本机 HTTPS 接管。</string>
            <key>PayloadIdentifier</key>
            <string>io.linuxdo.accelerator.profile</string>
            <key>PayloadOrganization</key>
            <string>linux.do</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(payloadUuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
        return xml.data(using: .utf8)
    }

    /// Derives a stable UUID string from bytes so repeated installs share IDs.
    private static func deterministicUuid(_ data: Data, salt: String) -> String {
        var hasher = Hasher()
        hasher.combine(data)
        hasher.combine(salt)
        let h = UInt64(bitPattern: Int64(hasher.finalize()))
        // Format as a UUID-shaped string; uniqueness within this app is enough.
        let hi = String(format: "%08X", UInt32(truncatingIfNeeded: h >> 32))
        let lo = String(format: "%08X", UInt32(truncatingIfNeeded: h))
        return "\(hi)-\(lo.prefix(4))-4\(lo.dropFirst(4).prefix(3))-8\(hi.dropFirst(1).prefix(3))-\(hi)\(lo.prefix(4))"
    }
}
