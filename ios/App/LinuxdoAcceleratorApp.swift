import SwiftUI

@main
struct LinuxdoAcceleratorApp: App {
    init() {
        // Seed the shared config into the App Group on first launch.
        ConfigStore.ensureSeeded()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
