import SwiftUI

@main
struct OAuth2MacAppApp: App {
    @StateObject private var authManager = AuthManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(authManager)
                .onOpenURL { url in
                    authManager.handleCallback(url: url)
                }
        }
    }
}
