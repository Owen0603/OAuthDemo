import SwiftUI

struct ContentView: View {
    @EnvironmentObject var authManager: AuthManager

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: authManager.isLoggedIn ? "person.crop.circle.fill.badge.checkmark" : "person.crop.circle")
                .resizable()
                .scaledToFit()
                .frame(width: 80, height: 80)
                .foregroundColor(authManager.isLoggedIn ? .green : .gray)

            Text(authManager.isLoggedIn ? "登录成功!" : "OAuth 2.0 登录 Demo")
                .font(.title)
                .fontWeight(.bold)

            if authManager.isLoggedIn {
                VStack(alignment: .leading, spacing: 8) {
                    InfoRow(label: "用户名", value: authManager.username)
                    InfoRow(label: "邮箱", value: authManager.email)
                    InfoRow(label: "Access Token", value: String(authManager.accessToken.prefix(20)) + "...")
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.green.opacity(0.1)))

                Button("退出登录") {
                    authManager.logout()
                }
                .buttonStyle(.bordered)
                .tint(.red)
            } else {
                Text("点击下方按钮，将在浏览器中完成 OAuth 授权登录")
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                if authManager.isLoading {
                    ProgressView("正在处理回调...")
                } else {
                    Button("使用浏览器登录") {
                        authManager.startOAuthLogin()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }

                if let error = authManager.errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }
            }
        }
        .padding(40)
        .frame(width: 420, height: 380)
    }
}

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label + ":")
                .fontWeight(.medium)
                .frame(width: 100, alignment: .trailing)
            Text(value)
                .foregroundColor(.secondary)
                .textSelection(.enabled)
        }
    }
}
