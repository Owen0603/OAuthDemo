import Foundation
import AppKit
import CryptoKit

@MainActor
class AuthManager: ObservableObject {
    @Published var isLoggedIn = false
    @Published var isLoading = false
    @Published var accessToken = ""
    @Published var username = ""
    @Published var email = ""
    @Published var errorMessage: String?

    // OAuth 配置 - 指向本地模拟服务器
    private let authorizationEndpoint = "http://localhost:8089/authorize"
    private let tokenEndpoint = "http://localhost:8089/token"
    private let userInfoEndpoint = "http://localhost:8089/userinfo"
    private let clientID = "demo-mac-app"
    private let redirectURI = "oauth2macapp://callback"

    // PKCE 参数
    private var codeVerifier = ""
    private var state = ""

    // MARK: - 发起 OAuth 登录

    func startOAuthLogin() {
        errorMessage = nil

        // 生成 PKCE code_verifier 和 code_challenge
        codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(from: codeVerifier)
        state = UUID().uuidString

        // 构建授权 URL
        var components = URLComponents(string: authorizationEndpoint)!
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]

        guard let url = components.url else {
            errorMessage = "无法构建授权 URL"
            return
        }

        // 打开浏览器进行授权
        NSWorkspace.shared.open(url)
    }

    // MARK: - 处理回调

    func handleCallback(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            errorMessage = "无效的回调 URL"
            return
        }

        // 检查是否有错误
        if let error = queryItems.first(where: { $0.name == "error" })?.value {
            errorMessage = "授权失败: \(error)"
            return
        }

        // 验证 state
        guard let returnedState = queryItems.first(where: { $0.name == "state" })?.value,
              returnedState == state else {
            errorMessage = "State 验证失败，可能存在 CSRF 攻击"
            return
        }

        // 获取 authorization code
        guard let code = queryItems.first(where: { $0.name == "code" })?.value else {
            errorMessage = "未收到授权码"
            return
        }

        // 用 code 换取 token
        isLoading = true
        Task {
            await exchangeCodeForToken(code: code)
        }
    }

    // MARK: - 用授权码换取 Token

    private func exchangeCodeForToken(code: String) async {
        let body = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectURI,
            "client_id": clientID,
            "code_verifier": codeVerifier,
        ]

        let bodyString = body.map { "\($0.key)=\($0.value)" }.joined(separator: "&")

        var request = URLRequest(url: URL(string: tokenEndpoint)!)
        request.httpMethod = "POST"
        request.httpBody = bodyString.data(using: .utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                errorMessage = "Token 请求失败"
                isLoading = false
                return
            }

            let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
            accessToken = tokenResponse.accessToken

            // 获取用户信息
            await fetchUserInfo(token: tokenResponse.accessToken)
        } catch {
            errorMessage = "网络错误: \(error.localizedDescription)"
            isLoading = false
        }
    }

    // MARK: - 获取用户信息

    private func fetchUserInfo(token: String) async {
        var request = URLRequest(url: URL(string: userInfoEndpoint)!)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                errorMessage = "获取用户信息失败"
                isLoading = false
                return
            }

            let userInfo = try JSONDecoder().decode(UserInfo.self, from: data)
            username = userInfo.name
            email = userInfo.email
            isLoggedIn = true
            isLoading = false
        } catch {
            errorMessage = "解析用户信息失败: \(error.localizedDescription)"
            isLoading = false
        }
    }

    // MARK: - 退出登录

    func logout() {
        isLoggedIn = false
        accessToken = ""
        username = ""
        email = ""
        codeVerifier = ""
        state = ""
    }

    // MARK: - PKCE 辅助方法

    private func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(buffer).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func generateCodeChallenge(from verifier: String) -> String {
        let data = Data(verifier.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// MARK: - 数据模型

struct TokenResponse: Decodable {
    let accessToken: String
    let tokenType: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
}

struct UserInfo: Decodable {
    let name: String
    let email: String
}
