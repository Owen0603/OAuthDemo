using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.IO;

namespace OAuth2WinApp
{
    public class AuthManager : INotifyPropertyChanged
    {
        // OAuth 配置 - 指向本地模拟服务器
        private const string AuthorizationEndpoint = "http://localhost:8089/authorize";
        private const string TokenEndpoint = "http://localhost:8089/token";
        private const string UserInfoEndpoint = "http://localhost:8089/userinfo";
        private const string ClientID = "demo-win-app";
        private const string RedirectURI = "http://localhost:8769/callback";

        // PKCE 参数
        private string _codeVerifier = "";
        private string _state = "";

        // 本地 HTTP 监听器，用于接收回调
        private HttpListener? _httpListener;

        // Python mock server 进程
        private Process? _serverProcess;

        private static readonly HttpClient _httpClient = new();

        public event PropertyChangedEventHandler? PropertyChanged;

        private bool _isLoggedIn;
        public bool IsLoggedIn
        {
            get => _isLoggedIn;
            set { _isLoggedIn = value; OnPropertyChanged(); }
        }

        private bool _isLoading;
        public bool IsLoading
        {
            get => _isLoading;
            set { _isLoading = value; OnPropertyChanged(); }
        }

        private string _accessToken = "";
        public string AccessToken
        {
            get => _accessToken;
            set { _accessToken = value; OnPropertyChanged(); }
        }

        private string _username = "";
        public string Username
        {
            get => _username;
            set { _username = value; OnPropertyChanged(); }
        }

        private string _email = "";
        public string Email
        {
            get => _email;
            set { _email = value; OnPropertyChanged(); }
        }

        private string? _errorMessage;
        public string? ErrorMessage
        {
            get => _errorMessage;
            set { _errorMessage = value; OnPropertyChanged(); }
        }

        // 发起 OAuth 登录
        public async Task StartOAuthLoginAsync()
        {
            ErrorMessage = null;

            // 确保 mock server 已启动
            if (!await EnsureServerRunningAsync())
                return;

            // 生成 PKCE code_verifier 和 code_challenge
            _codeVerifier = GenerateCodeVerifier();
            var codeChallenge = GenerateCodeChallenge(_codeVerifier);
            _state = Guid.NewGuid().ToString();

            // 启动本地 HTTP 监听器等待回调
            StartLocalListener();

            // 构建授权 URL
            static string Encode(string v) => Uri.EscapeDataString(v);
            var url = $"{AuthorizationEndpoint}"
                + $"?response_type=code"
                + $"&client_id={Encode(ClientID)}"
                + $"&redirect_uri={Encode(RedirectURI)}"
                + $"&scope={Encode("openid profile email")}"
                + $"&state={Encode(_state)}"
                + $"&code_challenge={Encode(codeChallenge)}"
                + $"&code_challenge_method=S256";

            // 打开浏览器进行授权
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

            // 等待回调
            await WaitForCallbackAsync();
        }

        // 启动本地 HTTP 监听器
        private void StartLocalListener()
        {
            StopLocalListener();
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add("http://localhost:8769/");
            _httpListener.Start();
        }

        private void StopLocalListener()
        {
            if (_httpListener != null)
            {
                try { _httpListener.Stop(); } catch { }
                _httpListener = null;
            }
        }

        // 等待浏览器回调
        private async Task WaitForCallbackAsync()
        {
            if (_httpListener == null) return;

            IsLoading = true;

            try
            {
                var context = await _httpListener.GetContextAsync();
                var request = context.Request;
                var queryParams = request.QueryString;

                // 返回成功页面给浏览器
                var responseHtml = """
                    <!DOCTYPE html>
                    <html><head><meta charset="UTF-8"><title>授权成功</title>
                    <style>
                        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #56ab2f, #a8e063);
                               min-height: 100vh; display: flex; align-items: center; justify-content: center; color: white; }
                        .card { background: rgba(255,255,255,0.2); backdrop-filter: blur(10px); padding: 40px 60px; border-radius: 16px; text-align: center; }
                    </style></head>
                    <body><div class="card"><h1>✅</h1><h2>授权成功!</h2><p>请返回应用查看结果，可以关闭此页面。</p></div></body>
                    </html>
                    """;
                var buffer = Encoding.UTF8.GetBytes(responseHtml);
                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.ContentLength64 = buffer.Length;
                await context.Response.OutputStream.WriteAsync(buffer);
                context.Response.Close();

                // 检查是否有错误
                var error = queryParams["error"];
                if (!string.IsNullOrEmpty(error))
                {
                    ErrorMessage = $"授权失败: {error}";
                    IsLoading = false;
                    return;
                }

                // 验证 state
                var returnedState = queryParams["state"];
                if (returnedState != _state)
                {
                    ErrorMessage = "State 验证失败，可能存在 CSRF 攻击";
                    IsLoading = false;
                    return;
                }

                // 获取 authorization code
                var code = queryParams["code"];
                if (string.IsNullOrEmpty(code))
                {
                    ErrorMessage = "未收到授权码";
                    IsLoading = false;
                    return;
                }

                // 用 code 换取 token
                await ExchangeCodeForTokenAsync(code);
            }
            catch (Exception ex)
            {
                ErrorMessage = $"回调处理错误: {ex.Message}";
                IsLoading = false;
            }
            finally
            {
                StopLocalListener();
            }
        }

        // 用授权码换取 Token
        private async Task ExchangeCodeForTokenAsync(string code)
        {
            var body = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RedirectURI,
                ["client_id"] = ClientID,
                ["code_verifier"] = _codeVerifier,
            };

            try
            {
                var response = await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                if (!response.IsSuccessStatusCode)
                {
                    ErrorMessage = "Token 请求失败";
                    IsLoading = false;
                    return;
                }

                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                if (tokenResponse == null)
                {
                    ErrorMessage = "Token 解析失败";
                    IsLoading = false;
                    return;
                }

                AccessToken = tokenResponse.AccessToken;

                // 获取用户信息
                await FetchUserInfoAsync(tokenResponse.AccessToken);
            }
            catch (Exception ex)
            {
                ErrorMessage = $"网络错误: {ex.Message}";
                IsLoading = false;
            }
        }

        // 获取用户信息
        private async Task FetchUserInfoAsync(string token)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, UserInfoEndpoint);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    ErrorMessage = "获取用户信息失败";
                    IsLoading = false;
                    return;
                }

                var json = await response.Content.ReadAsStringAsync();
                var userInfo = JsonSerializer.Deserialize<UserInfo>(json);
                if (userInfo == null)
                {
                    ErrorMessage = "用户信息解析失败";
                    IsLoading = false;
                    return;
                }

                Username = userInfo.Name;
                Email = userInfo.Email;
                IsLoggedIn = true;
                IsLoading = false;
            }
            catch (Exception ex)
            {
                ErrorMessage = $"解析用户信息失败: {ex.Message}";
                IsLoading = false;
            }
        }

        // 退出登录
        public void Logout()
        {
            IsLoggedIn = false;
            AccessToken = "";
            Username = "";
            Email = "";
            _codeVerifier = "";
            _state = "";
        }

        // 启动并等待 Mock OAuth Server 就绪
        private async Task<bool> EnsureServerRunningAsync()
        {
            // 先检测服务器是否已经在运行
            if (await IsServerReady())
                return true;

            // 查找 mock_oauth_server.py 的路径
            var serverScript = FindServerScript();
            if (serverScript == null)
            {
                ErrorMessage = "未找到 mock_oauth_server.py，请确保它在应用上级目录中";
                return false;
            }

            // 查找 Python 可执行文件
            var pythonCmd = FindPython();
            if (pythonCmd == null)
            {
                ErrorMessage = "未找到 Python，请安装 Python 3 并添加到 PATH";
                return false;
            }

            // 启动 Python 服务器
            try
            {
                _serverProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = pythonCmd,
                        Arguments = $"\"{serverScript}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    }
                };
                _serverProcess.Start();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"无法启动 OAuth 服务器: {ex.Message}";
                return false;
            }

            // 等待服务器就绪（最多 10 秒）
            for (int i = 0; i < 20; i++)
            {
                await Task.Delay(500);
                if (await IsServerReady())
                    return true;

                if (_serverProcess.HasExited)
                {
                    ErrorMessage = "OAuth 服务器启动失败，请检查 Python 环境";
                    return false;
                }
            }

            ErrorMessage = "OAuth 服务器启动超时";
            return false;
        }

        private static async Task<bool> IsServerReady()
        {
            try
            {
                var response = await _httpClient.GetAsync("http://localhost:8089/");
                return true; // 任何响应都说明服务器在运行
            }
            catch
            {
                return false;
            }
        }

        private static string? FindServerScript()
        {
            // 依次向上查找 mock_oauth_server.py
            var dir = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 5; i++)
            {
                var candidate = Path.Combine(dir, "mock_oauth_server.py");
                if (File.Exists(candidate))
                    return candidate;
                var parent = Directory.GetParent(dir);
                if (parent == null) break;
                dir = parent.FullName;
            }

            // 也检查工作目录
            var cwdCandidate = Path.Combine(Directory.GetCurrentDirectory(), "mock_oauth_server.py");
            if (File.Exists(cwdCandidate))
                return cwdCandidate;

            // 检查项目同级目录
            var projectDir = Directory.GetCurrentDirectory();
            var projectParent = Directory.GetParent(projectDir);
            if (projectParent != null)
            {
                var siblingCandidate = Path.Combine(projectParent.FullName, "mock_oauth_server.py");
                if (File.Exists(siblingCandidate))
                    return siblingCandidate;
            }

            return null;
        }

        private static string? FindPython()
        {
            foreach (var cmd in new[] { "python", "python3", "py" })
            {
                try
                {
                    var process = Process.Start(new ProcessStartInfo
                    {
                        FileName = cmd,
                        Arguments = "--version",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                    });
                    process?.WaitForExit(3000);
                    if (process?.ExitCode == 0)
                        return cmd;
                }
                catch { }
            }
            return null;
        }

        // 应用退出时关闭服务器
        public void StopServer()
        {
            if (_serverProcess != null && !_serverProcess.HasExited)
            {
                try { _serverProcess.Kill(); } catch { }
                _serverProcess = null;
            }
        }

        // PKCE 辅助方法
        private static string GenerateCodeVerifier()
        {
            var bytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        private static string GenerateCodeChallenge(string verifier)
        {
            var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        private void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    // 数据模型
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = "";

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = "";

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    public class UserInfo
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("email")]
        public string Email { get; set; } = "";
    }
}
