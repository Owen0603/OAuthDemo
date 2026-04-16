# OAuth 2.0 登录 Demo（Mac + Windows）

## 项目结构

```
OAuth2Demo/
├── mock_oauth_server.py          # Python 模拟 OAuth 服务器（Mac/Windows 共用）
├── OAuth2MacApp/                 # macOS Xcode 项目 (SwiftUI)
│   ├── OAuth2MacApp.xcodeproj/
│   └── OAuth2MacApp/
│       ├── OAuth2MacAppApp.swift  # 应用入口，处理 URL Scheme 回调
│       ├── ContentView.swift      # 登录界面
│       ├── AuthManager.swift      # OAuth 认证核心逻辑
│       ├── Info.plist             # 注册自定义 URL Scheme
│       └── OAuth2MacApp.entitlements
├── OAuth2WinApp/                 # Windows WPF 项目 (.NET 8 / C#)
│   ├── OAuth2WinApp.sln
│   ├── OAuth2WinApp.csproj
│   ├── App.xaml / App.xaml.cs     # 应用入口
│   ├── MainWindow.xaml / .cs      # 登录界面
│   └── AuthManager.cs             # OAuth 认证核心逻辑
└── README.md
```

## 登录流程

Mac 和 Windows 应用的登录流程一致，仅回调方式不同：

| | Mac 应用 | Windows 应用 |
|---|---|---|
| **回调方式** | Custom URL Scheme (`oauth2macapp://callback`) | 本地 HTTP 监听 (`http://localhost:8769/callback`) |
| **Client ID** | `demo-mac-app` | `demo-win-app` |

```
桌面应用                浏览器               模拟 OAuth 服务器
  │                      │                       │
  │── 1.点击登录 ────────>│                       │
  │   (打开浏览器)        │── 2.GET /authorize ──>│
  │                      │<── 3.返回登录页面 ─────│
  │                      │── 4.提交用户名密码 ──>│
  │                      │<── 5.重定向回应用 ─────│
  │<── 6.收到回调 ───────│   (code+state)         │
  │── 7.POST /token ─────────────────────────────>│
  │<── 8.返回 access_token ──────────────────────│
  │── 9.GET /userinfo ───────────────────────────>│
  │<── 10.返回用户信息 ──────────────────────────│
  │                                               │
  ✅ 登录成功!
```

---

## 运行步骤

### 第 1 步：启动模拟 OAuth 服务器

```bash
cd ~/Desktop/OAuth2Demo
python3 mock_oauth_server.py
```

服务器会在 `http://localhost:8089` 启动。

---

### Mac 应用

#### 第 2 步：用 Xcode 打开并运行

```bash
open ~/Desktop/OAuth2Demo/OAuth2MacApp/OAuth2MacApp.xcodeproj
```

在 Xcode 中按 `Cmd + R` 运行应用。

#### 第 3 步：测试登录

1. 在 Mac 应用中点击 **「使用浏览器登录」**
2. 浏览器会打开模拟的 OAuth 登录页面
3. 用户名密码已预填（demo_user / 123456），直接点击 **「授权并登录」**
4. 浏览器显示"授权成功"后自动跳转回 Mac 应用
5. Mac 应用显示登录成功，展示用户信息

---

### Windows 应用

#### 前置条件

- 安装 [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

#### 第 2 步：编译并运行

```bash
cd OAuth2WinApp
dotnet run
```

#### 第 3 步：测试登录

1. 在 Windows 应用中点击 **「使用浏览器登录」**
2. 浏览器会打开模拟的 OAuth 登录页面
3. 用户名密码已预填（demo_user / 123456），直接点击 **「授权并登录」**
4. 浏览器将回调到本地 `http://localhost:8769/callback`，应用自动接收授权码
5. Windows 应用显示登录成功，展示用户信息

---

## 关键技术点

| 技术 | Mac | Windows | 说明 |
|------|-----|---------|------|
| **回调机制** | Custom URL Scheme | 本地 HTTP 监听器 | Mac 用 `oauth2macapp://`，Windows 用 `HttpListener` 监听 localhost |
| **PKCE** | ✅ | ✅ | 使用 S256 code_challenge，防止授权码被截获 |
| **State 参数** | ✅ | ✅ | 防止 CSRF 攻击 |
| **UI 框架** | SwiftUI | WPF (XAML) | 各平台原生 UI |
