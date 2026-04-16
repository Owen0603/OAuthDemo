#!/usr/bin/env python3
"""
模拟 OAuth 2.0 授权服务器
用于演示 Mac / Windows 应用的 OAuth 登录流程

端点:
  GET  /authorize  - 授权页面（模拟登录表单）
  POST /token      - Token 端点
  GET  /userinfo   - 用户信息端点
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
import json
import hashlib
import base64
import secrets
import sys

# 存储已发放的授权码和对应信息
auth_codes = {}
access_tokens = {}


class OAuthHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/authorize":
            self.handle_authorize(parsed)
        elif parsed.path == "/userinfo":
            self.handle_userinfo()
        elif parsed.path == "/login":
            self.handle_login(parsed)
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/token":
            self.handle_token()
        else:
            self.send_error(404)

    def handle_authorize(self, parsed):
        """显示模拟的登录页面"""
        params = parse_qs(parsed.query)

        client_id = params.get("client_id", [""])[0]
        redirect_uri = params.get("redirect_uri", [""])[0]
        state = params.get("state", [""])[0]
        code_challenge = params.get("code_challenge", [""])[0]
        code_challenge_method = params.get("code_challenge_method", [""])[0]
        scope = params.get("scope", [""])[0]

        # 生成一个临时 session id
        session_id = secrets.token_hex(16)
        auth_codes[session_id] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "scope": scope,
        }

        # 返回模拟的登录页面
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth 2.0 模拟登录</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .login-card {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            width: 380px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .login-card h1 {{
            text-align: center;
            color: #333;
            margin-bottom: 8px;
            font-size: 24px;
        }}
        .login-card .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 6px;
            color: #555;
            font-size: 14px;
            font-weight: 500;
        }}
        input {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 15px;
            transition: border-color 0.2s;
            outline: none;
        }}
        input:focus {{
            border-color: #667eea;
        }}
        .btn {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
        }}
        .btn:hover {{
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102,126,234,0.4);
        }}
        .btn:active {{
            transform: translateY(0);
        }}
        .info {{
            margin-top: 20px;
            padding: 12px;
            background: #f0f0ff;
            border-radius: 8px;
            font-size: 12px;
            color: #666;
        }}
        .info strong {{ color: #667eea; }}
    </style>
</head>
<body>
    <div class="login-card">
        <h1>🔐 OAuth 登录</h1>
        <p class="subtitle">模拟 OAuth 2.0 授权服务器</p>
        <form action="/login?session={session_id}" method="GET">
            <input type="hidden" name="session" value="{session_id}">
            <div class="form-group">
                <label>用户名</label>
                <input type="text" name="username" value="demo_user" required>
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" name="password" value="123456" required>
            </div>
            <button type="submit" class="btn">授权并登录</button>
        </form>
        <div class="info">
            <strong>提示：</strong>这是模拟服务器，用户名和密码已预填。
            直接点击「授权并登录」即可完成授权，浏览器将自动跳转回应用。
            <br><br>
            <strong>Client ID:</strong> {client_id}<br>
            <strong>Scope:</strong> {scope}
        </div>
    </div>
</body>
</html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def handle_login(self, parsed):
        """处理登录，生成授权码并重定向回应用"""
        params = parse_qs(parsed.query)
        session_id = params.get("session", [""])[0]

        if session_id not in auth_codes:
            self.send_error(400, "Invalid session")
            return

        session = auth_codes[session_id]

        # 生成授权码
        code = secrets.token_hex(20)
        auth_codes[code] = {
            "client_id": session["client_id"],
            "redirect_uri": session["redirect_uri"],
            "code_challenge": session["code_challenge"],
            "code_challenge_method": session["code_challenge_method"],
            "scope": session["scope"],
            "username": params.get("username", ["demo_user"])[0],
        }

        # 清理 session
        del auth_codes[session_id]

        # 构建回调 URL
        callback_params = urlencode({
            "code": code,
            "state": session["state"],
        })
        redirect_url = f"{session['redirect_uri']}?{callback_params}"

        # 显示成功页面并自动跳转
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>授权成功</title>
    <meta http-equiv="refresh" content="1;url={redirect_url}">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #56ab2f, #a8e063);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            text-align: center;
        }}
        .card {{
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(10px);
            padding: 40px 60px;
            border-radius: 16px;
        }}
        h1 {{ font-size: 48px; margin-bottom: 16px; }}
        p {{ font-size: 18px; opacity: 0.9; }}
        a {{ color: white; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>✅</h1>
        <h2>授权成功!</h2>
        <p>正在跳转回应用...</p>
        <p><small>如果没有自动跳转，<a href="{redirect_url}">请点击这里</a></small></p>
    </div>
    <script>
        // Mac 应用使用 URL Scheme 回调，跳转后页面可直接关闭
        // Windows 应用使用 localhost 回调，由应用端页面关闭
        setTimeout(function() {{
            window.location.href = "{redirect_url}";
        }}, 800);
        // 跳转完成后 3 秒尝试关闭（对 Windows localhost 回调有效）
        setTimeout(function() {{
            window.close();
        }}, 3500);
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))
        print(f"[AUTH] 授权码已发放: {code[:10]}... -> 重定向到 {session['redirect_uri']}")

    def handle_token(self):
        """处理 token 请求"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        code = params.get("code", [""])[0]
        code_verifier = params.get("code_verifier", [""])[0]
        client_id = params.get("client_id", [""])[0]

        if code not in auth_codes:
            self.send_json(400, {"error": "invalid_grant", "error_description": "Invalid authorization code"})
            return

        stored = auth_codes[code]

        # 验证 client_id
        if stored["client_id"] != client_id:
            self.send_json(400, {"error": "invalid_client"})
            return

        # 验证 PKCE code_verifier
        if stored["code_challenge_method"] == "S256" and stored["code_challenge"]:
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            if computed_challenge != stored["code_challenge"]:
                self.send_json(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                return

        # 生成 access_token
        token = secrets.token_hex(32)
        access_tokens[token] = {
            "username": stored.get("username", "demo_user"),
            "scope": stored["scope"],
        }

        # 清理授权码（一次性使用）
        del auth_codes[code]

        self.send_json(200, {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })
        print(f"[TOKEN] Access Token 已发放: {token[:10]}...")

    def handle_userinfo(self):
        """返回用户信息"""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self.send_json(401, {"error": "invalid_token"})
            return

        token = auth_header[7:]
        if token not in access_tokens:
            self.send_json(401, {"error": "invalid_token"})
            return

        user = access_tokens[token]
        self.send_json(200, {
            "sub": "user-001",
            "name": user["username"],
            "email": f"{user['username']}@example.com",
            "picture": "https://via.placeholder.com/100",
        })
        print(f"[USERINFO] 用户信息已返回: {user['username']}")

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}")


def main():
    port = 8089
    server = HTTPServer(("127.0.0.1", port), OAuthHandler)
    print(f"=" * 50)
    print(f"  OAuth 2.0 模拟服务器已启动")
    print(f"  地址: http://localhost:{port}")
    print(f"=" * 50)
    print(f"  授权端点: http://localhost:{port}/authorize")
    print(f"  Token端点: http://localhost:{port}/token")
    print(f"  用户信息: http://localhost:{port}/userinfo")
    print(f"=" * 50)
    print(f"\n等待 Mac / Windows 应用发起授权请求...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        server.server_close()


if __name__ == "__main__":
    main()
