# OfficeClaw OAuth Vue Debug

独立 Vue + Node Demo，用于调试你要求的完整 6 步登录流（使用当前项目中的真实地址默认值）：

1. PKCE 生成（`code_verifier` / `code_challenge` / `state`）
2. 登录页点击登录，跳转授权页
3. 返回登录页，获取 `code` + `state`
4. 根据授权码换 token（调用 IAM `/v1/oauth2/tokens`）
5. 调用 `permission-validate`
6. 刷新 token（`grant_type=refresh_token`）

## 启动

1. 安装依赖

```bash
npm install
```

2. （可选）配置后端地址

```bash
cp .env.example .env
# 按需修改 VITE_API_TARGET
```

3. 启动（前端+后端一起）

```bash
npm run dev
```

默认地址：`http://127.0.0.1:5173`

## 使用说明

- 页面会展示真实默认地址：`AUTH_BASE` / `IAM_TOKEN_URL` / `HUAWEI_CLAW_BASE` / `CLIENT_ID` / `REDIRECT_URI`
- Step1 执行后可拿到 PKCE 三件套与 `authorizeUrl`
- Step2 直接在浏览器打开授权页
- 默认 `redirect_uri` 是本地页：`http://127.0.0.1:3008/demo-callback`
- 授权成功后会跳到本地捕获页，点击“复制完整回调URL”，粘贴到 Step3 输入框解析
- Step3 同样支持粘贴 `officeclaw://oauth/callback?...` 或普通 URL 回调地址自动提取参数
- Step4 由 Vue 调用本地 `/demo-api/flow/exchange`，再由 server 代理 IAM `/v1/oauth2/tokens`
- Step5 由 Vue 调用本地 `/demo-api/flow/permission-validate`，再由 server 代理远端接口
- Step6 由 Vue 调用本地 `/demo-api/flow/refresh`，再由 server 代理 IAM 刷新

## 注意

- 这是调试 demo，不会改动你主仓库登录逻辑。
- OAuth 平台上必须把 `redirect_uri` 加入白名单（默认是 `http://127.0.0.1:3008/demo-callback`）。
