import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { URL } from 'node:url';

const PORT = Number(process.env.DEMO_FLOW_PORT || 3008);
const HOST = process.env.DEMO_FLOW_HOST || '127.0.0.1';

const DEFAULT_IAM_BASE = 'https://sts-open.cn-north-7.myhuaweicloud.com';
const DEFAULT_AUTH_BASE = 'https://auth.ulanqab.huawei.com';
const DEFAULT_HUAWEI_CLAW_BASE = 'https://versatile.cn-north-4.myhuaweicloud.com';

const AUTH_BASE = stripTrailingSlash(process.env.OAUTH_AUTH_BASE || DEFAULT_AUTH_BASE);
const IAM_STS_BASE = stripTrailingSlash(process.env.OAUTH_IAM_BASE_URL || DEFAULT_IAM_BASE);
const HUAWEI_CLAW_BASE = stripTrailingSlash(process.env.HUAWEI_CLAW_URL || DEFAULT_HUAWEI_CLAW_BASE);
const IAM_TOKEN_URL = `${IAM_STS_BASE}/v1/oauth2/tokens`;

const CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'client-officeclaw';
const REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || `http://${HOST}:${PORT}/demo-callback`;
const SCOPE = 'openid';

const pendingStates = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, '');
}

function base64Url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createCodeVerifier() {
  return base64Url(randomBytes(64));
}

function createCodeChallenge(codeVerifier) {
  const digest = createHash('sha256').update(codeVerifier).digest();
  return base64Url(digest);
}

function createState() {
  return base64Url(randomBytes(24));
}

function json(res, status, data) {
  const payload = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(payload);
}

function pruneExpiredStates() {
  const now = Date.now();
  for (const [state, record] of pendingStates.entries()) {
    if (record.expiresAt < now) pendingStates.delete(state);
  }
}


const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);

  if (req.method === 'OPTIONS') {
    json(res, 204, {});
    return;
  }

  if (req.method === 'GET' && url.pathname === '/demo-callback') {
    const html = `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>OAuth 回调捕获页</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Helvetica Neue', Arial, sans-serif; margin: 0; background: #fff8f2; color: #1f1f1f; }
      .wrap { max-width: 900px; margin: 32px auto; padding: 16px; }
      .card { background: #fff; border: 1px solid #eedcca; border-radius: 12px; padding: 16px; }
      h1 { margin: 0 0 10px; font-size: 24px; }
      p { margin: 8px 0; color: #5f5f5f; }
      textarea { width: 100%; min-height: 120px; border: 1px solid #d7d7d7; border-radius: 8px; padding: 10px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace; font-size: 13px; }
      .row { display: flex; gap: 10px; margin-top: 12px; }
      button, a { border: none; border-radius: 999px; padding: 8px 14px; font-size: 12px; font-weight: 700; text-decoration: none; cursor: pointer; }
      button { background: #1d1d1d; color: #fff; }
      a { background: #f1f1f1; color: #1d1d1d; }
      code { background: #f7f7f7; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1>OAuth 回调已到达本地页面</h1>
        <p>把下面完整 URL 复制到 Vue Demo 的 Step3 输入框，然后点“解析回调参数”。</p>
        <p>当前默认回调地址：<code>${REDIRECT_URI}</code></p>
        <textarea id="urlBox" readonly></textarea>
        <div class="row">
          <button id="copyBtn" type="button">复制完整回调URL</button>
          <a href="http://127.0.0.1:5173" target="_blank" rel="noreferrer">打开 Vue Demo</a>
        </div>
      </div>
    </div>
    <script>
      const url = window.location.href;
      const box = document.getElementById('urlBox');
      const btn = document.getElementById('copyBtn');
      box.value = url;
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(url);
          btn.textContent = '已复制';
          setTimeout(() => (btn.textContent = '复制完整回调URL'), 1500);
        } catch {
          box.select();
          document.execCommand('copy');
          btn.textContent = '已复制';
          setTimeout(() => (btn.textContent = '复制完整回调URL'), 1500);
        }
      });
    </script>
  </body>
</html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  if (req.method === 'GET' && url.pathname === '/demo-api/flow/config') {
    json(res, 200, {
      authBase: AUTH_BASE,
      iamTokenUrl: IAM_TOKEN_URL,
      huaweiClawBase: HUAWEI_CLAW_BASE,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scope: SCOPE,
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/demo-api/flow/start') {
    pruneExpiredStates();
    const state = createState();
    const codeVerifier = createCodeVerifier();
    const codeChallenge = createCodeChallenge(codeVerifier);
    pendingStates.set(state, {
      codeVerifier,
      createdAt: Date.now(),
      expiresAt: Date.now() + STATE_TTL_MS,
    });

    const oauthParams = new URLSearchParams({
      client_id: CLIENT_ID,
      code_challenge: codeChallenge,
      code_challenge_method: 'SHA-256',
      state,
      scope: SCOPE,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
    });
    const innerUrl = `${AUTH_BASE}/authui/v1/oauth2/authorize?${oauthParams.toString()}`;
    const authorizeUrl = `${AUTH_BASE}/authui/login.html?service=${encodeURIComponent(innerUrl)}`;

    json(res, 200, {
      success: true,
      step: 1,
      state,
      codeVerifier,
      codeChallenge,
      authorizeUrl,
      generatedAt: new Date().toISOString(),
    });
    return;
  }

  json(res, 404, { error: 'Not Found' });
});

server.listen(PORT, HOST, () => {
  console.log(`[oauth-demo] server running at http://${HOST}:${PORT}`);
  console.log(`[oauth-demo] auth base: ${AUTH_BASE}`);
  console.log(`[oauth-demo] iam token: ${IAM_TOKEN_URL}`);
  console.log(`[oauth-demo] redirect uri: ${REDIRECT_URI}`);
});
