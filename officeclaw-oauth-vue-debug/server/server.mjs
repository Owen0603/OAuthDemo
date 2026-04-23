import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { URL } from 'node:url';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { Agent } from 'undici';

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
const sessions = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 60 * 1000;
const TLS_INSECURE_SKIP_VERIFY = process.env.OAUTH_TLS_INSECURE_SKIP_VERIFY === '1';
const TLS_CA_CERT_PATH = process.env.OAUTH_TLS_CA_CERT_PATH || '';

let TLS_DISPATCHER;
if (TLS_INSECURE_SKIP_VERIFY) {
  TLS_DISPATCHER = new Agent({
    connect: {
      rejectUnauthorized: false,
    },
  });
} else if (TLS_CA_CERT_PATH) {
  try {
    const ca = readFileSync(TLS_CA_CERT_PATH, 'utf8');
    TLS_DISPATCHER = new Agent({
      connect: {
        ca,
      },
    });
  } catch (error) {
    console.warn(`[oauth-demo] failed to read OAUTH_TLS_CA_CERT_PATH: ${TLS_CA_CERT_PATH}`);
    console.warn(`[oauth-demo] tls ca load error: ${String(error)}`);
  }
}

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

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function parseIdTokenClaims(idToken) {
  try {
    const parts = String(idToken || '').split('.');
    if (parts.length < 2) return {};
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return {
      sub: typeof payload.sub === 'string' ? payload.sub : undefined,
      preferred_username: typeof payload.preferred_username === 'string' ? payload.preferred_username : undefined,
      name: typeof payload.name === 'string' ? payload.name : undefined,
    };
  } catch {
    return {};
  }
}

async function fetchWithTimeout(input, init) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(new Error('timeout')), FETCH_TIMEOUT_MS);

  try {
    const requestInit = {
      ...init,
      signal: controller.signal,
    };
    if (TLS_DISPATCHER) {
      requestInit.dispatcher = TLS_DISPATCHER;
    }

    return await fetch(input, {
      ...requestInit,
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function generateDpopProof(method, url) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const iat = Math.floor(Date.now() / 1000);
  const jti = base64Url(randomBytes(16));
  return new SignJWT({ htm: method.toUpperCase(), htu: url, jti })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
    .setIssuedAt(iat)
    .setExpirationTime(iat + 120)
    .sign(privateKey);
}

async function exchangeToken({ code, state }) {
  pruneExpiredStates();
  const pending = pendingStates.get(state);
  const dpopProof = await generateDpopProof('POST', IAM_TOKEN_URL);
  const tokenBody = new URLSearchParams({
    client_id: CLIENT_ID,
    code,
    code_verifier: pending.codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI,
  });

  let tokenRes;
  try {
    tokenRes = await fetchWithTimeout(IAM_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: dpopProof,
      },
      body: tokenBody.toString(),
    });
  } catch (error) {
    return {
      status: 504,
      data: {
        error: `授权码换 token 请求失败: ${String(error)}`,
        tokenEndpoint: IAM_TOKEN_URL,
      },
    };
  }

  let tokenData = {};
  try {
    tokenData = await tokenRes.json();
  } catch {
    tokenData = { raw: await tokenRes.text().catch(() => '') };
  }

  if (!tokenRes.ok) {
    return {
      status: tokenRes.status,
      data: {
        error: '授权码换 token 失败',
        tokenEndpoint: IAM_TOKEN_URL,
        tokenResponse: tokenData,
      },
    };
  }

  const credential = tokenData.credential || {};
  const claims = parseIdTokenClaims(tokenData.id_token);
  const sessionUserId = claims.sub || `oauth-${base64Url(randomBytes(8))}`;
  const sessionUserName = claims.preferred_username || claims.name || sessionUserId;

  sessions.set(sessionUserId, {
    userId: sessionUserId,
    userName: sessionUserName,
    refreshToken: tokenData.refresh_token || '',
    credential,
  });

  return {
    status: 200,
    data: {
      success: true,
      userId: sessionUserId,
      userName: sessionUserName,
      tokenEndpoint: IAM_TOKEN_URL,
      tokenResponse: tokenData,
    },
  };
}

async function validatePermission({ userId }) {
  const session = sessions.get(userId);
  if (!session) {
    return { status: 404, data: { error: '找不到 session，请先完成登录' } };
  }

  const permissionUrl = `${HUAWEI_CLAW_BASE}/v1/claw/permission-validate`;
  const permissionHeaders = { Accept: 'application/json' };
  if (session.credential?.securityToken) permissionHeaders['X-Security-Token'] = session.credential.securityToken;
  if (session.credential?.project_id) permissionHeaders['X-Project-ID'] = session.credential.project_id;

  let permissionRes;
  try {
    permissionRes = await fetchWithTimeout(permissionUrl, { method: 'GET', headers: permissionHeaders });
  } catch (error) {
    return {
      status: 504,
      data: {
        success: false,
        userId,
        url: permissionUrl,
        error: String(error),
      },
    };
  }

  let permissionBody = null;
  try {
    permissionBody = await permissionRes.json();
  } catch {
    permissionBody = await permissionRes.text().catch(() => '');
  }

  return {
    status: permissionRes.status,
    data: {
      success: permissionRes.ok,
      userId,
      url: permissionUrl,
      status: permissionRes.status,
      body: permissionBody,
    },
  };
}

async function refreshToken({ userId }) {
  const session = sessions.get(userId);
  if (!session) {
    return { status: 404, data: { error: '找不到 session，请先完成登录' } };
  }
  if (!session.refreshToken) {
    return { status: 400, data: { error: '当前 session 无 refresh_token' } };
  }

  const dpopProof = await generateDpopProof('POST', IAM_TOKEN_URL);
  const tokenBody = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: session.refreshToken,
  });

  let tokenRes;
  try {
    tokenRes = await fetchWithTimeout(IAM_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: dpopProof,
      },
      body: tokenBody.toString(),
    });
  } catch (error) {
    return {
      status: 504,
      data: {
        error: `刷新 token 请求失败: ${String(error)}`,
        tokenEndpoint: IAM_TOKEN_URL,
      },
    };
  }

  let tokenData = {};
  try {
    tokenData = await tokenRes.json();
  } catch {
    tokenData = { raw: await tokenRes.text().catch(() => '') };
  }

  if (!tokenRes.ok) {
    return {
      status: tokenRes.status,
      data: {
        error: '刷新 token 失败',
        tokenEndpoint: IAM_TOKEN_URL,
        tokenResponse: tokenData,
      },
    };
  }

  session.credential = tokenData.credential || session.credential;
  if (tokenData.refresh_token) session.refreshToken = tokenData.refresh_token;
  sessions.set(userId, session);

  return {
    status: 200,
    data: {
      success: true,
      userId,
      tokenEndpoint: IAM_TOKEN_URL,
      tokenResponse: tokenData,
    },
  };
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

  if (req.method === 'POST' && url.pathname === '/demo-api/flow/exchange') {
    try {
      const body = await readBody(req);
      const code = String(body.code || '').trim();
      const state = String(body.state || '').trim();
      if (!code || !state) {
        json(res, 400, { error: 'code/state 不能为空' });
        return;
      }
      const result = await exchangeToken({ code, state });
      json(res, result.status, result.data);
    } catch (error) {
      json(res, 500, { error: `exchange 异常: ${String(error)}` });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/demo-api/flow/permission-validate') {
    try {
      const body = await readBody(req);
      const userId = String(body.userId || '').trim();
      if (!userId) {
        json(res, 400, { error: 'userId 不能为空' });
        return;
      }
      const result = await validatePermission({ userId });
      json(res, result.status, result.data);
    } catch (error) {
      json(res, 500, { error: `permission-validate 异常: ${String(error)}` });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/demo-api/flow/refresh') {
    try {
      const body = await readBody(req);
      const userId = String(body.userId || '').trim();
      if (!userId) {
        json(res, 400, { error: 'userId 不能为空' });
        return;
      }
      const result = await refreshToken({ userId });
      json(res, result.status, result.data);
    } catch (error) {
      json(res, 500, { error: `refresh 异常: ${String(error)}` });
    }
    return;
  }

  json(res, 404, { error: 'Not Found' });
});

server.listen(PORT, HOST, () => {
  console.log(`[oauth-demo] server running at http://${HOST}:${PORT}`);
  console.log(`[oauth-demo] auth base: ${AUTH_BASE}`);
  console.log(`[oauth-demo] iam token: ${IAM_TOKEN_URL}`);
  console.log(`[oauth-demo] redirect uri: ${REDIRECT_URI}`);
  if (TLS_INSECURE_SKIP_VERIFY) {
    console.warn('[oauth-demo] TLS certificate verification is DISABLED via OAUTH_TLS_INSECURE_SKIP_VERIFY=1');
  } else if (TLS_CA_CERT_PATH) {
    console.log(`[oauth-demo] using custom CA cert: ${TLS_CA_CERT_PATH}`);
  }
});
