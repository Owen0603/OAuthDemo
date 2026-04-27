<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

type FlowConfig = {
  authBase: string;
  iamTokenUrl: string;
  huaweiClawBase: string;
  clientId: string;
  redirectUri: string;
  scope: string;
};

type ApiResponse = Record<string, unknown>;

const flowApiBase = ref('/demo-api');
const busy = ref(false);
const logs = ref<string[]>([]);
const FETCH_TIMEOUT_MS = 60 * 1000;
const currentPath = ref(window.location.pathname || '/');

const config = ref<FlowConfig | null>(null);

const codeVerifier = ref('');
const codeChallenge = ref('');
const state = ref('');
const authorizeUrl = ref('');

const callbackCode = ref('');
const callbackState = ref('');
const callbackError = ref('');

const tokenResult = ref<ApiResponse | null>(null);
const directTokenResult = ref<ApiResponse | null>(null);
const permissionResult = ref<ApiResponse | null>(null);
const refreshResult = ref<ApiResponse | null>(null);
const credential = ref<ApiResponse | null>(null);
const refreshTokenValue = ref('');
const directCallIncludeDpop = ref(true);
const testMethod = ref('POST');
const testUrl = ref('');
const testHeadersText = ref('Accept: application/json\nContent-Type: application/x-www-form-urlencoded');
const testBody = ref('');
const testUseCredentials = ref(false);
const testResult = ref<ApiResponse | null>(null);

const currentUserId = ref('');
const currentUserName = ref('');

const hasTokenStepDone = computed(() => Boolean(tokenResult.value && currentUserId.value));
const isTestRoute = computed(() => currentPath.value === '/test');
const testCurlCommand = computed(() => {
  const url = testUrl.value.trim();
  if (!url) return 'curl';

  const method = testMethod.value.toUpperCase();
  let headers: Record<string, string> = {};
  try {
    headers = parseHeadersText(testHeadersText.value);
  } catch {
    return 'Header 格式错误，暂时无法生成 curl';
  }

  const parts = ['curl'];
  if (method !== 'GET') {
    parts.push(`-X ${shellEscape(method)}`);
  }
  for (const [name, value] of Object.entries(headers)) {
    parts.push(`-H ${shellEscape(`${name}: ${value}`)}`);
  }
  if (testUseCredentials.value) {
    parts.push('--cookie-jar cookies.txt');
    parts.push('--cookie cookies.txt');
  }
  if (shouldAttachBody(method) && testBody.value) {
    parts.push(`--data ${shellEscape(testBody.value)}`);
  }
  parts.push(shellEscape(url));
  return parts.join(' \\\n+  ');
});

function now(): string {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false });
}

function log(message: string): void {
  logs.value.unshift(`[${now()}] ${message}`);
}

function apiUrl(path: string): string {
  const base = flowApiBase.value.trim().replace(/\/+$/, '');
  return `${base}${path}`;
}

function navigateTo(path: string): void {
  if (window.location.pathname === path) {
    currentPath.value = path;
    return;
  }
  window.history.pushState({}, '', path);
  currentPath.value = path;
}

function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function toBase64Url(input: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < input.length; i += 1) {
    binary += String.fromCharCode(input[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomBase64Url(bytes = 16): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return toBase64Url(data);
}

function parseJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length < 2) return {};
  const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const json = atob(b64 + pad);
  return JSON.parse(json) as Record<string, unknown>;
}

async function generateDpopProof(method: string, url: string): Promise<string> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const iat = Math.floor(Date.now() / 1000);
  const jti = randomBase64Url(16);
  return new SignJWT({ htm: method.toUpperCase(), htu: url, jti })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
    .setIssuedAt(iat)
    .setExpirationTime(iat + 120)
    .sign(privateKey);
}

function proxyIamTokenUrl(): string {
  const endpoint = String(config.value?.iamTokenUrl || '').trim();
  if (!endpoint) return '/proxy/iam/v1/oauth2/tokens';
  const url = new URL(endpoint);
  return `/proxy/iam${url.pathname}${url.search}`;
}

function permissionValidateUrl(): string {
  return '/proxy/claw/v1/claw/permission-validate';
}

async function fetchWithTimeout(input: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(new Error('timeout')), FETCH_TIMEOUT_MS);

  if (init?.signal) {
    if (init.signal.aborted) {
      controller.abort(init.signal.reason);
    } else {
      init.signal.addEventListener('abort', () => controller.abort(init.signal?.reason), { once: true });
    }
  }

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function callApi(path: string, init?: RequestInit): Promise<{ ok: boolean; status: number; data: ApiResponse }> {
  let res: Response;
  try {
    res = await fetchWithTimeout(apiUrl(path), init);
  } catch (error) {
    return { ok: false, status: 0, data: { error: `请求失败: ${String(error)}` } };
  }

  let data: ApiResponse = {};
  try {
    data = (await res.json()) as ApiResponse;
  } catch {
    data = { error: '非 JSON 响应' };
  }
  return { ok: res.ok, status: res.status, data };
}

async function callApiDirect(url: string, init?: RequestInit): Promise<{ ok: boolean; status: number; data: ApiResponse }> {
  let res: Response;
  try {
    res = await fetchWithTimeout(url, init);
  } catch (error) {
    return { ok: false, status: 0, data: { error: `请求失败: ${String(error)}`, url } };
  }

  let data: ApiResponse = {};
  try {
    data = (await res.json()) as ApiResponse;
  } catch {
    data = { raw: await res.text().catch(() => '') };
  }
  return { ok: res.ok, status: res.status, data };
}

function buildTokenRequestBody(grantType: 'authorization_code' | 'refresh_token'): URLSearchParams {
  if (grantType === 'refresh_token') {
    return new URLSearchParams({
      client_id: String(config.value?.clientId || ''),
      grant_type: 'refresh_token',
      refresh_token: refreshTokenValue.value.trim(),
    });
  }

  return new URLSearchParams({
    client_id: String(config.value?.clientId || ''),
    code: callbackCode.value.trim(),
    code_verifier: codeVerifier.value.trim(),
    grant_type: 'authorization_code',
    redirect_uri: String(config.value?.redirectUri || ''),
  });
}

function guessDirectCallIssue(error: unknown, includeDpop: boolean): string {
  const text = String(error || '');
  if (/TypeError: Failed to fetch|Load failed|NetworkError|Network request failed/i.test(text)) {
    return includeDpop
      ? '浏览器直连通常会先发 CORS 预检；当前请求带了 DPoP 自定义请求头，服务端若未放行 OPTIONS 或 Access-Control-Allow-Headers 里未包含 DPoP，浏览器会直接拦截。'
      : '浏览器直连失败且没有拿到 HTTP 响应，通常是目标接口未返回允许当前来源的 CORS 头，或 TLS / 网络层被浏览器拦截。';
  }
  return '浏览器已发起请求，但失败原因需要结合 DevTools Network 查看预检 OPTIONS 和实际 POST。';
}

function parseHeadersText(source: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of source.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    const separatorIndex = text.indexOf(':');
    if (separatorIndex === -1) {
      throw new Error(`Header 格式错误: ${text}`);
    }
    const name = text.slice(0, separatorIndex).trim();
    const value = text.slice(separatorIndex + 1).trim();
    if (!name) {
      throw new Error(`Header 名为空: ${text}`);
    }
    headers[name] = value;
  }
  return headers;
}

function shouldAttachBody(method: string): boolean {
  return !['GET', 'HEAD'].includes(method.toUpperCase());
}

async function runTestRequest(): Promise<void> {
  await withBusy('Test 路由直接调用', async () => {
    const url = testUrl.value.trim();
    if (!url) {
      log('Test 路由缺少 URL');
      return;
    }

    let headers: Record<string, string>;
    try {
      headers = parseHeadersText(testHeadersText.value);
    } catch (error) {
      testResult.value = {
        success: false,
        error: String(error),
      };
      log(`Test Header 解析失败: ${String(error)}`);
      return;
    }

    const method = testMethod.value.toUpperCase();
    try {
      const response = await fetchWithTimeout(url, {
        method,
        headers,
        body: shouldAttachBody(method) ? testBody.value : undefined,
        credentials: testUseCredentials.value ? 'include' : 'same-origin',
      });
      const responseText = await response.text();
      const responseHeaders = Object.fromEntries(response.headers.entries());
      let responseBody: ApiResponse | string = responseText;
      try {
        responseBody = responseText ? (JSON.parse(responseText) as ApiResponse) : {};
      } catch {
        responseBody = responseText;
      }

      testResult.value = {
        success: response.ok,
        request: {
          url,
          method,
          headers,
          body: shouldAttachBody(method) ? testBody.value : '',
          credentials: testUseCredentials.value ? 'include' : 'same-origin',
        },
        response: {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: responseBody,
        },
      };
      log(`Test 路由调用完成: status=${response.status}`);
    } catch (error) {
      testResult.value = {
        success: false,
        request: {
          url,
          method,
          headers,
          body: shouldAttachBody(method) ? testBody.value : '',
          credentials: testUseCredentials.value ? 'include' : 'same-origin',
        },
        error: String(error),
        diagnosis: '浏览器未拿到响应时，优先检查 CORS、预检 OPTIONS、证书、网络代理和目标域名白名单。',
      };
      log(`Test 路由调用失败: ${String(error)}`);
    }
  });
}

function fillIamTokenTemplate(): void {
  testMethod.value = 'POST';
  testUrl.value = String(config.value?.iamTokenUrl || '');
  testHeadersText.value = 'Accept: application/json\nContent-Type: application/x-www-form-urlencoded';
  testBody.value = buildTokenRequestBody('authorization_code').toString();
  testUseCredentials.value = false;
  log('已用当前 IAM_TOKEN_URL 和 Step4 参数填充 test 表单');
}

async function appendTestDpopHeader(): Promise<void> {
  const url = testUrl.value.trim();
  if (!url) {
    log('请先填写 Test URL，再生成 DPoP');
    return;
  }

  const method = testMethod.value.toUpperCase();
  const dpop = await generateDpopProof(method, url);
  let headers: Record<string, string>;
  try {
    headers = parseHeadersText(testHeadersText.value);
  } catch (error) {
    log(`当前 Header 无法解析，未写入 DPoP: ${String(error)}`);
    return;
  }

  headers.DPoP = dpop;
  testHeadersText.value = Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
  log(`已为 Test 请求写入 DPoP 头: method=${method}`);
}

async function withBusy(title: string, fn: () => Promise<void>) {
  if (busy.value) return;
  busy.value = true;
  log(`${title} 开始`);
  try {
    await fn();
    log(`${title} 完成`);
  } catch (error) {
    log(`${title} 异常: ${String(error)}`);
  } finally {
    busy.value = false;
  }
}

async function loadConfig(): Promise<void> {
  const res = await callApi('/flow/config', { method: 'GET' });
  if (!res.ok) {
    log(`读取配置失败: ${res.status}`);
    return;
  }
  config.value = {
    authBase: String(res.data.authBase || ''),
    iamTokenUrl: String(res.data.iamTokenUrl || ''),
    huaweiClawBase: String(res.data.huaweiClawBase || ''),
    clientId: String(res.data.clientId || ''),
    redirectUri: String(res.data.redirectUri || ''),
    scope: String(res.data.scope || ''),
  };
  log('已加载当前项目实际地址配置');
}

async function step1GeneratePkce(): Promise<void> {
  await withBusy('Step1 PKCE生成', async () => {
    const res = await callApi('/flow/start', { method: 'GET' });
    if (!res.ok) {
      log(`PKCE 生成失败: ${res.status} ${String(res.data.error || '')}`);
      return;
    }
    codeVerifier.value = String(res.data.codeVerifier || '');
    codeChallenge.value = String(res.data.codeChallenge || '');
    state.value = String(res.data.state || '');
    authorizeUrl.value = String(res.data.authorizeUrl || '');
    callbackState.value = state.value;
    log(`PKCE 完成，state=${state.value}`);
  });
}

function step2OpenAuthorizePage(): void {
  if (!authorizeUrl.value) {
    log('请先执行 Step1 获取 authorizeUrl');
    return;
  }
  window.open(authorizeUrl.value, '_blank', 'noopener,noreferrer');
  log('已打开授权页，请完成授权');
}

function parseOfficeClawCallback(raw: string): { code: string; state: string; error: string } {
  const text = raw.trim();
  if (!text) return { code: '', state: '', error: '' };
  try {
    if (text.startsWith('officeclaw://')) {
      const url = new URL(text);
      return {
        code: (url.searchParams.get('code') || '').trim(),
        state: (url.searchParams.get('state') || '').trim(),
        error: (url.searchParams.get('error') || '').trim(),
      };
    }
    const url = new URL(text);
    return {
      code: (url.searchParams.get('code') || '').trim(),
      state: (url.searchParams.get('state') || '').trim(),
      error: (url.searchParams.get('error') || '').trim(),
    };
  } catch {
    return { code: '', state: '', error: '' };
  }
}

const rawCallbackUrl = ref('');
function step3ParseCallback(): void {
  const parsed = parseOfficeClawCallback(rawCallbackUrl.value);
  callbackCode.value = parsed.code;
  if (parsed.state) callbackState.value = parsed.state;
  callbackError.value = parsed.error;
  log(`回调解析结果: code=${parsed.code ? '有' : '无'}, state=${parsed.state ? '有' : '无'}, error=${parsed.error || '无'}`);
}

async function step4ExchangeToken(): Promise<void> {
  await withBusy('Step4 授权码换token', async () => {
    if (callbackError.value.trim()) {
      log(`回调包含 error: ${callbackError.value}`);
      return;
    }
    if (!callbackCode.value.trim() || !callbackState.value.trim()) {
      log('请先准备 code 和 state');
      return;
    }

    if (callbackState.value.trim() !== state.value.trim()) {
      log('警告：回调 state 与 Step1 生成 state 不一致，请确认登录流程是否被打断');
    }

    if (!config.value?.iamTokenUrl) {
      log('缺少 iamTokenUrl 配置，请先刷新页面加载配置');
      return;
    }

    const tokenEndpoint = config.value.iamTokenUrl;
    const dpopProof = await generateDpopProof('POST', tokenEndpoint);
    const body = buildTokenRequestBody('authorization_code');

    const res = await callApiDirect(proxyIamTokenUrl(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: dpopProof,
      },
      body: body.toString(),
    });

    tokenResult.value = {
      success: res.ok,
      tokenEndpoint,
      tokenResponse: res.data,
    };
    if (!res.ok) {
      log(`换token失败: ${res.status}`);
      return;
    }

    const tokenData = res.data;
    credential.value = (tokenData.credential as ApiResponse | undefined) || null;
    refreshTokenValue.value = String(tokenData.refresh_token || '');
    const claims = parseJwtPayload(String(tokenData.id_token || ''));
    const sub = String(claims.sub || '').trim();
    const preferred = String(claims.preferred_username || '').trim();
    const name = String(claims.name || '').trim();
    currentUserId.value = sub || `oauth-${Date.now()}`;
    currentUserName.value = preferred || name || currentUserId.value;
    permissionResult.value = null;
    log(`换token成功: userId=${currentUserId.value || '(空)'}`);
  });
}

async function step4DirectExchangeToken(): Promise<void> {
  await withBusy('Step4 浏览器直连 IAM_TOKEN_URL', async () => {
    if (callbackError.value.trim()) {
      log(`回调包含 error: ${callbackError.value}`);
      return;
    }
    if (!callbackCode.value.trim() || !callbackState.value.trim()) {
      log('请先准备 code 和 state');
      return;
    }
    if (!config.value?.iamTokenUrl) {
      log('缺少 iamTokenUrl 配置，请先刷新页面加载配置');
      return;
    }

    const tokenEndpoint = config.value.iamTokenUrl;
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };
    if (directCallIncludeDpop.value) {
      headers.DPoP = await generateDpopProof('POST', tokenEndpoint);
    }

    const body = buildTokenRequestBody('authorization_code');
    try {
      const response = await fetchWithTimeout(tokenEndpoint, {
        method: 'POST',
        headers,
        body: body.toString(),
      });

      const responseText = await response.text();
      let parsedBody: ApiResponse | string = responseText;
      try {
        parsedBody = responseText ? (JSON.parse(responseText) as ApiResponse) : {};
      } catch {
        parsedBody = responseText;
      }

      directTokenResult.value = {
        success: response.ok,
        status: response.status,
        statusText: response.statusText,
        request: {
          url: tokenEndpoint,
          method: 'POST',
          includeDpop: directCallIncludeDpop.value,
          headers,
          body: body.toString(),
        },
        response: parsedBody,
      };
      log(`浏览器直连 IAM 完成: status=${response.status}`);
    } catch (error) {
      directTokenResult.value = {
        success: false,
        request: {
          url: tokenEndpoint,
          method: 'POST',
          includeDpop: directCallIncludeDpop.value,
          headers,
          body: body.toString(),
        },
        error: String(error),
        diagnosis: guessDirectCallIssue(error, directCallIncludeDpop.value),
      };
      log(`浏览器直连 IAM 失败: ${String(error)}`);
    }
  });
}

async function step5ValidatePermission(): Promise<void> {
  await withBusy('Step5 permission-validate', async () => {
    if (!currentUserId.value.trim() || !credential.value) {
      log('请先完成 Step4 获取 credential');
      return;
    }

    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    const securityToken = String(credential.value.securityToken || '').trim();
    const projectId = String(credential.value.project_id || '').trim();
    if (securityToken) headers['X-Security-Token'] = securityToken;
    if (projectId) headers['X-Project-ID'] = projectId;

    const url = permissionValidateUrl();
    const res = await callApiDirect(url, {
      method: 'GET',
      headers,
    });

    permissionResult.value = {
      success: res.ok,
      userId: currentUserId.value.trim(),
      url,
      status: res.status,
      body: res.data,
    };
    if (!res.ok) {
      log(`permission-validate 失败: ${res.status}`);
      return;
    }
    log(`permission-validate 完成: status=${String(res.status)}`);
  });
}

async function step6RefreshToken(): Promise<void> {
  await withBusy('Step6 刷新token', async () => {
    if (!currentUserId.value.trim()) {
      log('请先完成 Step4 获得 userId');
      return;
    }

    if (!refreshTokenValue.value.trim()) {
      log('当前没有 refresh_token，无法刷新');
      return;
    }

    if (!config.value?.iamTokenUrl) {
      log('缺少 iamTokenUrl 配置，请先刷新页面加载配置');
      return;
    }

    const tokenEndpoint = config.value.iamTokenUrl;
    const dpopProof = await generateDpopProof('POST', tokenEndpoint);
    const body = new URLSearchParams({
      client_id: String(config.value.clientId || ''),
      grant_type: 'refresh_token',
      refresh_token: refreshTokenValue.value.trim(),
    });

    const res = await callApiDirect(proxyIamTokenUrl(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: dpopProof,
      },
      body: body.toString(),
    });

    refreshResult.value = {
      success: res.ok,
      userId: currentUserId.value.trim(),
      tokenEndpoint,
      tokenResponse: res.data,
    };
    if (!res.ok) {
      log(`刷新token失败: ${res.status}`);
      return;
    }

    const tokenData = res.data;
    const nextCredential = (tokenData.credential as ApiResponse | undefined) || null;
    if (nextCredential) credential.value = nextCredential;
    if (String(tokenData.refresh_token || '').trim()) {
      refreshTokenValue.value = String(tokenData.refresh_token || '').trim();
    }
    log('刷新token成功');
  });
}

onMounted(async () => {
  await loadConfig();
  if (!testUrl.value.trim()) {
    testUrl.value = String(config.value?.iamTokenUrl || '');
  }

  const current = new URL(window.location.href);
  const code = (current.searchParams.get('code') || '').trim();
  const urlState = (current.searchParams.get('state') || '').trim();
  const err = (current.searchParams.get('error') || '').trim();
  if (code || urlState || err) {
    callbackCode.value = code;
    if (urlState) callbackState.value = urlState;
    callbackError.value = err;
    log('检测到浏览器 URL 中包含回调参数');
  }

  window.addEventListener('popstate', () => {
    currentPath.value = window.location.pathname || '/';
  });
});
</script>

<template>
  <main v-if="!isTestRoute" class="page">
    <header class="header card">
      <h1>OAuth 完整登录流 Demo（真实地址版）</h1>
      <p>
        按你要求的 6 步执行：PKCE 生成 -> 点击登录跳转授权页 -> 回调取 code -> code 换 token -> permission-validate -> refresh token。
      </p>
      <div class="row">
        <button :disabled="busy" @click="navigateTo('/test')">打开 Test 路由</button>
      </div>
      <label>Flow API Base</label>
      <input v-model="flowApiBase" :disabled="busy" />
    </header>

    <section class="card">
      <h2>当前实际地址（来自当前项目配置）</h2>
      <pre>{{ config }}</pre>
    </section>

    <section class="grid two">
      <article class="card">
        <h2>Step 1：PKCE生成</h2>
        <button :disabled="busy" @click="step1GeneratePkce">执行 Step1</button>
        <label>codeVerifier</label>
        <textarea :value="codeVerifier" rows="3" readonly />
        <label>codeChallenge</label>
        <textarea :value="codeChallenge" rows="2" readonly />
        <label>state</label>
        <input :value="state" readonly />
      </article>

      <article class="card">
        <h2>Step 2：登录页面点击登录并跳转授权页</h2>
        <button :disabled="busy || !authorizeUrl" @click="step2OpenAuthorizePage">执行 Step2（打开授权页）</button>
        <label>authorizeUrl</label>
        <textarea :value="authorizeUrl" rows="5" readonly />
      </article>
    </section>

    <section class="grid two">
      <article class="card">
        <h2>Step 3：返回登录获取 code</h2>
        <label>粘贴 deep link 或浏览器回调地址</label>
        <textarea
          v-model="rawCallbackUrl"
          rows="3"
          placeholder="officeclaw://oauth/callback?code=...&state=... 或 http(s)://...?..."
        />
        <button :disabled="busy" @click="step3ParseCallback">解析回调参数</button>
        <label>code</label>
        <input v-model="callbackCode" placeholder="code" />
        <label>state</label>
        <input v-model="callbackState" placeholder="state" />
        <label>error</label>
        <input v-model="callbackError" placeholder="error" />
      </article>

      <article class="card">
        <h2>Step 4：根据授权码获取token</h2>
        <button :disabled="busy" @click="step4ExchangeToken">执行 Step4（exchange）</button>
        <pre>{{ tokenResult }}</pre>
      </article>
    </section>

    <section class="card">
      <h2>IAM_TOKEN_URL 直连调试</h2>
      <p class="hint">这个按钮会让浏览器直接 POST 到当前配置里的 IAM_TOKEN_URL，不经过 Vite 代理，可用于判断是不是浏览器侧 CORS / 预检问题。</p>
      <label class="checkbox">
        <input v-model="directCallIncludeDpop" :disabled="busy" type="checkbox" />
        <span>带上 DPoP 请求头一起直连</span>
      </label>
      <div class="row">
        <button :disabled="busy" @click="step4DirectExchangeToken">直接调用 IAM_TOKEN_URL</button>
      </div>
      <pre>{{ directTokenResult }}</pre>
    </section>

    <section class="grid two">
      <article class="card">
        <h2>Step 5：调用 permission-validate</h2>
        <p class="hint">由 Vue 直接调用远端 permission-validate。</p>
        <button :disabled="busy || !hasTokenStepDone" @click="step5ValidatePermission">执行 Step5（permission-validate）</button>
        <pre>{{ permissionResult }}</pre>
      </article>

      <article class="card">
        <h2>Step 6：刷新token</h2>
        <label>userId</label>
        <input v-model="currentUserId" placeholder="Step4 后自动填充" />
        <label>userName</label>
        <input v-model="currentUserName" placeholder="Step4 后自动填充" />
        <button :disabled="busy || !hasTokenStepDone" @click="step6RefreshToken">执行 Step6（refresh）</button>
        <pre>{{ refreshResult }}</pre>
      </article>
    </section>

    <section class="card">
      <h2>执行日志</h2>
      <button :disabled="busy" @click="logs = []">清空</button>
      <ul>
        <li v-for="line in logs" :key="line">{{ line }}</li>
      </ul>
    </section>
  </main>

  <main v-else class="page page-test">
    <header class="header card">
      <h1>接口直调 Test 路由</h1>
      <p>这个页面只做一件事：在浏览器里按你填写的 URL、Header、Body 原样发请求，方便确认是不是浏览器环境导致失败。</p>
      <div class="row">
        <button :disabled="busy" @click="navigateTo('/')">返回 OAuth Demo</button>
        <button :disabled="busy" @click="fillIamTokenTemplate">填充 IAM_TOKEN_URL 模板</button>
        <button :disabled="busy" @click="appendTestDpopHeader">生成 DPoP Header</button>
      </div>
    </header>

    <section class="grid two">
      <article class="card">
        <h2>请求配置</h2>
        <label>Method</label>
        <select v-model="testMethod" :disabled="busy">
          <option>GET</option>
          <option>POST</option>
          <option>PUT</option>
          <option>PATCH</option>
          <option>DELETE</option>
          <option>OPTIONS</option>
        </select>
        <label>URL</label>
        <input v-model="testUrl" :disabled="busy" placeholder="https://example.com/path" />
        <label>Headers</label>
        <textarea
          v-model="testHeadersText"
          :disabled="busy"
          rows="8"
          placeholder="Accept: application/json&#10;Content-Type: application/x-www-form-urlencoded"
        />
        <label>Body</label>
        <textarea
          v-model="testBody"
          :disabled="busy"
          rows="8"
          placeholder="grant_type=authorization_code&client_id=..."
        />
        <label class="checkbox">
          <input v-model="testUseCredentials" :disabled="busy" type="checkbox" />
          <span>携带 credentials=include</span>
        </label>
        <div class="row">
          <button :disabled="busy" @click="runTestRequest">直接调用</button>
        </div>
      </article>

      <article class="card">
        <h2>当前项目配置</h2>
        <pre>{{ config }}</pre>
        <p class="hint">如果你想复现 IAM_TOKEN_URL 问题，先走主页的 Step1-Step3，再点“填充 IAM_TOKEN_URL 模板”。</p>
      </article>
    </section>

    <section class="card">
      <h2>调用结果</h2>
      <pre>{{ testResult }}</pre>
    </section>

    <section class="card">
      <h2>curl 预览</h2>
      <p class="hint">这个命令会按当前表单内容生成，方便你和 Postman 或终端请求逐项对比。</p>
      <pre>{{ testCurlCommand }}</pre>
    </section>

    <section class="card">
      <h2>执行日志</h2>
      <button :disabled="busy" @click="logs = []">清空</button>
      <ul>
        <li v-for="line in logs" :key="line">{{ line }}</li>
      </ul>
    </section>
  </main>
</template>

<style scoped>
.page {
  max-width: 1180px;
  margin: 0 auto;
  padding: 22px 18px 36px;
}

.grid {
  display: grid;
  gap: 14px;
  margin-top: 14px;
}

.grid.two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.card {
  background: #fffdfb;
  border: 1px solid #ecd8c1;
  border-radius: 12px;
  padding: 14px;
  box-shadow: 0 10px 24px -20px rgba(35, 35, 35, 0.65);
}

.header h1 {
  margin: 0 0 8px;
  font-size: 24px;
}

.header p {
  margin: 0 0 10px;
  color: #5f5a53;
}

h2 {
  margin: 0 0 10px;
  font-size: 16px;
}

label {
  display: block;
  margin: 8px 0 4px;
  font-size: 12px;
  color: #66594a;
}

input,
select,
textarea,
pre {
  width: 100%;
  border: 1px solid #d8d1c7;
  border-radius: 8px;
  padding: 8px;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
  background: #fff;
}

pre {
  white-space: pre-wrap;
  margin-top: 10px;
  min-height: 56px;
}

button {
  border: none;
  border-radius: 999px;
  background: #1d1d1d;
  color: #fff;
  padding: 7px 12px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.hint {
  margin: 0;
  font-size: 12px;
  color: #75695c;
}

.checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
}

.checkbox input {
  width: auto;
}

ul {
  margin: 10px 0 0;
  padding-left: 18px;
  max-height: 240px;
  overflow: auto;
}

li {
  margin-bottom: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
  font-size: 12px;
}

@media (max-width: 960px) {
  .grid.two {
    grid-template-columns: 1fr;
  }
}
</style>
