<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

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

const config = ref<FlowConfig | null>(null);

const codeVerifier = ref('');
const codeChallenge = ref('');
const state = ref('');
const authorizeUrl = ref('');

const callbackCode = ref('');
const callbackState = ref('');
const callbackError = ref('');

const tokenResult = ref<ApiResponse | null>(null);
const permissionResult = ref<ApiResponse | null>(null);
const refreshResult = ref<ApiResponse | null>(null);
const sessionSnapshot = ref<ApiResponse | null>(null);

const currentUserId = ref('');
const currentUserName = ref('');

const hasTokenStepDone = computed(() => Boolean(tokenResult.value && currentUserId.value));

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

async function callApi(path: string, init?: RequestInit): Promise<{ ok: boolean; status: number; data: ApiResponse }> {
  const res = await fetch(apiUrl(path), init);
  let data: ApiResponse = {};
  try {
    data = (await res.json()) as ApiResponse;
  } catch {
    data = { error: '非 JSON 响应' };
  }
  return { ok: res.ok, status: res.status, data };
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

    const res = await callApi('/flow/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: callbackCode.value.trim(),
        state: callbackState.value.trim(),
      }),
    });

    tokenResult.value = res.data;
    if (!res.ok) {
      log(`换token失败: ${res.status} ${String(res.data.error || '')}`);
      return;
    }

    currentUserId.value = String(res.data.userId || '');
    currentUserName.value = String(res.data.userName || '');
    permissionResult.value = null;
    log(`换token成功: userId=${currentUserId.value || '(空)'}`);
  });
}

async function step5ValidatePermission(): Promise<void> {
  await withBusy('Step5 permission-validate', async () => {
    if (!currentUserId.value.trim()) {
      log('请先完成 Step4 获得 userId');
      return;
    }

    const res = await callApi('/flow/permission-validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: currentUserId.value.trim() }),
    });

    permissionResult.value = res.data;
    if (!res.ok) {
      log(`permission-validate 失败: ${res.status} ${String(res.data.error || '')}`);
      return;
    }
    log(`permission-validate 完成: status=${String(res.data.status || res.status)}`);
  });
}

async function step6RefreshToken(): Promise<void> {
  await withBusy('Step6 刷新token', async () => {
    if (!currentUserId.value.trim()) {
      log('请先完成 Step4 获得 userId');
      return;
    }

    const res = await callApi('/flow/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: currentUserId.value.trim() }),
    });

    refreshResult.value = res.data;
    if (!res.ok) {
      log(`刷新token失败: ${res.status} ${String(res.data.error || '')}`);
      return;
    }
    log('刷新token成功');
  });
}

async function readSession(): Promise<void> {
  if (!currentUserId.value.trim()) {
    log('暂无 userId，无法读取 session');
    return;
  }
  const res = await callApi(`/flow/session?userId=${encodeURIComponent(currentUserId.value.trim())}`, {
    method: 'GET',
  });
  sessionSnapshot.value = res.data;
  log(`读取session: ${res.status}`);
}

onMounted(async () => {
  await loadConfig();

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
});
</script>

<template>
  <main class="page">
    <header class="header card">
      <h1>OAuth 完整登录流 Demo（真实地址版）</h1>
      <p>
        按你要求的 6 步执行：PKCE 生成 -> 点击登录跳转授权页 -> 回调取 code -> code 换 token -> permission-validate -> refresh token。
      </p>
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

    <section class="grid two">
      <article class="card">
        <h2>Step 5：调用 permission-validate</h2>
        <p class="hint">由 Vue 主动调用后端接口。</p>
        <button :disabled="busy || !hasTokenStepDone" @click="step5ValidatePermission">执行 Step5（permission-validate）</button>
        <pre>{{ permissionResult }}</pre>
      </article>

      <article class="card">
        <h2>Step 6：刷新token</h2>
        <label>userId</label>
        <input v-model="currentUserId" placeholder="Step4 后自动填充" />
        <label>userName</label>
        <input v-model="currentUserName" placeholder="Step4 后自动填充" />
        <div class="row">
          <button :disabled="busy || !hasTokenStepDone" @click="step6RefreshToken">执行 Step6（refresh）</button>
          <button :disabled="busy || !currentUserId" @click="readSession">查看 session</button>
        </div>
        <pre>{{ refreshResult }}</pre>
        <pre>{{ sessionSnapshot }}</pre>
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
