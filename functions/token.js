/**
 * Cloudflare Pages Function —— 管理站 Token 获取 / 校验
 *
 * 职责：
 *   1. 校验管理站密码，生成 13 位随机 Token（数字 + 大写字母）
 *   2. 把 Token 同步到管理站（写入 KV 存储，管理后台登录时用同一份数据校验）
 *   3. 提供校验接口，管理后台「Token 直登」时验证 Token 是否有效
 *
 * 部署位置：Cloudflare Pages 项目的 functions/ 目录（functions/token.js）
 * 函数路由：https://<你的项目名>.pages.dev/token
 *
 * 存储（推荐 KV）：
 *   Cloudflare Dashboard → Workers & Pages → KV → 新建 namespace
 *   Pages 项目 → Settings → Bindings → Add binding：
 *     Variable name 填 TOKENS，KV namespace 选刚建的 namespace
 *   未绑定 KV 时自动降级为内存存储（仅供本地调试，Worker 重启后 Token 会丢，
 *   且与 functions/upload.js 不在同一实例时无法跨函数校验）。
 *
 * 环境变量（Pages 项目 → Settings → Environment variables）：
 *   ADMIN_PASSWORD  管理站密码（默认 233677，与 functions/upload.js 保持一致）
 *   TOKEN_TTL       Token 有效期（秒，默认 604800 = 7 天）
 */

const TOKEN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const TOKEN_LEN = 13;
const DEFAULT_TTL = 7 * 24 * 60 * 60; // 7 天

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

// 内存降级存储（无 KV 绑定时使用；多实例间不共享，重启即失效）
const memoryStore = new Map();

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

/* ---------- 生成 13 位随机 Token（数字 + 大写字母） ---------- */
function generateToken() {
  const bytes = new Uint8Array(TOKEN_LEN);
  crypto.getRandomValues(bytes);
  let token = "";
  for (let i = 0; i < TOKEN_LEN; i++) {
    // 拒绝采样消除取模偏差：36 * 7 = 252，超过则重取
    let r;
    do { r = crypto.getRandomValues(new Uint8Array(1))[0]; } while (r >= 252);
    token += TOKEN_CHARS[r % TOKEN_CHARS.length];
  }
  return token;
}

/* ---------- 存储：KV 优先，内存兜底 ---------- */
async function tokenStorePut(env, token, ttl) {
  const payload = JSON.stringify({ issued: Date.now(), expire: Date.now() + ttl * 1000 });
  if (env.TOKENS) {
    await env.TOKENS.put(token, payload, { expirationTtl: ttl });
    return "kv";
  }
  memoryStore.set(token, { expire: Date.now() + ttl * 1000 });
  return "memory";
}

async function tokenStoreGet(env, token) {
  if (env.TOKENS) {
    return await env.TOKENS.get(token);
  }
  const mem = memoryStore.get(token);
  if (!mem) return null;
  if (mem.expire < Date.now()) {
    memoryStore.delete(token);
    return null;
  }
  return JSON.stringify({ expire: mem.expire });
}

export async function onRequest(context) {
  const { request, env } = context;

  // 浏览器跨域预检（前端在 github.io，函数在 pages.dev，跨域必须处理）
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const url = new URL(request.url);

  // GET /token?verify=XXX → 校验 Token 是否有效（管理后台登录用）
  if (request.method === "GET" && url.searchParams.has("verify")) {
    return handleVerify(url.searchParams.get("verify"), env);
  }

  // POST /token  body: { password } → 校验密码并签发 Token
  if (request.method === "POST") {
    return handleIssue(request, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

/* ---------- 签发 Token ---------- */
async function handleIssue(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const pwd = String(body.password || "");
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";
  if (pwd !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }

  const ttl = parseInt(env.TOKEN_TTL, 10) > 0 ? parseInt(env.TOKEN_TTL, 10) : DEFAULT_TTL;
  const token = generateToken();
  const storage = await tokenStorePut(env, token, ttl);

  return json({ ok: true, token, ttl, storage });
}

/* ---------- 校验 Token ---------- */
async function handleVerify(token, env) {
  const t = String(token || "");
  if (!/^[A-Z0-9]{13}$/.test(t)) {
    return json({ ok: true, valid: false });
  }
  const raw = await tokenStoreGet(env, t);
  if (!raw) {
    return json({ ok: true, valid: false });
  }
  try {
    const data = JSON.parse(raw);
    if (data.expire && data.expire < Date.now()) {
      return json({ ok: true, valid: false });
    }
  } catch (e) {
    return json({ ok: true, valid: false });
  }
  return json({ ok: true, valid: true });
}
