/**
 * 开放平台 —— OAuth 授权端点
 *   GET  /api/openplatform/oauth/authorize?client_id&redirect_uri&scope&state&response_type=code
 *        预检：校验应用存在 / 未吊销 / 回调地址匹配，返回应用信息、权限与一次性授权 nonce（授权页展示用）
 *   POST /api/openplatform/oauth/authorize  body: { client_id, redirect_uri, scope, state, token, nonce }
 *        站长输入管理站 Token 确认授权 → 校验一次性 nonce（防 CSRF/重放）→ 生成一次性授权码 → 返回 redirect_url
 *
 * 安全加固：
 *  - 一次性 nonce：GET 签发、POST 校验并销毁，绑定 client_id/redirect_uri/scope，防跨站伪造与重放
 *  - Origin / Referer 白名单，拦截跨站 POST
 *  - state 字符白名单校验后原样透传；redirect_uri 强制 https 且与注册记录全等匹配（防开放重定向）
 *  - 统一安全响应头（防点击劫持 / MIME 嗅探 / 降级 / XSS 来源限制）
 *
 * 授权码：24 字节随机 hex，存 OP_CODES（key "code:"+code），10 分钟有效，一次性使用。
 */

// 允许发起授权页/确认授权的前端来源
const ALLOWED_ORIGINS = [
  "https://songyuheng800.github.io",
  "https://utau-4oo.pages.dev",
  "https://utau-catbox-test.pages.dev",
];

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
  ...SECURITY_HEADERS,
};

// 写操作 CSRF 校验：Origin 命中白名单，缺失时回退 Referer 同源校验
function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

function corsPreflight() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function appGet(env, clientId) {
  if (!env.OP_APPS) return null;
  const raw = await env.OP_APPS.get("app:" + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function kvPut(env, key, obj, ttlSec) {
  if (!env.OP_CODES) throw new Error("OP_CODES KV 未绑定");
  await env.OP_CODES.put(key, JSON.stringify(obj), ttlSec ? { expirationTtl: ttlSec } : undefined);
}

async function kvGet(env, key) {
  if (!env.OP_CODES) return null;
  return await env.OP_CODES.get(key);
}

async function kvDelete(env, key) {
  if (env.OP_CODES) await env.OP_CODES.delete(key);
}

async function verifyAdminToken(env, token) {
  if (!env.TOKENS || !token) return false;
  const t = String(token).trim();
  if (!/^[A-Z0-9]{13}$/.test(t)) return false;
  const raw = await env.TOKENS.get(t);
  if (!raw) return false;
  try {
    const data = JSON.parse(raw);
    if (data.expire && data.expire < Date.now()) return false;
    return true;
  } catch (e) { return false; }
}

// state 仅允许字母数字与 -_.~，长度上限，防注入/跳转污染
function validState(s) {
  return typeof s === "string" && s.length <= 200 && /^[\w\-_.~]*$/.test(s);
}

// redirect_uri 必须是 https 且与注册记录全等（在调用方先做全等比对，这里兜底协议校验）
function validHttpsUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:";
  } catch (e) { return false; }
}

const CODE_TTL = 10 * 60;   // 授权码 10 分钟
const NONCE_TTL = 5 * 60;   // 授权 nonce 5 分钟

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();

  if (request.method === "GET") return handleCheck(request, env);
  if (request.method === "POST") return handleConfirm(request, env);

  return json({ ok: false, msg: "方法错误" }, 405);
}

/* ---------- 预检（授权页加载时调用，签发一次性 nonce） ---------- */
async function handleCheck(request, env) {
  const url = new URL(request.url);
  const clientId = String(url.searchParams.get("client_id") || "");
  const redirectUri = String(url.searchParams.get("redirect_uri") || "");
  const rawScopes = String(url.searchParams.get("scope") || "read");
  const state = String(url.searchParams.get("state") || "");

  const app = await appGet(env, clientId);
  if (!app) {
    return json({ ok: false, msg: "应用不存在：client_id 无效" }, 400);
  }
  if (app.revoked) {
    return json({ ok: false, msg: "该应用已被吊销，请联系平台管理员" }, 403);
  }
  if (!validHttpsUrl(redirectUri) || app.redirect_uri !== redirectUri) {
    return json({ ok: false, msg: "回调地址与注册时不匹配" }, 400);
  }

  const scopes = rawScopes.split(/[\s,]+/).filter(Boolean);
  // 请求的权限必须是应用已注册权限的子集
  const invalid = scopes.filter((s) => !app.scopes.includes(s));
  if (invalid.length > 0) {
    return json({ ok: false, msg: "请求了应用未注册的权限：" + invalid.join(",") }, 400);
  }

  // 签发一次性 nonce，绑定本次校验参数，POST 时必须一致
  const nonce = randomHex(24);
  try {
    await kvPut(env, "auth_nonce:" + nonce, {
      client_id: clientId,
      redirect_uri: redirectUri,
      scopes,
      exp: Date.now() + NONCE_TTL * 1000,
    }, NONCE_TTL);
  } catch (e) {
    return json({ ok: false, msg: "授权服务暂不可用（KV 未绑定）" }, 500);
  }

  return json({
    ok: true,
    nonce,
    app: {
      client_id: app.client_id,
      name: app.name,
      desc: app.desc || "",
      redirect_uri: app.redirect_uri,
    },
    scopes,
  });
}

/* ---------- 确认授权（站长输入 Token 后） ---------- */
async function handleConfirm(request, env) {
  // CSRF：跨站伪造的确认请求会被 Origin/Referer 白名单拦截
  if (!originAllowed(request)) {
    return json({ ok: false, msg: "非法来源，拒绝授权" }, 403);
  }

  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const clientId = String(body.client_id || "");
  const redirectUri = String(body.redirect_uri || "");
  const state = String(body.state || "");
  const token = String(body.token || "").trim();
  const rawScopes = String(body.scope || "read");
  const nonce = String(body.nonce || "");

  // 一次性 nonce 校验（防 CSRF / 重放）
  if (!nonce) return json({ ok: false, msg: "缺少授权凭证，请刷新页面重试" }, 403);
  const savedRaw = await kvGet(env, "auth_nonce:" + nonce);
  if (!savedRaw) return json({ ok: false, msg: "授权凭证已失效，请刷新页面重试" }, 403);
  let saved;
  try { saved = JSON.parse(savedRaw); } catch (e) { return json({ ok: false, msg: "授权凭证损坏" }, 403); }
  // 一次性：校验后立即销毁
  await kvDelete(env, "auth_nonce:" + nonce);
  if (saved.exp && saved.exp < Date.now()) {
    return json({ ok: false, msg: "授权凭证已过期，请刷新页面重试" }, 403);
  }
  // nonce 绑定的参数必须与本次提交一致，防止换参重放
  if (saved.client_id !== clientId || saved.redirect_uri !== redirectUri) {
    return json({ ok: false, msg: "授权参数与预检不一致，请刷新重试" }, 403);
  }

  const app = await appGet(env, clientId);
  if (!app) return json({ ok: false, msg: "应用不存在" }, 400);
  if (app.revoked) return json({ ok: false, msg: "该应用已被吊销" }, 403);
  if (!validHttpsUrl(redirectUri) || app.redirect_uri !== redirectUri) {
    return json({ ok: false, msg: "回调地址不匹配" }, 400);
  }

  const scopes = rawScopes.split(/[\s,]+/).filter(Boolean);
  if (scopes.some((s) => !app.scopes.includes(s))) {
    return json({ ok: false, msg: "请求了未注册的权限" }, 400);
  }
  // 与预检 scope 集合一致
  const a = [...scopes].sort().join(","), b = [...(saved.scopes || [])].sort().join(",");
  if (a !== b) return json({ ok: false, msg: "权限范围与预检不一致，请刷新重试" }, 403);

  // state 白名单校验，避免污染跳转地址
  if (!validState(state)) return json({ ok: false, msg: "state 参数非法" }, 400);

  // 站长身份：管理站 Token
  if (!(await verifyAdminToken(env, token))) {
    return json({ ok: false, msg: "管理站 Token 无效或已过期" }, 403);
  }

  // 生成一次性授权码
  const code = randomHex(24);
  // 一次性：核销由 token 端点"先删除再签发"保证，不依赖 used 标记（避免 check-then-set 竞态）
  await kvPut(env, "code:" + code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    scopes,
    user: "admin",
    issued: Date.now(),
  }, CODE_TTL);

  const sep = redirectUri.includes("?") ? "&" : "?";
  const redirectUrl = redirectUri + sep + "code=" + encodeURIComponent(code) + "&state=" + encodeURIComponent(state);

  return json({ ok: true, redirect_url: redirectUrl, code });
}
