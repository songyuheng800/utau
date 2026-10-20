/**
 * 开放平台 —— OAuth Token 端点
 *   POST /api/openplatform/oauth/token
 *     grant_type=authorization_code + client_id + client_secret + code + redirect_uri
 *       → { access_token, token_type, expires_in, refresh_token, scope }
 *     grant_type=refresh_token + client_id + client_secret + refresh_token
 *       → 新的 access_token（refresh_token 轮换）
 *
 * access_token：32 字节 hex，1 小时；refresh_token：32 字节 hex，30 天。
 * 存 OP_CODES（key "token:" / "refresh:"）。
 */

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
  ...SECURITY_HEADERS,
};

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

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function appGet(env, clientId) {
  if (!env.OP_APPS) return null;
  const raw = await env.OP_APPS.get("app:" + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function kvGet(env, key) {
  if (!env.OP_CODES) return null;
  return await env.OP_CODES.get(key);
}

async function kvPut(env, key, obj, ttlSec) {
  if (!env.OP_CODES) throw new Error("OP_CODES KV 未绑定");
  await env.OP_CODES.put(key, JSON.stringify(obj), ttlSec ? { expirationTtl: ttlSec } : undefined);
}

async function kvDelete(env, key) {
  if (env.OP_CODES) await env.OP_CODES.delete(key);
}

const ACCESS_TTL = 60 * 60;            // 1 小时
const REFRESH_TTL = 30 * 24 * 60 * 60; // 30 天

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);

  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const grantType = String(body.grant_type || "");
  const clientId = String(body.client_id || "");
  const secret = String(body.client_secret || "");

  const app = await appGet(env, clientId);
  if (!app) return json({ ok: false, msg: "client_id 无效" }, 400);
  if (app.revoked) return json({ ok: false, msg: "该应用已被吊销" }, 403);
  const hash = await sha256Hex(secret);
  if (hash !== app.secret_hash) return json({ ok: false, msg: "client_secret 错误" }, 403);

  if (grantType === "authorization_code") {
    return handleCodeGrant(body, app, env);
  }
  if (grantType === "refresh_token") {
    return handleRefresh(body, app, env);
  }
  return json({ ok: false, msg: "grant_type 只支持 authorization_code / refresh_token" }, 400);
}

/* ---------- 授权码换令牌 ---------- */
async function handleCodeGrant(body, app, env) {
  const code = String(body.code || "");
  const redirectUri = String(body.redirect_uri || "");
  if (!code || !redirectUri) {
    return json({ ok: false, msg: "缺少 code 或 redirect_uri" }, 400);
  }
  if (app.redirect_uri !== redirectUri) {
    return json({ ok: false, msg: "redirect_uri 不匹配" }, 400);
  }

  const raw = await kvGet(env, "code:" + code);
  if (!raw) return json({ ok: false, msg: "授权码无效、已过期或已被使用" }, 400);
  let grant;
  try { grant = JSON.parse(raw); } catch (e) { return json({ ok: false, msg: "授权码数据损坏" }, 500); }

  if (grant.client_id !== app.client_id) return json({ ok: false, msg: "授权码与应用不匹配" }, 400);

  // TOCTOU 缓解：校验通过后【先一次性销毁授权码，再签发令牌】，
  // 使并发的第二次兑换读不到该码，压缩检查→使用之间的重放窗口。
  // （KV 无原子 CAS，彻底串行需 Durable Object，见加固说明）
  await kvDelete(env, "code:" + code);

  const accessToken = randomHex(32);
  const refreshToken = randomHex(32);
  const scopes = grant.scopes || app.scopes || [];

  await kvPut(env, "token:" + accessToken, {
    client_id: app.client_id,
    user: grant.user || "admin",
    scopes,
    type: "access",
    issued: Date.now(),
  }, ACCESS_TTL);

  await kvPut(env, "refresh:" + refreshToken, {
    client_id: app.client_id,
    user: grant.user || "admin",
    scopes,
    type: "refresh",
    issued: Date.now(),
  }, REFRESH_TTL);

  return json({
    ok: true,
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: refreshToken,
    scope: scopes.join(" "),
  });
}

/* ---------- 刷新令牌 ---------- */
async function handleRefresh(body, app, env) {
  const refreshToken = String(body.refresh_token || "");
  if (!refreshToken) return json({ ok: false, msg: "缺少 refresh_token" }, 400);

  const raw = await kvGet(env, "refresh:" + refreshToken);
  if (!raw) return json({ ok: false, msg: "refresh_token 无效或已过期" }, 400);
  let refresh;
  try { refresh = JSON.parse(raw); } catch (e) { return json({ ok: false, msg: "refresh_token 数据损坏" }, 500); }

  if (refresh.client_id !== app.client_id) return json({ ok: false, msg: "refresh_token 与应用不匹配" }, 400);

  // TOCTOU 缓解：先销毁旧 refresh_token 再签发新对，压缩并发重放窗口（轮换即作废）
  await kvDelete(env, "refresh:" + refreshToken);

  const accessToken = randomHex(32);
  const newRefreshToken = randomHex(32);

  await kvPut(env, "token:" + accessToken, {
    client_id: app.client_id,
    user: refresh.user || "admin",
    scopes: refresh.scopes || app.scopes || [],
    type: "access",
    issued: Date.now(),
  }, ACCESS_TTL);

  await kvPut(env, "refresh:" + newRefreshToken, {
    client_id: app.client_id,
    user: refresh.user || "admin",
    scopes: refresh.scopes || app.scopes || [],
    type: "refresh",
    issued: Date.now(),
  }, REFRESH_TTL);

  return json({
    ok: true,
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: newRefreshToken,
    scope: (refresh.scopes || app.scopes || []).join(" "),
  });
}
