/**
 * 开放平台 OAuth2.0 共享工具库
 * 存储约定（KV）：
 *   OP_APPS  → key "app:" + client_id      应用注册表
 *   OP_CODES → key "code:" + code          授权码（一次性，10 分钟）
 *   OP_CODES → key "token:" + access       访问令牌（1 小时）
 *   OP_CODES → key "refresh:" + refresh    刷新令牌（30 天）
 *   TOKENS   → 管理站 Token（授权页站长身份验证）
 */

export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
};

export function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

export function corsPreflight() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(len) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < len; i++) {
    let r;
    do { r = crypto.getRandomValues(new Uint8Array(1))[0]; } while (r >= 252);
    out += chars[r % chars.length];
  }
  return out;
}

/* SHA-256 hex —— 用于 client_secret 只存哈希 */
export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ---------- 应用注册表（OP_APPS） ---------- */
export async function appGet(env, clientId) {
  if (!env.OP_APPS) return null;
  const raw = await env.OP_APPS.get("app:" + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

export async function appPut(env, app) {
  if (!env.OP_APPS) throw new Error("OP_APPS KV 未绑定");
  await env.OP_APPS.put("app:" + app.client_id, JSON.stringify(app));
}

export async function appDelete(env, clientId) {
  if (env.OP_APPS) await env.OP_APPS.delete("app:" + clientId);
}

/* 列出全部应用（不含 secret_hash，公开字段） */
export async function appListPublic(env) {
  if (!env.OP_APPS) return [];
  const out = [];
  const list = await env.OP_APPS.list({ prefix: "app:" });
  for (const k of list.keys) {
    const raw = await env.OP_APPS.get(k.name);
    if (!raw) continue;
    try {
      const app = JSON.parse(raw);
      out.push({
        client_id: app.client_id,
        name: app.name,
        desc: app.desc || "",
        redirect_uri: app.redirect_uri || "",
        scopes: app.scopes || [],
        created: app.created || 0,
        revoked: !!app.revoked,
      });
    } catch (e) { /* 跳过坏数据 */ }
  }
  return out;
}

/* 列出全部应用（管理视角，含敏感字段） */
export async function appListAdmin(env) {
  if (!env.OP_APPS) return [];
  const out = [];
  const list = await env.OP_APPS.list({ prefix: "app:" });
  for (const k of list.keys) {
    const raw = await env.OP_APPS.get(k.name);
    if (!raw) continue;
    try {
      const app = JSON.parse(raw);
      out.push({
        client_id: app.client_id,
        name: app.name,
        desc: app.desc || "",
        redirect_uri: app.redirect_uri || "",
        scopes: app.scopes || [],
        created: app.created || 0,
        revoked: !!app.revoked,
        has_secret: !!app.secret_hash,
      });
    } catch (e) { /* 跳过坏数据 */ }
  }
  return out;
}

/* ---------- 授权码 / 令牌（OP_CODES） ---------- */
export async function kvGet(env, key) {
  if (!env.OP_CODES) return null;
  return await env.OP_CODES.get(key);
}

export async function kvPut(env, key, obj, ttlSec) {
  if (!env.OP_CODES) throw new Error("OP_CODES KV 未绑定");
  await env.OP_CODES.put(key, JSON.stringify(obj), ttlSec ? { expirationTtl: ttlSec } : undefined);
}

export async function kvDelete(env, key) {
  if (env.OP_CODES) await env.OP_CODES.delete(key);
}

/* ---------- 管理站 Token 校验（授权页站长身份） ---------- */
export async function verifyAdminToken(env, token) {
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

/* 生成 OAuth 应用凭证 */
export async function createAppCredential() {
  const clientId = randomHex(16);
  const clientSecret = randomToken(32);
  const secretHash = await sha256Hex(clientSecret);
  return { client_id: clientId, client_secret: clientSecret, secret_hash: secretHash };
}
