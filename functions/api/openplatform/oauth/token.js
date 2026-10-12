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
import { json, corsPreflight, randomHex, sha256Hex, appGet, kvPut, kvGet, kvDelete } from "./_lib.js";

const ACCESS_TTL = 60 * 60;          // 1 小时
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
  if (!raw) return json({ ok: false, msg: "授权码无效或已过期" }, 400);
  let grant;
  try { grant = JSON.parse(raw); } catch (e) { return json({ ok: false, msg: "授权码数据损坏" }, 500); }

  if (grant.used) return json({ ok: false, msg: "授权码已被使用（一次性）" }, 400);
  if (grant.client_id !== app.client_id) return json({ ok: false, msg: "授权码与应用不匹配" }, 400);

  // 标记已使用
  grant.used = true;
  await kvPut(env, "code:" + code, grant, 60);
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

  // 轮换：旧 refresh 作废
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
