/**
 * 开放平台 —— OAuth 授权端点
 *   GET  /api/openplatform/oauth/authorize?client_id&redirect_uri&scope&state&response_type=code
 *        预检：校验应用存在 / 未吊销 / 回调地址匹配，返回应用信息与请求的权限（授权页展示用）
 *   POST /api/openplatform/oauth/authorize  body: { client_id, redirect_uri, scope, state, token }
 *        站长输入管理站 Token 确认授权 → 生成一次性授权码 → 返回 redirect_url（含 code & state）
 *
 * 授权码：24 字节随机 hex，存 OP_CODES（key "code:"+code），10 分钟有效，一次性使用。
 */
import { json, corsPreflight, randomHex, appGet, kvPut } from "./_lib.js";

const CODE_TTL = 10 * 60; // 10 分钟
const CODE_RE = /^[a-f0-9]{48}$/;

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();

  if (request.method === "GET") return handleCheck(request, env);
  if (request.method === "POST") return handleConfirm(request, env);

  return json({ ok: false, msg: "方法错误" }, 405);
}

/* ---------- 预检（授权页加载时调用） ---------- */
async function handleCheck(request, env) {
  const url = new URL(request.url);
  const clientId = String(url.searchParams.get("client_id") || "");
  const redirectUri = String(url.searchParams.get("redirect_uri") || "");
  const rawScopes = String(url.searchParams.get("scope") || "read");

  const app = await appGet(env, clientId);
  if (!app) {
    return json({ ok: false, msg: "应用不存在：client_id 无效" }, 400);
  }
  if (app.revoked) {
    return json({ ok: false, msg: "该应用已被吊销，请联系平台管理员" }, 403);
  }
  if (app.redirect_uri !== redirectUri) {
    return json({ ok: false, msg: "回调地址与注册时不匹配" }, 400);
  }

  const scopes = rawScopes.split(/[\s,]+/).filter(Boolean);
  // 请求的权限必须是应用已注册权限的子集
  const invalid = scopes.filter((s) => !app.scopes.includes(s));
  if (invalid.length > 0) {
    return json({ ok: false, msg: "请求了应用未注册的权限：" + invalid.join(",") }, 400);
  }

  return json({
    ok: true,
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
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const clientId = String(body.client_id || "");
  const redirectUri = String(body.redirect_uri || "");
  const state = String(body.state || "");
  const token = String(body.token || "").trim();
  const rawScopes = String(body.scope || "read");

  const app = await appGet(env, clientId);
  if (!app) return json({ ok: false, msg: "应用不存在" }, 400);
  if (app.revoked) return json({ ok: false, msg: "该应用已被吊销" }, 403);
  if (app.redirect_uri !== redirectUri) return json({ ok: false, msg: "回调地址不匹配" }, 400);

  const scopes = rawScopes.split(/[\s,]+/).filter(Boolean);
  if (scopes.some((s) => !app.scopes.includes(s))) {
    return json({ ok: false, msg: "请求了未注册的权限" }, 400);
  }

  // 站长身份：管理站 Token
  const { verifyAdminToken } = await import("./_lib.js");
  if (!(await verifyAdminToken(env, token))) {
    return json({ ok: false, msg: "管理站 Token 无效或已过期" }, 403);
  }

  // 生成一次性授权码
  let code;
  do { code = randomHex(24); } while (CODE_RE.test(code) === false || (await env.OP_CODES.get("code:" + code)));

  await kvPut(env, "code:" + code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    scopes,
    user: "admin",
    used: false,
    issued: Date.now(),
  }, CODE_TTL);

  const sep = redirectUri.includes("?") ? "&" : "?";
  const redirectUrl = redirectUri + sep + "code=" + encodeURIComponent(code) + "&state=" + encodeURIComponent(state);

  return json({ ok: true, redirect_url: redirectUrl, code });
}
