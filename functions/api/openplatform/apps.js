/**
 * 开放平台 —— 应用自助注册 / 公开列表
 *   GET  /api/openplatform/apps            公开应用列表（不含密钥）
 *   POST /api/openplatform/apps            自助注册（name/desc/redirect_uri/scopes）
 *   返回 client_id + client_secret（secret 仅此一次明文返回）
 */
import { json, corsPreflight, randomHex, createAppCredential, appPut, appListPublic } from "./_lib.js";

const VALID_SCOPES = ["read", "write"];
const REDIRECT_URI_MAX = 500;

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();

  if (request.method === "GET") {
    const apps = await appListPublic(env);
    return json({ ok: true, apps });
  }

  if (request.method === "POST") {
    return handleRegister(request, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const name = String(body.name || "").trim();
  const desc = String(body.desc || "").trim();
  const redirectUri = String(body.redirect_uri || "").trim();
  const rawScopes = Array.isArray(body.scopes) ? body.scopes : ["read"];

  if (name.length < 1 || name.length > 40) {
    return json({ ok: false, msg: "应用名称必填，1-40 个字符" }, 400);
  }
  if (desc.length > 200) {
    return json({ ok: false, msg: "应用描述最多 200 字" }, 400);
  }
  if (!/^https:\/\/.+/.test(redirectUri) || redirectUri.length > REDIRECT_URI_MAX) {
    return json({ ok: false, msg: "回调地址必须是 https:// 开头的完整 URL" }, 400);
  }
  const scopes = rawScopes.filter((s) => VALID_SCOPES.includes(String(s)));
  if (scopes.length === 0) {
    return json({ ok: false, msg: "至少选择一个权限范围（read/write）" }, 400);
  }
  // write 权限必须同时含 read
  if (scopes.includes("write") && !scopes.includes("read")) scopes.unshift("read");

  const { client_id, client_secret, secret_hash } = await createAppCredential();
  const app = {
    client_id,
    name,
    desc,
    redirect_uri: redirectUri,
    scopes,
    secret_hash,
    created: Date.now(),
    revoked: false,
  };
  try {
    await appPut(env, app);
  } catch (e) {
    return json({ ok: false, msg: "OP_APPS KV 未绑定，无法注册" }, 500);
  }

  return json({
    ok: true,
    client_id,
    client_secret,
    note: "client_secret 仅显示这一次，请立即保存；后端只存其哈希。",
    app: { name, desc, redirect_uri: redirectUri, scopes, created: app.created },
  }, 201);
}
