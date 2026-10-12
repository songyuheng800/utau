/**
 * 开放平台 —— 应用自助注册 / 公开列表
 *   GET  /api/openplatform/apps            公开应用列表（不含密钥）
 *   POST /api/openplatform/apps            自助注册（name/desc/redirect_uri/scopes）
 *   返回 client_id + client_secret（secret 仅此一次明文返回）
 *
 * 注意：Cloudflare Pages Functions 不支持跨文件相对导入，公共工具已内联。
 */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
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

function randomToken(len) {
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

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function appPut(env, app) {
  if (!env.OP_APPS) throw new Error("OP_APPS KV 未绑定");
  await env.OP_APPS.put("app:" + app.client_id, JSON.stringify(app));
}

async function appListPublic(env) {
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

async function createAppCredential() {
  const clientId = randomHex(16);
  const clientSecret = randomToken(32);
  const secretHash = await sha256Hex(clientSecret);
  return { client_id: clientId, client_secret: clientSecret, secret_hash: secretHash };
}

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
