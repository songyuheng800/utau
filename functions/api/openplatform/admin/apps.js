/**
 * 开放平台 —— 管理员管理（需管理站 Token）
 *   GET  /api/openplatform/admin/apps?token=XXX   全部应用（管理视角）
 *   POST /api/openplatform/admin/apps              body: { token, action, client_id }
 *     action = "revoke"   吊销
 *     action = "restore"  恢复
 */

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
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
  ...SECURITY_HEADERS,
};

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

async function appGet(env, clientId) {
  if (!env.OP_APPS) return null;
  const raw = await env.OP_APPS.get("app:" + clientId);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function appPut(env, app) {
  if (!env.OP_APPS) throw new Error("OP_APPS KV 未绑定");
  await env.OP_APPS.put("app:" + app.client_id, JSON.stringify(app));
}

async function appListAdmin(env) {
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

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();

  if (request.method === "GET") {
    const url = new URL(request.url);
    const token = url.searchParams.get("token") || "";
    if (!(await verifyAdminToken(env, token))) {
      return json({ ok: false, msg: "Token 无效或已过期" }, 403);
    }
    const apps = await appListAdmin(env);
    return json({ ok: true, apps });
  }

  if (request.method === "POST") {
    return handlePost(request, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

async function handlePost(request, env) {
  // CSRF：跨站伪造的吊销/恢复请求会被 Origin/Referer 白名单拦截
  if (!originAllowed(request)) {
    return json({ ok: false, msg: "非法来源，拒绝操作" }, 403);
  }
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const token = String(body.token || "");
  if (!(await verifyAdminToken(env, token))) {
    return json({ ok: false, msg: "Token 无效或已过期" }, 403);
  }

  const action = String(body.action || "");
  const clientId = String(body.client_id || "");
  if (!["revoke", "restore"].includes(action) || !clientId) {
    return json({ ok: false, msg: "action 只支持 revoke / restore，且需要 client_id" }, 400);
  }

  const app = await appGet(env, clientId);
  if (!app) {
    return json({ ok: false, msg: "应用不存在" }, 404);
  }

  app.revoked = action === "revoke";
  app.revoked_at = action === "revoke" ? Date.now() : 0;
  await appPut(env, app);
  return json({ ok: true, msg: action === "revoke" ? "应用已吊销" : "应用已恢复", revoked: !!app.revoked });
}
