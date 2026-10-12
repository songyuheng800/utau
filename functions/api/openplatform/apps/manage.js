/**
 * 开放平台 —— 开发者应用管理（凭据校验 / 自吊销 / 详情）
 *   POST /api/openplatform/apps/manage  body: { action, client_id, client_secret }
 *     action = "info"    校验 client_secret 后返回应用详情（可含吊销状态）
 *     action = "revoke"  校验 client_secret 后吊销应用
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

async function appPut(env, app) {
  if (!env.OP_APPS) throw new Error("OP_APPS KV 未绑定");
  await env.OP_APPS.put("app:" + app.client_id, JSON.stringify(app));
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();
  if (request.method !== "POST") return json({ ok: false, msg: "方法错误" }, 405);

  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const action = String(body.action || "");
  const clientId = String(body.client_id || "");
  const secret = String(body.client_secret || "");

  if (!["info", "revoke"].includes(action)) {
    return json({ ok: false, msg: "action 只支持 info / revoke" }, 400);
  }
  if (!clientId || !secret) {
    return json({ ok: false, msg: "缺少 client_id 或 client_secret" }, 400);
  }

  const app = await appGet(env, clientId);
  if (!app) {
    return json({ ok: false, msg: "应用不存在" }, 404);
  }

  const hash = await sha256Hex(secret);
  if (hash !== app.secret_hash) {
    return json({ ok: false, msg: "client_secret 错误" }, 403);
  }

  if (action === "info") {
    return json({
      ok: true,
      app: {
        client_id: app.client_id,
        name: app.name,
        desc: app.desc || "",
        redirect_uri: app.redirect_uri,
        scopes: app.scopes || [],
        created: app.created,
        revoked: !!app.revoked,
      },
    });
  }

  // revoke
  app.revoked = true;
  app.revoked_at = Date.now();
  await appPut(env, app);
  return json({ ok: true, msg: "应用已吊销，该 client_id 将无法再发起授权" });
}
