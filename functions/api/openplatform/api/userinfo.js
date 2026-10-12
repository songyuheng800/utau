/**
 * 开放平台 —— 用户信息 API
 *   GET /api/openplatform/api/userinfo   Authorization: Bearer <access_token>
 *   返回当前授权用户（站长）公开信息
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

async function kvGet(env, key) {
  if (!env.OP_CODES) return null;
  return await env.OP_CODES.get(key);
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsPreflight();
  if (request.method !== "GET") return json({ ok: false, msg: "方法错误" }, 405);

  const auth = String(request.headers.get("Authorization") || "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const raw = await kvGet(env, "token:" + token);
  if (!raw) return json({ ok: false, msg: "access_token 无效或已过期" }, 401);

  let access;
  try { access = JSON.parse(raw); } catch (e) {
    return json({ ok: false, msg: "令牌数据损坏" }, 500);
  }
  if (access.type !== "access") return json({ ok: false, msg: "令牌类型错误" }, 401);

  return json({
    ok: true,
    user: {
      id: access.user || "admin",
      name: "UTAU 配布站管理员",
      site: "https://songyuheng800.github.io/utau/",
    },
    scope: (access.scopes || []).join(" "),
    client_id: access.client_id,
  });
}
