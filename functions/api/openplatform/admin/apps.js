/**
 * 开放平台 —— 管理员管理（需管理站 Token）
 *   GET  /api/openplatform/admin/apps?token=XXX   全部应用（管理视角）
 *   POST /api/openplatform/admin/apps              body: { token, action, client_id }
 *     action = "revoke"   吊销
 *     action = "restore"  恢复
 */
import { json, corsPreflight, verifyAdminToken, appListAdmin, appGet, appPut } from "./_lib.js";

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
