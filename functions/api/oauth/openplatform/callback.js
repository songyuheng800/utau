/**
 * OpenPlatform（开放平台）OAuth 回调
 * GET /api/oauth/openplatform/callback?code=...&state=...
 * 1. 校验 state（登录页固定值 utau_login，或走 start 生成的随机 state）
 * 2. 用 code 换 access_token（POST utau-4oo /api/openplatform/oauth/token，JSON）
 * 3. 拉取用户信息（GET utau-4oo /api/openplatform/api/userinfo，Bearer）
 * 4. 签发会话 cookie（存 AUTH_KV，7 天），302 跳回登录页
 */
const FRONT_ORIGIN = "https://songyuheng800.github.io";
const SESSION_TTL = 7 * 24 * 3600;
const OP_BASE = "https://utau-4oo.pages.dev";

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;
  const CLIENT_ID = env.OP_OAUTH_CLIENT_ID;
  const CLIENT_SECRET = env.OP_OAUTH_CLIENT_SECRET;
  const REDIRECT_URI = "https://utau-4oo.pages.dev/api/oauth/openplatform/callback";

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const fail = (why) => Response.redirect(`${FRONT_ORIGIN}/utau/login/?err=${encodeURIComponent(why)}`, 302);

  if (!code || !state) return fail("缺少 code 或 state");
  if (!kv || !CLIENT_ID || !CLIENT_SECRET) return fail("服务未配置");

  // state 校验：静态登录按钮使用固定值 utau_login；若走 start 接口则校验 KV 一次性 state
  if (state !== "utau_login") {
    try {
      const saved = await kv.get("oauth_state:" + state);
      if (saved === null) return fail("state 校验失败");
      await kv.delete("oauth_state:" + state);
    } catch (e) {
      return fail("state 校验异常");
    }
  }

  // 1. code 换 access_token（openplatform token 端点，JSON body）
  let tokenResp;
  try {
    tokenResp = await fetch(OP_BASE + "/api/openplatform/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "utau-login" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
    });
  } catch (e) {
    return fail("换取 token 失败：" + e.message);
  }
  const tokenData = await tokenResp.json();
  if (!tokenData.access_token) {
    return fail("开放平台拒绝授权：" + (tokenData.msg || tokenData.error_description || tokenData.error || "未知错误"));
  }

  // 2. 拉取用户信息
  let userResp;
  try {
    userResp = await fetch(OP_BASE + "/api/openplatform/api/userinfo", {
      headers: { Authorization: "Bearer " + tokenData.access_token, "User-Agent": "utau-login", "Accept": "application/json" },
    });
  } catch (e) {
    return fail("获取用户信息失败：" + e.message);
  }
  if (userResp.status !== 200) return fail("开放平台用户接口异常 " + userResp.status);
  const userData = await userResp.json();
  const u = userData.user || {};
  if (!u.id) return fail("开放平台未返回用户信息");

  const session = {
    op_id: u.id,
    name: u.name || u.id,
    avatar: u.avatar || "",
    site: u.site || "",
    provider: "openplatform",
    op_access_token: tokenData.access_token || "",
    op_refresh_token: tokenData.refresh_token || "",
    op_scope: tokenData.scope || (tokenData.scopes || []).join(" ") || "read",
    created_at: Date.now(),
  };

  const token = randomHex(32);
  try {
    await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });
  } catch (e) {
    return fail("会话写入失败");
  }

  const cookie = `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=None`;
  return new Response(null, {
    status: 302,
    headers: { Location: `${FRONT_ORIGIN}/utau/login/?ok=1`, "Set-Cookie": cookie },
  });
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}
