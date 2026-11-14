/**
 * 登录站手机短信验证码登录（独立体系，与邮箱验证码平行，不经过 OAuth / 第三方授权）
 *
 * 路由：/sms-login?action=sendcode | verify | login-password
 *   sendcode       ：给手机号发 6 位数字验证码（Spug 推送助手，HTTP POST，后端发起）
 *   verify         ：校验验证码，通过即签发 utau_session 并写 HttpOnly Cookie
 *   login-password ：手机号 + 密码直接登录（注册时设过密码的账号）
 *
 * 安全：Origin/Referer 白名单防 CSRF；60 秒重发限流；验证码 10 分钟有效；
 *      统一安全响应头，防点击劫持 / MIME 嗅探；凭证仅存服务端环境变量，不下发前端。
 * KV：优先 env.AUTH_KV，兜底 env.TOKENS。
 *
 * 环境变量：
 *   SPUG_SMS_CODE  ：Spug 短信模板编码（调用凭证，形如 A27L****bgEY）。未配置时接口返回“未开通”。
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

// 大陆手机号：11 位，1 开头，第二位 3-9
const PHONE_RE = /^1[3-9]\d{9}$/;
const CODE_TTL = 600;      // 验证码 10 分钟
const RATE_TTL = 60;       // 60 秒重发限制
const SESSION_TTL = 7 * 24 * 3600;

function originAllowed(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin) return ALLOWED_ORIGINS.includes(origin);
  const ref = request.headers.get("Referer") || "";
  if (!ref) return false;
  try { return ALLOWED_ORIGINS.includes(new URL(ref).origin); } catch (e) { return false; }
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(obj, status = 200, extra = {}, request) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
      ...(request ? corsHeaders(request) : {}),
      ...extra,
    },
  });
}

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function pbkdf2(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 归一化手机号：去除 +86 / 86 前缀、空格、横线；返回 11 位号码或 null */
function normalizePhone(raw) {
  let s = String(raw || "").replace(/[^\d]/g, "");
  if (s.startsWith("86") && s.length === 13) s = s.slice(2);
  if (s.startsWith("0086") && s.length === 15) s = s.slice(4);
  return PHONE_RE.test(s) ? s : null;
}

/* ---------- 发信：Spug 推送助手（后端 HTTP POST，模板编码即凭证） ---------- */
async function sendCodeSms(env, phone, code) {
  const tpl = env.SPUG_SMS_CODE;
  if (!tpl) throw new Error("短信通道尚未开通");
  let resp;
  try {
    resp = await fetch("https://push.spug.cc/sms/" + encodeURIComponent(tpl), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to: phone, code, number: 10 }),
    });
  } catch (e) {
    throw new Error("短信服务网络异常：" + e.message.slice(0, 100));
  }
  let data = {};
  try { data = await resp.json(); } catch (e) { /* 非 JSON 时按状态码判断 */ }
  if (resp.ok && (data.code === 200 || data.code === 0)) return;
  const msg = data.msg || ("HTTP " + resp.status);
  throw new Error("短信发送失败：" + String(msg).slice(0, 100));
}

async function handleSendCode(body, kv, env) {
  const phone = normalizePhone(body.phone);
  if (!phone) return json({ ok: false, msg: "手机号格式不正确（需为大陆 11 位手机号）" }, 400);

  if (await kv.get("sms_rl:" + phone)) return json({ ok: false, msg: "发送过于频繁，请 60 秒后再试" }, 429);

  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  await kv.put("sms_code:" + phone, code, { expirationTtl: CODE_TTL });
  await kv.put("sms_rl:" + phone, "1", { expirationTtl: RATE_TTL });

  try {
    await sendCodeSms(env, phone, code);
  } catch (e) {
    // 发送失败即清掉已写的验证码，避免占用限流窗口后用户拿不到码
    await kv.delete("sms_code:" + phone);
    await kv.delete("sms_rl:" + phone);
    return json({ ok: false, msg: e.message }, 502);
  }
  return json({ ok: true, msg: "验证码已发送至 " + phone });
}

async function handleVerify(body, kv) {
  const phone = normalizePhone(body.phone);
  const code = String(body.code || "").trim();
  if (!phone) return json({ ok: false, msg: "手机号格式不正确" }, 400);
  if (!/^\d{6}$/.test(code)) return json({ ok: false, msg: "验证码为 6 位数字" }, 400);

  const stored = await kv.get("sms_code:" + phone);
  if (!stored || stored !== code) return json({ ok: false, msg: "验证码错误或已过期，请重新获取" }, 400);

  await kv.delete("sms_code:" + phone);

  // 注册时可一并设置密码：6-64 位，PBKDF2 加盐哈希落库
  if (body.password) {
    const pw = String(body.password || "");
    if (pw.length < 6 || pw.length > 64) return json({ ok: false, msg: "密码需 6-64 位" }, 400);
    const salt = randomHex(16);
    const hash = await pbkdf2(pw, salt);
    await kv.put("pwd_phone:" + phone, JSON.stringify({ salt, hash, phone, created: Date.now() }));
  }

  const token = randomHex(32);
  const session = { provider: "phone", phone, name: "用户" + phone.slice(-4), created: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "登录成功", user: session }, 200, {
    "Set-Cookie": `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=Lax`,
  });
}

// 手机号 + 密码直接登录（注册时设过密码的账号）
async function handlePhonePassword(body, kv) {
  const phone = normalizePhone(body.phone);
  const password = String(body.password || "");
  if (!phone) return json({ ok: false, msg: "手机号格式不正确" }, 400);
  if (!password) return json({ ok: false, msg: "请输入密码" }, 400);

  const raw = await kv.get("pwd_phone:" + phone).catch(() => null);
  let authorized = false;
  if (raw) {
    try {
      const rec = JSON.parse(raw);
      const hash = await pbkdf2(password, rec.salt);
      authorized = hash === rec.hash;
    } catch (e) { authorized = false; }
  }
  if (!authorized) return json({ ok: false, msg: "手机号或密码错误" }, 401);

  const token = randomHex(32);
  const session = { provider: "phone", phone, name: "用户" + phone.slice(-4), created: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "登录成功", user: session }, 200, {
    "Set-Cookie": `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=Lax`,
  });
}

function withCors(resp, request) {
  const h = new Headers(resp.headers);
  const ch = corsHeaders(request);
  for (const [k, v] of Object.entries(ch)) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}

export async function onRequest(context) {
  const { request, env } = context;
  // 跨域预检
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }

  const kv = env.AUTH_KV || env.TOKENS;
  if (!kv) return withCors(json({ ok: false, msg: "KV 未绑定（AUTH_KV / TOKENS）" }, 500), request);

  const action = new URL(request.url).searchParams.get("action");

  if (request.method === "POST") {
    // CSRF：跨站伪造的写操作被 Origin/Referer 白名单拦截
    if (!originAllowed(request)) return withCors(json({ ok: false, msg: "非法来源，拒绝操作" }, 403), request);
    let body;
    try { body = await request.json(); } catch (e) { return withCors(json({ ok: false, msg: "请求体不是合法 JSON" }, 400), request); }
    let resp;
    if (action === "sendcode") resp = await handleSendCode(body, kv, env);
    else if (action === "verify") resp = await handleVerify(body, kv);
    else if (action === "login-password") resp = await handlePhonePassword(body, kv);
    else resp = json({ ok: false, msg: "未知操作" }, 400);
    return withCors(resp, request);
  }

  return withCors(json({ ok: false, msg: "方法错误" }, 405), request);
}
