/**
 * 登录站邮箱验证码登录（独立体系，不经过 OAuth / 第三方授权）
 *
 * 路由：/otp-login?action=sendcode | verify
 *   sendcode：给邮箱发 6 位验证码（GitHub Actions 代发 QQ SMTP）
 *   verify  ：校验验证码，通过即签发 utau_session 并写 HttpOnly Cookie
 *
 * 安全：Origin/Referer 白名单防 CSRF；60 秒重发限流；验证码 10 分钟有效；
 *      统一安全响应头，防点击劫持 / MIME 嗅探。
 * KV：优先 env.AUTH_KV，兜底 env.TOKENS。
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

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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

/* ---------- 发信：GitHub Actions 代发 QQ SMTP（绕开 CF 函数封禁 SMTP 端口） ---------- */
async function sendCodeEmail(env, to, code) {
  const subject = "邮箱登录验证码";
  const text = "你的登录验证码是：" + code + "\n\n（十分钟内有效，请勿泄露。非本人操作请忽略。）";
  const errs = [];

  // 通道1：触发 GitHub Actions，由 runner 连 smtp.qq.com:465 发信；失败降级不中断
  if (env.GH_TOKEN) {
    try {
      const owner = env.GH_USER || "songyuheng800";
      const repo = env.GH_REPO || "utau";
      const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/dispatches`, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + env.GH_TOKEN,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "User-Agent": "utau-otp",
        },
        body: JSON.stringify({ event_type: "send-otp", client_payload: { email: to, code, subject, text } }),
      });
      if (r.ok) return;
      errs.push("GitHub Actions " + r.status);
    } catch (e) {
      errs.push("GitHub Actions 异常：" + e.message.slice(0, 100));
    }
  }
  if (env.BREVO_API_KEY) {
    try {
      const r = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: { name: "UTAU", email: env.MAIL_FROM || "13181260223@163.com" },
          to: [{ email: to }],
          subject,
          textContent: text,
        }),
      });
      if (r.ok) return;
      errs.push("Brevo " + r.status);
    } catch (e) {
      errs.push("Brevo 异常：" + e.message.slice(0, 100));
    }
  }
  if (env.RESEND_API_KEY) {
    try {
      const from = env.MAIL_FROM || "onboarding@resend.dev";
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ from, to: [to], subject, text }),
      });
      if (r.ok) return;
      errs.push("Resend " + r.status);
    } catch (e) {
      errs.push("Resend 异常：" + e.message.slice(0, 100));
    }
  }
  throw new Error(errs.length ? errs.join(" | ") : "未配置任何发信通道");
}

async function handleSendCode(body, kv, env) {
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 100) return json({ ok: false, msg: "邮箱格式不正确" }, 400);

  if (await kv.get("otp_rl:" + email)) return json({ ok: false, msg: "发送过于频繁，请 60 秒后再试" }, 429);

  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  await kv.put("otp_code:" + email, code, { expirationTtl: CODE_TTL });
  await kv.put("otp_rl:" + email, "1", { expirationTtl: RATE_TTL });

  try {
    await sendCodeEmail(env, email, code);
  } catch (e) {
    return json({ ok: false, msg: "邮件发送失败：" + e.message }, 502);
  }
  return json({ ok: true, msg: "验证码已发送至 " + email });
}

async function handleVerify(body, kv) {
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  if (!EMAIL_RE.test(email)) return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  if (!/^\d{6}$/.test(code)) return json({ ok: false, msg: "验证码为 6 位数字" }, 400);

  const stored = await kv.get("otp_code:" + email);
  if (!stored || stored !== code) return json({ ok: false, msg: "验证码错误或已过期，请重新获取" }, 400);

  await kv.delete("otp_code:" + email);

  // 注册时可一并设置密码：6-64 位，PBKDF2 加盐哈希落库
  if (body.password) {
    const pw = String(body.password || "");
    if (pw.length < 6 || pw.length > 64) return json({ ok: false, msg: "密码需 6-64 位" }, 400);
    const salt = randomHex(16);
    const hash = await pbkdf2(pw, salt);
    await kv.put("pwd_email:" + email, JSON.stringify({ salt, hash, email, created: Date.now() }));
  }

  const token = randomHex(32);
  const session = { provider: "email", email, name: email.split("@")[0], created: Date.now() };
  await kv.put("session:" + token, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  return json({ ok: true, msg: "登录成功", user: session }, 200, {
    "Set-Cookie": `utau_session=${token}; Path=/; Max-Age=${SESSION_TTL}; Secure; HttpOnly; SameSite=Lax`,
  });
}

// 邮箱 + 密码直接登录（注册时设过密码的账号）
async function handleEmailPassword(body, kv) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!EMAIL_RE.test(email)) return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  if (!password) return json({ ok: false, msg: "请输入密码" }, 400);

  const raw = await kv.get("pwd_email:" + email).catch(() => null);
  let authorized = false;
  if (raw) {
    try {
      const rec = JSON.parse(raw);
      const hash = await pbkdf2(password, rec.salt);
      authorized = hash === rec.hash;
    } catch (e) { authorized = false; }
  }
  if (!authorized) return json({ ok: false, msg: "邮箱或密码错误" }, 401);

  const token = randomHex(32);
  const session = { provider: "email", email, name: email.split("@")[0], created: Date.now() };
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
    else if (action === "login-password") resp = await handleEmailPassword(body, kv);
    else resp = json({ ok: false, msg: "未知操作" }, 400);
    return withCors(resp, request);
  }

  return withCors(json({ ok: false, msg: "方法错误" }, 405), request);
}
