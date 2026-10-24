/**
 * 测试站：纯邮箱验证码登录（无密码、无注册）
 *
 * 路由：/otptest?action=sendcode | verify | me | logout
 *   sendcode：给邮箱发 6 位验证码（Resend HTTP API）
 *   verify  ：校验验证码，通过即签发会话 token 并返回登录态
 *
 * 测试兜底：未配置 RESEND_API_KEY，或发送失败时，把验证码随响应回传（便于联调点通）。
 *
 * KV：优先 env.AUTH_KV，兜底 env.TOKENS。
 * 环境变量：RESEND_API_KEY（Resend 密钥）、MAIL_FROM（发件人，未验证域名时用 onboarding@resend.dev）。
 */
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_TTL = 600;       // 验证码 10 分钟
const RATE_TTL = 60;        // 60 秒重发限制
const SESSION_TTL = 7 * 24 * 60 * 60;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

function randomToken(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ---------- 发信：GitHub Actions 代发 QQ SMTP（绕开 CF 函数封禁 SMTP 端口） ---------- */
async function sendCodeEmail(env, to, code) {
  const subject = "邮箱登录验证码";
  const text = "你的登录验证码是：" + code + "\n\n（十分钟内有效，请勿泄露。非本人操作请忽略。）";

  // 通道1：触发 GitHub Actions，由 runner 连 smtp.qq.com:465 发信
  if (env.GH_TOKEN) {
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
      body: JSON.stringify({
        event_type: "send-otp",
        client_payload: { email: to, code, subject, text },
      }),
    });
    if (r.ok) return;
    const t = await r.text();
    throw new Error("GitHub Actions 代发失败 " + r.status + "：" + t.slice(0, 120));
  }

  // 通道2：Brevo HTTP API（/v3/smtp/email）
  const brevoKey = env.BREVO_API_KEY;
  if (brevoKey) {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": brevoKey, "Content-Type": "application/json" },
      body: JSON.stringify({
        sender: { name: "UTAU", email: env.MAIL_FROM || "13181260223@163.com" },
        to: [{ email: to }],
        subject,
        textContent: text,
      }),
    });
    if (!r.ok) {
      const t = await r.text();
      throw new Error("Brevo " + r.status + "：" + t.slice(0, 140));
    }
    return;
  }

  // 回退：Resend 沙箱（仅能发注册邮箱本人）
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) throw new Error("未配置 BREVO_API_KEY / RESEND_API_KEY");
  const from = env.MAIL_FROM || "onboarding@resend.dev";
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, text }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error("Resend " + r.status + "：" + t.slice(0, 140));
  }
}

/* ---------- 操作 ---------- */
async function handleSendCode(body, kv, env) {
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 100) return json({ ok: false, msg: "邮箱格式不正确" }, 400);

  if (await kv.get("otp_rl:" + email)) return json({ ok: false, msg: "发送过于频繁，请 60 秒后再试" }, 429);

  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  await kv.put("otp_code:" + email, code, { expirationTtl: CODE_TTL });
  await kv.put("otp_rl:" + email, "1", { expirationTtl: RATE_TTL });

  // 真邮件发送；未配置/失败时走测试兜底（回传验证码），保证联调可点通
  let devCode = null;
  let failNote = "";
  try {
    await sendCodeEmail(env, email, code);
  } catch (e) {
    devCode = code;
    failNote = "邮件未发出（" + e.message + "），测试模式已回传验证码";
  }
  const out = { ok: true, msg: "验证码已发送至 " + email };
  if (devCode) { out.devCode = devCode; out.note = failNote; }
  return json(out);
}

async function handleVerify(body, kv) {
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  if (!EMAIL_RE.test(email)) return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  if (!/^\d{6}$/.test(code)) return json({ ok: false, msg: "验证码为 6 位数字" }, 400);

  const stored = await kv.get("otp_code:" + email);
  if (!stored || stored !== code) return json({ ok: false, msg: "验证码错误或已过期，请重新获取" }, 400);

  await kv.delete("otp_code:" + email);
  const token = randomToken(32);
  await kv.put("otp_session:" + token, JSON.stringify({ email, created: Date.now() }), { expirationTtl: SESSION_TTL });
  return json({ ok: true, token, email, msg: "登录成功" });
}

async function handleMe(request, kv) {
  const token = String(new URL(request.url).searchParams.get("token") || "");
  const rec = await kv.get("otp_session:" + token);
  if (!rec) return json({ ok: false, msg: "未登录或会话已过期" }, 401);
  return json({ ok: true, email: JSON.parse(rec).email });
}

async function handleLogout(body, kv) {
  await kv.delete("otp_session:" + String(body.token || ""));
  return json({ ok: true });
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const kv = env.AUTH_KV || env.TOKENS;
  if (!kv) return json({ ok: false, msg: "KV 未绑定（AUTH_KV / TOKENS）" }, 500);

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  if (request.method === "GET" && action === "me") return handleMe(request, kv);

  if (request.method === "POST") {
    let body;
    try { body = await request.json(); } catch (e) { return json({ ok: false, msg: "请求体不是合法 JSON" }, 400); }
    if (action === "sendcode") return handleSendCode(body, kv, env);
    if (action === "verify") return handleVerify(body, kv);
    if (action === "logout") return handleLogout(body, kv);
    return json({ ok: false, msg: "未知操作" }, 400);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}
