/**
 * 测试站：纯邮箱验证码登录（无密码、无注册）
 *
 * 路由：/otptest?action=sendcode | verify | me | logout
 *   sendcode：给邮箱发 6 位验证码（QQ 邮箱 SMTP 直发）
 *   verify  ：校验验证码，通过即签发会话 token 并返回登录态
 *
 * 测试兜底：未配置 SMTP_USER/SMTP_PASS，或发送失败时，把验证码随响应回传
 * （仅便于本地/联调点通；配好 SMTP 后自动走真邮件，不再回传）。
 *
 * KV：优先 env.AUTH_KV，兜底 env.TOKENS。
 * 环境变量：SMTP_USER（发信邮箱）、SMTP_PASS（QQ SMTP 授权码）、SMTP_HOST/SMTP_PORT 可选。
 */
import { connect } from "cloudflare:sockets";

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

function b64u(s) {
  const b = new TextEncoder().encode(s);
  let bin = "";
  b.forEach((x) => { bin += String.fromCharCode(x); });
  return btoa(bin);
}

/* ---------- SMTP 客户端（QQ smtp.qq.com:465 隐式 TLS） ---------- */
class SmtpSession {
  constructor(reader, writer) { this.reader = reader; this.writer = writer; this.buf = ""; }
  async line(ms = 10000) {
    const deadline = Date.now() + ms;
    while (true) {
      const idx = this.buf.indexOf("\r\n");
      if (idx >= 0) { const l = this.buf.slice(0, idx); this.buf = this.buf.slice(idx + 2); return l; }
      if (Date.now() > deadline) throw new Error("SMTP 响应超时");
      const { value, done } = await Promise.race([
        this.reader.read(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("SMTP 响应超时")), 5000)),
      ]);
      if (done) throw new Error("SMTP 连接被关闭");
      this.buf += new TextDecoder().decode(value);
    }
  }
  async cmd(cmd, expected, ms = 20000) {
    await this.writer.write(new TextEncoder().encode(cmd + "\r\n"));
    let resp = await this.line(ms);
    while (resp.length >= 4 && resp[3] === "-") resp = await this.line(ms);
    const code = parseInt(resp.slice(0, 3), 10);
    if (!expected.includes(code)) throw new Error("SMTP 错误 " + code + "（" + cmd.split(" ")[0] + "）: " + resp);
    return resp;
  }
}

async function sendCodeEmail(env, to, code) {
  const host = env.SMTP_HOST || "smtp.qq.com";
  const port = parseInt(env.SMTP_PORT || "465", 10);
  const user = env.SMTP_USER;
  const pass = env.SMTP_PASS;
  if (!user || !pass) throw new Error("SMTP 未配置（SMTP_USER / SMTP_PASS）");

  const socket = connect({ hostname: host, port, secureTransport: "on" });
  try {
    const s = new SmtpSession(socket.readable.getReader(), socket.writable.getWriter());
    await s.line();
    await s.cmd("EHLO otp.local", [250]);
    await s.cmd("AUTH LOGIN", [334]);
    await s.cmd(btoa(user), [334]);
    await s.cmd(btoa(pass), [235]);
    await s.cmd("MAIL FROM:<" + user + ">", [250]);
    await s.cmd("RCPT TO:<" + to + ">", [250, 251]);
    await s.cmd("DATA", [354]);
    const subject = "邮箱登录验证码";
    const text = "你的测试站登录验证码是：" + code + "\n\n10 分钟内有效，请勿泄露。非本人操作请忽略。";
    const body =
      "From: <" + user + ">\r\nTo: <" + to + ">\r\n" +
      "Subject: =?UTF-8?B?" + b64u(subject) + "?=\r\n" +
      "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\n" + b64u(text) + "\r\n.\r\n";
    await s.writer.write(new TextEncoder().encode(body));
    await s.line(15000);
    await s.cmd("QUIT", [221]);
  } finally {
    try { socket.close(); } catch (e) { /* 忽略 */ }
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
  let smtpNote = "";
  try {
    await sendCodeEmail(env, email, code);
  } catch (e) {
    devCode = code;
    smtpNote = "真邮件未发送（" + e.message + "），测试模式已回传验证码";
  }
  const out = { ok: true, msg: "验证码已发送至 " + email };
  if (devCode) { out.devCode = devCode; out.note = smtpNote; }
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

// 临时诊断：探测函数到 QQ SMTP 各端口的连通与问候
async function handleDiag() {
  const probes = [
    { h: "smtp.qq.com", p: 465, st: "on" },
    { h: "smtp.qq.com", p: 587, st: undefined },
    { h: "smtp.qq.com", p: 25, st: undefined },
  ];
  const out = [];
  for (const pr of probes) {
    const r = { port: pr.p };
    let socket;
    try {
      const opt = { hostname: pr.h, port: pr.p };
      if (pr.st === "on") opt.secureTransport = "on";
      socket = connect(opt);
      const reader = socket.readable.getReader();
      const { value } = await Promise.race([
        reader.read(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("连接/问候超时")), 6000)),
      ]);
      r.greeting = new TextDecoder().decode(value).slice(0, 100);
    } catch (e) { r.error = e.message; }
    finally { try { if (socket) socket.close(); } catch (_) {} }
    out.push(r);
  }
  return json({ ok: true, probes: out });
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const kv = env.AUTH_KV || env.TOKENS;
  if (!kv) return json({ ok: false, msg: "KV 未绑定（AUTH_KV / TOKENS）" }, 500);

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  if (request.method === "GET" && action === "me") return handleMe(request, kv);
  if (request.method === "GET" && action === "diag") return handleDiag();

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
