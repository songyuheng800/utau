/**
 * Cloudflare Pages Function —— UTAU 配布站 登录 / 注册后端
 *
 * 职责：
 *   1. sendcode：向邮箱发送 6 位验证码（QQ 邮箱 SMTP 直发，无需第三方邮件服务）
 *   2. register：校验验证码 + 密码，创建账号（密码 PBKDF2 加盐哈希），自动登录
 *   3. login：邮箱 + 密码登录，签发会话 Token
 *   4. me：校验会话 Token，返回当前登录邮箱
 *   5. logout：注销会话
 *
 * 部署位置：Cloudflare Pages 项目的 functions/ 目录（functions/auth.js）
 * 函数路由：https://<你的项目名>.pages.dev/auth
 *
 * 存储：独立 KV 绑定 AUTH_KV（命名空间 UTAU_AUTH，与主站 UTAU_TOKENS 完全隔离），
 *       键前缀 auth_user: / auth_code: / auth_session: / auth_rl:。
 *       未绑定 AUTH_KV 时兜底使用 TOKENS（不推荐，仅过渡）。
 *
 * 环境变量（Pages 项目 → Settings → Environment variables → Production）：
 *   SMTP_USER  发信邮箱（QQ 邮箱地址，如 2192465687@qq.com）
 *   SMTP_PASS  QQ 邮箱 SMTP 授权码（QQ 邮箱设置 → 账户 → 开启 SMTP 服务后生成，非 QQ 密码）
 *   SMTP_HOST  默认 smtp.qq.com（一般不用改）
 *   SMTP_PORT  默认 465（一般不用改）
 */

import { connect } from "cloudflare:sockets";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_TTL = 600;          // 验证码有效期 10 分钟
const RATE_TTL = 60;           // 发送频率限制 60 秒
const SESSION_TTL = 7 * 24 * 60 * 60; // 会话有效期 7 天

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function randomToken(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return hex(arr);
}

/* ---------- 密码哈希（PBKDF2 + 随机盐） ---------- */
async function hashPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: 10000, hash: "SHA-256" }, key, 256);
  return { salt: hex(saltBytes), hash: hex(new Uint8Array(bits)) };
}

async function verifyPassword(password, saltHex, hashHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: hexToBytes(saltHex), iterations: 10000, hash: "SHA-256" }, key, 256);
  return hex(new Uint8Array(bits)) === hashHex;
}

/* ---------- 会话 ---------- */
async function newSession(kv, email) {
  const token = randomToken(32);
  await kv.put("auth_session:" + token, JSON.stringify({ email, created: Date.now() }), { expirationTtl: SESSION_TTL });
  return token;
}

/* ---------- SMTP 客户端（QQ 邮箱 smtp.qq.com:465，隐式 TLS） ---------- */
function b64(s) { return btoa(s); }
function b64u(s) {
  const b = new TextEncoder().encode(s);
  let bin = "";
  b.forEach((x) => { bin += String.fromCharCode(x); });
  return btoa(bin);
}

class SmtpSession {
  constructor(reader, writer) {
    this.reader = reader;
    this.writer = writer;
    this.buf = "";
  }
  async line(ms = 10000) {
    const deadline = Date.now() + ms;
    while (true) {
      const idx = this.buf.indexOf("\r\n");
      if (idx >= 0) {
        const line = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + 2);
        return line;
      }
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
    // 多行响应：形如 "250-xxx\r\n250 yyy"，续行以 "-" 结尾，读到最终行（空格分隔）为止
    while (resp.length >= 4 && resp[3] === "-") {
      resp = await this.line(ms);
    }
    const code = parseInt(resp.slice(0, 3), 10);
    if (!expected.includes(code)) throw new Error("SMTP 错误 " + code + "（命令 " + cmd.split(" ")[0] + "）: " + resp);
    return resp;
  }
}

async function sendVerificationEmail(env, to, code) {
  const host = env.SMTP_HOST || "smtp.qq.com";
  const port = parseInt(env.SMTP_PORT || "465", 10);
  const user = env.SMTP_USER;
  const pass = env.SMTP_PASS;
  if (!user || !pass) throw new Error("SMTP 未配置（SMTP_USER / SMTP_PASS）");

  const socket = connect({ hostname: host, port, tls: true });
  try {
    const s = new SmtpSession(socket.readable.getReader(), socket.writable.getWriter());
    await s.line(); // 220 服务就绪
    await s.cmd("EHLO utau.local", [250]);
    await s.cmd("AUTH LOGIN", [334]);
    await s.cmd(b64(user), [334]);
    await s.cmd(b64(pass), [235]); // 235 认证成功
    await s.cmd("MAIL FROM:<" + user + ">", [250]);
    await s.cmd("RCPT TO:<" + to + ">", [250, 251]);
    await s.cmd("DATA", [354]);

    const subject = "UTAU 配布站注册验证码";
    const text = "你的 UTAU / OpenUTAU 工程配布站注册验证码是：" + code + "\n\n验证码 10 分钟内有效，请勿泄露给他人。\n如果不是你本人操作，请忽略本邮件。";
    const body =
      "From: <" + user + ">\r\n" +
      "To: <" + to + ">\r\n" +
      "Subject: =?UTF-8?B?" + b64u(subject) + "?=\r\n" +
      "MIME-Version: 1.0\r\n" +
      "Content-Type: text/plain; charset=UTF-8\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\n" +
      b64u(text) + "\r\n.\r\n";
    await s.writer.write(new TextEncoder().encode(body));
    await s.line(15000); // 250 邮件已接收
    await s.cmd("QUIT", [221]);
  } finally {
    try { socket.close(); } catch (e) { /* 忽略 */ }
  }
}

/* ---------- 各操作处理 ---------- */
async function handleSendCode(body, kv, env) {
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 100) {
    return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  }
  const rl = await kv.get("auth_rl:" + email);
  if (rl) {
    return json({ ok: false, msg: "发送过于频繁，请 60 秒后再试" }, 429);
  }
  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  await kv.put("auth_code:" + email, code, { expirationTtl: CODE_TTL });
  await kv.put("auth_rl:" + email, "1", { expirationTtl: RATE_TTL });
  try {
    await sendVerificationEmail(env, email, code);
  } catch (e) {
    return json({ ok: false, msg: "邮件发送失败：" + e.message }, 502);
  }
  return json({ ok: true, msg: "验证码已发送至 " + email });
}

async function handleRegister(body, kv) {
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  const password = String(body.password || "");
  if (!EMAIL_RE.test(email) || email.length > 100) {
    return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  }
  if (!/^\d{6}$/.test(code)) {
    return json({ ok: false, msg: "验证码格式不正确（6 位数字）" }, 400);
  }
  if (password.length < 6 || password.length > 64) {
    return json({ ok: false, msg: "密码需为 6~64 位" }, 400);
  }
  const stored = await kv.get("auth_code:" + email);
  if (!stored || stored !== code) {
    return json({ ok: false, msg: "验证码错误或已过期，请重新获取" }, 400);
  }
  const exists = await kv.get("auth_user:" + email);
  if (exists) {
    return json({ ok: false, msg: "该邮箱已注册，请直接登录" }, 409);
  }
  const { salt, hash } = await hashPassword(password);
  await kv.put("auth_user:" + email, JSON.stringify({ salt, hash, created: Date.now() }));
  await kv.delete("auth_code:" + email);
  const token = await newSession(kv, email);
  return json({ ok: true, token, email });
}

async function handleLogin(body, kv) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!EMAIL_RE.test(email)) {
    return json({ ok: false, msg: "邮箱或密码错误" }, 401);
  }
  const rec = await kv.get("auth_user:" + email);
  if (!rec) {
    return json({ ok: false, msg: "邮箱或密码错误" }, 401);
  }
  const u = JSON.parse(rec);
  if (!(await verifyPassword(password, u.salt, u.hash))) {
    return json({ ok: false, msg: "邮箱或密码错误" }, 401);
  }
  const token = await newSession(kv, email);
  return json({ ok: true, token, email });
}

async function handleMe(request, kv) {
  const token = String(new URL(request.url).searchParams.get("token") || "");
  const rec = await kv.get("auth_session:" + token);
  if (!rec) {
    return json({ ok: false, msg: "未登录或会话已过期" }, 401);
  }
  return json({ ok: true, email: JSON.parse(rec).email });
}

async function handleLogout(body, kv) {
  const token = String(body.token || "");
  await kv.delete("auth_session:" + token);
  return json({ ok: true });
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const kv = env.AUTH_KV || env.TOKENS;
  if (!kv) {
    return json({ ok: false, msg: "KV 未绑定（AUTH_KV）" }, 500);
  }

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  if (request.method === "GET" && action === "me") {
    return handleMe(request, kv);
  }

  if (request.method === "POST") {
    let body;
    try { body = await request.json(); } catch (e) {
      return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
    }
    if (action === "sendcode") return handleSendCode(body, kv, env);
    if (action === "register") return handleRegister(body, kv);
    if (action === "login") return handleLogin(body, kv);
    if (action === "logout") return handleLogout(body, kv);
    return json({ ok: false, msg: "未知操作" }, 400);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}
