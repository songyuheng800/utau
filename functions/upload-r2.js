/**
 * Cloudflare Pages Function —— UTAU / OpenUTAU 工程配布站后端（R2 对象存储版）
 *
 * 职责：访客匿名上传/下载/删除文件，文件全部存 Cloudflare R2，日志存 KV。
 *       不再依赖 GitHub 仓库，无 base64 膨胀，无 GitHub API 限速。
 *
 * 部署位置：Cloudflare Pages 项目的 functions/upload.js（替换旧版）
 * 函数路由：https://<你的项目名>.pages.dev/upload
 *
 * 需要的绑定（Pages → Settings → Bindings）：
 *   R2 Bucket 绑定名：UTAU_R2  （桶名随意，如 utau-files）
 *   KV Namespace 绑定名：UTAU_LOGS  （存访问/下载日志）
 *   环境变量：ADMIN_PASSWORD （管理密码，默认 233677）
 */

const MAX_RAW_SIZE = 50 * 1024 * 1024; // 单文件上限 50MB
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const MAX_NAME_LEN = 200;
const LOG_KEY = "access_logs";
const LOG_MAX = 500; // KV 里最多保留 500 条日志

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

export async function onRequest(context) {
  const { request, env } = context;

  // 浏览器跨域预检
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // 检查 R2 绑定是否存在
  if (!env.UTAU_R2) {
    return json({ ok: false, msg: "R2 存储未绑定（UTAU_R2）" }, 500);
  }

  const url = new URL(request.url);

  // GET：列表 / 下载 / 日志
  if (request.method === "GET") {
    // ?stats=密码 → 查看访问日志
    if (url.searchParams.has("stats")) {
      return handleStats(url.searchParams.get("stats"), env);
    }
    // ?download=文件名 → 代理下载
    if (url.searchParams.has("download")) {
      return handleDownload(url.searchParams.get("download"), request, env);
    }
    // 默认：文件列表
    return handleList(request, env);
  }

  // POST：上传 / 记录访问
  if (request.method === "POST") {
    // ?track=1 → 记录页面访问
    if (url.searchParams.get("track") === "1") {
      await logEvent(env, { type: "pageview" }, request);
      return json({ ok: true });
    }
    // 默认：上传文件
    return handleUpload(request, env);
  }

  // DELETE：删除文件（管理后台）
  if (request.method === "DELETE") {
    return handleDelete(request, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

/* ---------- 文件列表：从 R2 拉取 ---------- */
async function handleList(request, env) {
  const list = await env.UTAU_R2.list({ limit: 1000 });
  const files = list.objects
    .filter((o) => !o.key.startsWith("_")) // 下划线开头的是内部文件（如 logs），不显示
    .map((o) => ({
      name: o.key,
      size: o.size,
      uploaded: o.uploaded.toISOString(),
      download: `${new URL(request.url).origin}/upload?download=${encodeURIComponent(o.key)}`,
    }))
    .sort((a, b) => b.name.localeCompare(a.name));

  // ETag 缓存
  const etag = 'W/"' + files.length + '-' + (files[0]?.uploaded || '') + '"';
  const inm = request.headers.get("If-None-Match");
  if (inm === etag) {
    const h = new Headers(CORS_HEADERS);
    h.set("ETag", etag);
    h.set("Cache-Control", "public, max-age=30, stale-while-revalidate=60");
    return new Response(null, { status: 304, headers: h });
  }

  const h = new Headers(CORS_HEADERS);
  h.set("Cache-Control", "public, max-age=30, stale-while-revalidate=60");
  h.set("ETag", etag);
  return new Response(JSON.stringify({ ok: true, files }), { status: 200, headers: h });
}

/* ---------- 上传：直接写 R2 二进制 ---------- */
async function handleUpload(request, env) {
  let rawName = "";
  let fileData = null; // ArrayBuffer 或 Uint8Array

  const ct = request.headers.get("content-type") || "";

  if (ct.includes("multipart/form-data")) {
    // 浏览器二进制直传
    let form;
    try {
      form = await request.formData();
    } catch (e) {
      return json({ ok: false, msg: "multipart 解析失败" }, 400);
    }
    rawName = String(form.get("filename") || "");
    const part = form.get("file");
    if (!part || typeof part.arrayBuffer !== "function") {
      return json({ ok: false, msg: "缺少文件字段 file" }, 400);
    }
    fileData = await part.arrayBuffer();
  } else {
    // 兼容旧 JSON 格式 {filename, data: base64}
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ ok: false, msg: "请求体不是合法 JSON" }, 400);
    }
    rawName = typeof body.filename === "string" ? body.filename : "";
    const b64 = typeof body.data === "string" ? body.data : "";
    if (!b64) {
      return json({ ok: false, msg: "缺少文件数据" }, 400);
    }
    fileData = base64ToArrayBuffer(b64);
  }

  if (!fileData || fileData.byteLength === 0) {
    return json({ ok: false, msg: "文件为空" }, 400);
  }
  if (fileData.byteLength > MAX_RAW_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
  }

  // 校验扩展名
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }

  // 加时间戳防覆盖
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = sanitizeFilename(ts + "_" + rawName);
  if (!filename) {
    return json({ ok: false, msg: "文件名不合法" }, 400);
  }

  // 写入 R2
  try {
    await env.UTAU_R2.put(filename, fileData, {
      httpMetadata: {
        contentType: "application/octet-stream",
      },
    });
    return json({ ok: true, name: filename });
  } catch (e) {
    return json({ ok: false, msg: "R2 写入失败：" + e.message }, 502);
  }
}

/* ---------- 代理下载：从 R2 读，强制保存 ---------- */
async function handleDownload(filename, request, env) {
  const safeName = String(filename).split(/[\\/]/).pop();
  const ext = safeName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return new Response("不允许的文件类型", { status: 400 });
  }

  const obj = await env.UTAU_R2.get(safeName);
  if (!obj) {
    return new Response("文件不存在", { status: 404 });
  }

  // 记录下载日志
  await logEvent(env, { type: "download", file: safeName }, request);

  const headers = new Headers();
  headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", obj.size);
  headers.set("Access-Control-Allow-Origin", "*");
  return new Response(obj.body, { status: 200, headers });
}

/* ---------- 删除文件（需密码） ---------- */
async function handleDelete(request, env) {
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, msg: "请求体格式错误" }, 400);
  }

  const pwd = String(body.password || "");
  if (pwd !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }

  const filename = String(body.filename || "").split(/[\\/]/).pop();
  if (!filename) {
    return json({ ok: false, msg: "缺少文件名" }, 400);
  }

  // 检查文件是否存在
  const obj = await env.UTAU_R2.head(filename);
  if (!obj) {
    return json({ ok: false, msg: "文件不存在" }, 404);
  }

  await env.UTAU_R2.delete(filename);
  return json({ ok: true });
}

/* ---------- 日志（存 KV） ---------- */
async function logEvent(env, { type, file }, request) {
  if (!env.UTAU_LOGS) return; // 没绑定 KV 就静默跳过

  try {
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const ua = (request.headers.get("User-Agent") || "unknown").substring(0, 200);
    const entry = {
      time: new Date().toISOString(),
      type,
      file: file || "",
      ip,
      ua,
    };

    // 读现有日志
    let logs = [];
    try {
      const raw = await env.UTAU_LOGS.get(LOG_KEY);
      if (raw) logs = JSON.parse(raw);
    } catch (e) { /* 损坏就重置 */ }

    logs.unshift(entry);
    logs = logs.slice(0, LOG_MAX);

    await env.UTAU_LOGS.put(LOG_KEY, JSON.stringify(logs));
  } catch (e) {
    // 日志失败不影响主流程
  }
}

/* ---------- 查看日志（需密码） ---------- */
async function handleStats(password, env) {
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";
  if (password !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }
  if (!env.UTAU_LOGS) {
    return json({ ok: true, logs: [], msg: "KV 未绑定" });
  }
  try {
    const raw = await env.UTAU_LOGS.get(LOG_KEY);
    const logs = raw ? JSON.parse(raw) : [];
    return json({ ok: true, logs });
  } catch (e) {
    return json({ ok: true, logs: [], msg: "读取失败" });
  }
}

/* ---------- 工具函数 ---------- */
function sanitizeFilename(name) {
  let n = String(name).split(/[\\/]/).pop().trim();
  n = n.replace(/[:*?"<>|]/g, "_");
  if (!n || n.length > MAX_NAME_LEN) return "";
  return n;
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
