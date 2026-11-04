/**
 * Cloudflare Pages Function —— UTAU 配布站后端（多 KV 分片存储版）
 *
 * 50 个 KV namespace 分片存储，免费额度拉满。
 * 文件按文件名哈希分片到 50 个 KV，主 KV 存索引（文件名→分片号+元数据）。
 *
 * 绑定名规则：
 *   KV_INDEX  主索引 KV（存文件列表索引）
 *   KV_00 ~ KV_49  50 个分片 KV（存文件本体）
 *   共 51 个 KV 绑定
 */

const SHARD_COUNT = 50;
const MAX_RAW_SIZE = 25 * 1024 * 1024; // KV 单值上限 25MB
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const MAX_NAME_LEN = 200;
const INDEX_KEY = "file_index";
const LOG_KEY = "access_logs";
const LOG_MAX = 500;

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

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (!env.KV_INDEX) {
    return json({ ok: false, msg: "KV 索引未绑定（KV_INDEX）" }, 500);
  }

  const url = new URL(request.url);

  if (request.method === "GET") {
    if (url.searchParams.has("stats")) {
      return handleStats(url.searchParams.get("stats"), env);
    }
    if (url.searchParams.has("download")) {
      return handleDownload(url.searchParams.get("download"), request, env);
    }
    return handleList(request, env);
  }

  if (request.method === "POST") {
    if (url.searchParams.get("track") === "1") {
      await logEvent(env, { type: "pageview" }, request);
      return json({ ok: true });
    }
    return handleUpload(request, env);
  }

  if (request.method === "DELETE") {
    return handleDelete(request, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

/* ---------- 哈希分片：文件名 → 分片号 ---------- */
function shardIndex(filename) {
  let h = 0;
  for (let i = 0; i < filename.length; i++) {
    h = (h * 31 + filename.charCodeAt(i)) >>> 0;
  }
  return h % SHARD_COUNT;
}

function getShardKV(env, shard) {
  const name = "KV_" + String(shard).padStart(2, "0");
  return env[name];
}

/* ---------- 读索引：从主 KV 拿文件列表 ---------- */
async function readIndex(env) {
  try {
    const raw = await env.KV_INDEX.get(INDEX_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

/* ---------- 写索引 ---------- */
async function writeIndex(env, files) {
  await env.KV_INDEX.put(INDEX_KEY, JSON.stringify(files));
}

/* ---------- 文件列表 ---------- */
async function handleList(request, env) {
  const files = await readIndex(env);
  const enriched = files.map((f) => ({
    name: f.name,
    size: f.size,
    uploaded: f.uploaded,
    shard: f.shard,
    download: `${new URL(request.url).origin}/upload?download=${encodeURIComponent(f.name)}`,
  })).sort((a, b) => b.name.localeCompare(a.name));

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
  return new Response(JSON.stringify({ ok: true, files: enriched }), { status: 200, headers: h });
}

/* ---------- 上传 ---------- */
async function handleUpload(request, env) {
  let rawName = "";
  let fileData = null;

  const ct = request.headers.get("content-type") || "";

  if (ct.includes("multipart/form-data")) {
    let form;
    try { form = await request.formData(); }
    catch (e) { return json({ ok: false, msg: "multipart 解析失败" }, 400); }
    rawName = String(form.get("filename") || "");
    const part = form.get("file");
    if (!part || typeof part.arrayBuffer !== "function") {
      return json({ ok: false, msg: "缺少文件字段 file" }, 400);
    }
    fileData = await part.arrayBuffer();
  } else {
    let body;
    try { body = await request.json(); }
    catch (e) { return json({ ok: false, msg: "请求体不是合法 JSON" }, 400); }
    rawName = typeof body.filename === "string" ? body.filename : "";
    const b64 = typeof body.data === "string" ? body.data : "";
    if (!b64) return json({ ok: false, msg: "缺少文件数据" }, 400);
    fileData = base64ToArrayBuffer(b64);
  }

  if (!fileData || fileData.byteLength === 0) {
    return json({ ok: false, msg: "文件为空" }, 400);
  }
  if (fileData.byteLength > MAX_RAW_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
  }

  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = sanitizeFilename(ts + "_" + rawName);
  if (!filename) return json({ ok: false, msg: "文件名不合法" }, 400);

  // 哈希分片
  const shard = shardIndex(filename);
  const shardKV = getShardKV(env, shard);
  if (!shardKV) {
    return json({ ok: false, msg: "分片 KV 未绑定（KV_" + shard + "）" }, 500);
  }

  // 写入分片 KV
  try {
    await shardKV.put(filename, fileData, {
      expirationTtl: 0, // 永久
    });
  } catch (e) {
    return json({ ok: false, msg: "KV 写入失败：" + e.message }, 502);
  }

  // 更新索引
  const files = await readIndex(env);
  files.push({
    name: filename,
    size: fileData.byteLength,
    uploaded: new Date().toISOString(),
    shard: shard,
  });
  await writeIndex(env, files);

  return json({ ok: true, name: filename, shard: shard });
}

/* ---------- 下载 ---------- */
async function handleDownload(filename, request, env) {
  const safeName = String(filename).split(/[\\/]/).pop();
  const ext = safeName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return new Response("不允许的文件类型", { status: 400 });
  }

  // 从索引查分片号
  const files = await readIndex(env);
  const meta = files.find((f) => f.name === safeName);
  if (!meta) {
    return new Response("文件不存在", { status: 404 });
  }

  const shardKV = getShardKV(env, meta.shard);
  if (!shardKV) {
    return new Response("分片存储异常", { status: 500 });
  }

  const data = await shardKV.get(safeName, "arrayBuffer");
  if (!data) {
    return new Response("文件不存在", { status: 404 });
  }

  await logEvent(env, { type: "download", file: safeName }, request);

  const headers = new Headers();
  headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", String(data.byteLength));
  headers.set("Access-Control-Allow-Origin", "*");
  return new Response(data, { status: 200, headers });
}

/* ---------- 删除 ---------- */
async function handleDelete(request, env) {
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ ok: false, msg: "请求体格式错误" }, 400); }

  const pwd = String(body.password || "");
  if (pwd !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }

  const filename = String(body.filename || "").split(/[\\/]/).pop();
  if (!filename) return json({ ok: false, msg: "缺少文件名" }, 400);

  // 查索引
  const files = await readIndex(env);
  const idx = files.findIndex((f) => f.name === filename);
  if (idx === -1) return json({ ok: false, msg: "文件不存在" }, 404);

  const meta = files[idx];
  const shardKV = getShardKV(env, meta.shard);
  if (shardKV) {
    await shardKV.delete(filename);
  }

  // 从索引移除
  files.splice(idx, 1);
  await writeIndex(env, files);

  return json({ ok: true });
}

/* ---------- 日志 ---------- */
async function logEvent(env, { type, file }, request) {
  if (!env.KV_INDEX) return;
  try {
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const ua = (request.headers.get("User-Agent") || "unknown").substring(0, 200);
    const entry = { time: new Date().toISOString(), type, file: file || "", ip, ua };

    let logs = [];
    try {
      const raw = await env.KV_INDEX.get(LOG_KEY);
      if (raw) logs = JSON.parse(raw);
    } catch (e) {}

    logs.unshift(entry);
    logs = logs.slice(0, LOG_MAX);
    await env.KV_INDEX.put(LOG_KEY, JSON.stringify(logs));
  } catch (e) {}
}

async function handleStats(password, env) {
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";
  if (password !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }
  try {
    const raw = await env.KV_INDEX.get(LOG_KEY);
    const logs = raw ? JSON.parse(raw) : [];
    return json({ ok: true, logs });
  } catch (e) {
    return json({ ok: true, logs: [] });
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
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
