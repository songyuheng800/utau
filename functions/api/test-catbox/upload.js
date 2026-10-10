/**
 * Cloudflare Pages Function —— Catbox（猫盒）测试站后端
 *
 * 路由：/api/test-catbox/upload
 * 功能：
 *   POST   multipart 上传文件 → 转发到 catbox.moe（匿名永久存储）→ 记录到 KV
 *   GET    返回测试站已上传文件列表（从 KV 读取）
 *   DELETE 从 KV 列表移除记录（说明：匿名上传到 catbox 的文件本身无法通过 API 删除，
 *          只能从本站列表中移除；如需真正删除需 catbox 账号 userhash）
 *
 * 存储：KV 绑定 AUTH_KV（UTAU_AUTH 命名空间，与主站 UTAU_TOKENS 隔离），
 *       键 catbox_test:list = JSON 数组。
 *
 * 限制：Cloudflare 免费版请求体上限约 100MB，测试站实际上传上限设为 100MB；
 *       catbox 本身支持单文件 200MB。
 */

const MAX_SIZE = 100 * 1024 * 1024; // 100MB（受 Pages 函数请求体上限约束）
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const CATBOX_API = "https://catbox.moe/user/api.php";
const LIST_KEY = "catbox_test:list";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.AUTH_KV;
  if (!kv) {
    return json({ ok: false, msg: "KV 未绑定（AUTH_KV）" }, 500);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (request.method === "POST") {
    return handleUpload(request, kv);
  }
  if (request.method === "GET") {
    return handleList(kv);
  }
  if (request.method === "DELETE") {
    return handleDelete(request, kv);
  }
  return json({ ok: false, msg: "方法错误" }, 405);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

async function getList(kv) {
  const raw = await kv.get(LIST_KEY);
  try { return raw ? JSON.parse(raw) : []; } catch (e) { return []; }
}

/* ---------- 上传：转发到 catbox ---------- */
async function handleUpload(request, kv) {
  let form;
  try {
    form = await request.formData();
  } catch (e) {
    return json({ ok: false, msg: "请求必须是 multipart/form-data" }, 400);
  }

  const file = form.get("fileToUpload");
  if (!(file instanceof File) && !file) {
    return json({ ok: false, msg: "缺少文件字段 fileToUpload" }, 400);
  }
  const rawName = String(file.name || "");
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }
  if (file.size > MAX_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 100 MB（受 Cloudflare 免费版请求体限制）" }, 413);
  }

  // 转发到 catbox
  const fd = new FormData();
  fd.append("reqtype", "fileupload");
  fd.append("fileToUpload", new Blob([await file.arrayBuffer()], { type: file.type || "application/octet-stream" }), rawName);

  let resp;
  try {
    resp = await fetch(CATBOX_API, { method: "POST", body: fd });
  } catch (e) {
    return json({ ok: false, msg: "连接猫盒失败：" + e.message }, 502);
  }
  const text = await resp.text();
  if (!resp.ok || !/^https?:\/\/\S+$/.test(text.trim())) {
    return json({ ok: false, msg: "猫盒上传失败（HTTP " + resp.status + "）: " + text.slice(0, 200) }, 502);
  }
  const url = text.trim();

  // 记录到 KV 列表（新的在前）
  const ts = new Date().toISOString();
  const list = await getList(kv);
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  list.unshift({ id, name: rawName, url, time: ts });
  await kv.put(LIST_KEY, JSON.stringify(list));

  return json({ ok: true, url, name: rawName });
}

/* ---------- 列表 ---------- */
async function handleList(kv) {
  const list = await getList(kv);
  return json({ ok: true, files: list });
}

/* ---------- 删除（仅移除本站记录；catbox 匿名文件无法 API 删除） ---------- */
async function handleDelete(request, kv) {
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体格式错误" }, 400);
  }
  const id = String(body.id || "");
  if (!id) return json({ ok: false, msg: "缺少 id" }, 400);
  const list = await getList(kv);
  const next = list.filter((f) => f.id !== id);
  await kv.put(LIST_KEY, JSON.stringify(next));
  return json({ ok: true, removed: list.length !== next.length });
}
