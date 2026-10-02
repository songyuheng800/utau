/**
 * Cloudflare Pages Function —— UTAU / OpenUTAU 工程配布站后端代理（GitHub 版）
 *
 * 职责：访客无需任何 GitHub 账号或 Token，由本函数用后端环境变量里的 PAT
 *       把文件写入你的 GitHub 仓库 uploads/ 目录，并返回文件列表。
 *
 * 部署位置：Cloudflare Pages 项目的 functions/ 目录（仓库根目录下建 functions/upload.js）
 * 函数路由：https://<你的项目名>.pages.dev/upload
 *
 * 环境变量（Pages 项目 → Settings → Environment variables → Production）：
 *   GH_TOKEN  你的 GitHub Personal Access Token（Contents 读写权限，建议 Fine-grained 并只授权给存储仓库）
 *   GH_USER   你的 GitHub 用户名
 *   GH_REPO   存储上传文件的仓库名（如 utau）
 */

const MAX_RAW_SIZE = 50 * 1024 * 1024; // 单文件上限（默认 50MB，可调）。
// 平台硬顶说明：Cloudflare 免费版请求体上限 100MB；base64 编码约膨胀 4/3；
// GitHub Contents API 单文件上限 100MB。三者取交集，原始文件理论上限约 75MB。
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const MAX_NAME_LEN = 200;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

export async function onRequest(context) {
  const { request, env } = context;
  const { GH_TOKEN, GH_USER, GH_REPO } = env;

  if (!GH_TOKEN || !GH_USER || !GH_REPO) {
    return json({ ok: false, msg: "后端环境变量未配置（GH_TOKEN / GH_USER / GH_REPO）" }, 500);
  }

  // 浏览器跨域预检（前端在 github.io，函数在 pages.dev，跨域必须处理）
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (request.method === "GET") {
    const url = new URL(request.url);
    // ?download=文件名 → 代理下载，强制浏览器保存
    if (url.searchParams.has("download")) {
      return handleDownload(url.searchParams.get("download"), GH_TOKEN, GH_USER, GH_REPO);
    }
    return handleList(url, GH_TOKEN, GH_USER, GH_REPO);
  }

  if (request.method === "POST") {
    return handleUpload(request, GH_TOKEN, GH_USER, GH_REPO);
  }

  if (request.method === "DELETE") {
    return handleDelete(request, GH_TOKEN, GH_USER, GH_REPO, env);
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

/* ---------- 文件列表 ---------- */
async function handleList(requestUrl, token, user, repo) {
  const apiRes = await fetch(`https://api.github.com/repos/${user}/${repo}/contents/uploads`, {
    headers: {
      Authorization: `token ${token}`,
      "User-Agent": "utau-sharing-proxy",
      Accept: "application/vnd.github+json",
    },
  });

  // uploads/ 目录还不存在，返回空列表而不是报错
  if (apiRes.status === 404) {
    return json({ ok: true, files: [] });
  }
  if (!apiRes.ok) {
    return json({ ok: false, msg: "读取文件列表失败（GitHub API " + apiRes.status + "）" }, 502);
  }

  const list = await apiRes.json();
  const files = list
    .filter((x) => x.type === "file")
    .map((x) => ({
      name: x.name,
      raw: `https://raw.githubusercontent.com/${user}/${repo}/main/uploads/${encodeURIComponent(x.name)}`,
      // 代理下载地址（同源，带 Content-Disposition: attachment，浏览器直接下载）
      download: `${requestUrl.origin}/upload?download=${encodeURIComponent(x.name)}`,
    }))
    .sort((a, b) => b.name.localeCompare(a.name)); // 文件名带时间戳前缀，新的在前

  return json({ ok: true, files });
}

/* ---------- 上传 ---------- */
async function handleUpload(request, token, user, repo) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const rawName = typeof body.filename === "string" ? body.filename : "";
  const data = typeof body.data === "string" ? body.data : "";

  // 服务端再次校验扩展名（不信任前端）
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }

  // base64 长度换算原始大小做上限检查（base64 约膨胀 4/3）
  const rawSize = Math.floor(data.length * 3 / 4);
  if (rawSize > MAX_RAW_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
  }

  // 服务端加时间戳，保证同名文件不会互相覆盖（每次都是新文件）
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = sanitizeFilename(ts + "_" + rawName);
  if (!filename) {
    return json({ ok: false, msg: "文件名不合法" }, 400);
  }

  const putUrl = `https://api.github.com/repos/${user}/${repo}/contents/uploads/${filename}`;
  const resp = await fetch(putUrl, {
    method: "PUT",
    headers: {
      Authorization: `token ${token}`,
      "User-Agent": "utau-sharing-proxy",
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: `上传工程/声库文件: ${filename}`,
      content: data,
    }),
  });

  let result = {};
  try { result = await resp.json(); } catch (e) { /* 非 JSON 响应 */ }

  if (resp.ok) {
    return json({ ok: true });
  }
  const ghMsg = result.message || result.errors || "GitHub 写入失败";
  return json({ ok: false, msg: String(ghMsg) }, 502);
}

/* ---------- 代理下载：强制浏览器保存文件 ---------- */
async function handleDownload(filename, token, user, repo) {
  // 安全校验：只允许文件名（不能含路径穿越）
  const safeName = String(filename).split(/[\\/]/).pop();
  const ext = safeName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return new Response("不允许的文件类型", { status: 400 });
  }

  // 从 GitHub raw 取文件内容
  const rawUrl = `https://raw.githubusercontent.com/${user}/${repo}/main/uploads/${encodeURIComponent(safeName)}`;
  const resp = await fetch(rawUrl, {
    headers: { "User-Agent": "utau-sharing-proxy" },
  });

  if (!resp.ok) {
    return new Response("文件不存在", { status: 404 });
  }

  // 关键：Content-Disposition: attachment 让浏览器下载而不是显示
  const headers = new Headers(resp.headers);
  headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`);
  headers.set("Content-Type", "application/octet-stream");
  // 允许跨域（前端在 github.io）
  headers.set("Access-Control-Allow-Origin", "*");

  return new Response(resp.body, { status: 200, headers });
}

/* ---------- 删除文件（管理后台，需密码） ---------- */
async function handleDelete(request, token, user, repo, env) {
  // 管理密码：优先读环境变量 ADMIN_PASSWORD，默认 283920
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233920";

  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体格式错误" }, 400);
  }

  // 校验密码
  if (body.password !== ADMIN_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }

  const filename = String(body.filename || "").split(/[\\/]/).pop();
  if (!filename) {
    return json({ ok: false, msg: "缺少文件名" }, 400);
  }

  // 先查文件 SHA
  const metaRes = await fetch(
    `https://api.github.com/repos/${user}/${repo}/contents/uploads/${encodeURIComponent(filename)}`,
    { headers: { Authorization: `token ${token}`, "User-Agent": "utau-sharing-proxy" } }
  );
  if (!metaRes.ok) {
    return json({ ok: false, msg: "文件不存在" }, 404);
  }
  const meta = await metaRes.json();

  // 删除
  const delRes = await fetch(
    `https://api.github.com/repos/${user}/${repo}/contents/uploads/${encodeURIComponent(filename)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `token ${token}`,
        "User-Agent": "utau-sharing-proxy",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: "删除文件: " + filename, sha: meta.sha }),
    }
  );

  if (delRes.ok) {
    return json({ ok: true });
  }
  return json({ ok: false, msg: "删除失败（GitHub " + delRes.status + "）" }, 502);
}

/* 去掉路径部分、替换 GitHub 不允许的字符、限制长度 */
function sanitizeFilename(name) {
  let n = String(name).split(/[\\/]/).pop().trim();
  n = n.replace(/[:*?"<>|]/g, "_");
  if (!n || n.length > MAX_NAME_LEN) return "";
  return n;
}
