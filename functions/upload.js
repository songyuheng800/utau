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
// 小文件独立存储仓（新建，与旧仓 utau 共存；旧仓不删）
const FILES_REPO = "utau-files";
const DEPLOY_TAG = "files-repo=utau-files";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
  "X-Deploy-Tag": DEPLOY_TAG,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

export async function onRequest(context) {
  const { request, env } = context;
  const { GH_TOKEN, GH_USER } = env;
  // 主仓=独立新仓 FILES_REPO；兜底仓=旧仓 env.GH_REPO（令牌已授权），授权未就绪时回退写入，旧仓保留共存
  const FALLBACK_REPO = env.GH_REPO || "";

  if (!GH_TOKEN || !GH_USER) {
    return json({ ok: false, msg: "后端环境变量未配置（GH_TOKEN / GH_USER）" }, 500);
  }

  // 浏览器跨域预检（前端在 github.io，函数在 pages.dev，跨域必须处理）
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (request.method === "GET") {
    const url = new URL(request.url);
    // ?stats=密码 → 高管站查看访问日志（读旧仓 logs.json）
    if (url.searchParams.has("stats")) {
      return handleStats(request, url.searchParams.get("stats"), env);
    }
    // ?download=文件名 → 代理下载，强制保存；先找新仓，回退旧仓
    if (url.searchParams.has("download")) {
      return handleDownload(url.searchParams.get("download"), GH_TOKEN, GH_USER, request, env, [FILES_REPO, FALLBACK_REPO].filter(Boolean));
    }
    return handleList(url, GH_TOKEN, GH_USER, [FILES_REPO, FALLBACK_REPO].filter(Boolean), env);
  }

  if (request.method === "POST") {
    // ?track=1 → 记录页面访问（写旧仓 logs.json）
    const url = new URL(request.url);
    if (url.searchParams.get("track") === "1") {
      return handleTrack(request, env, "pageview");
    }
    return handleUpload(request, GH_TOKEN, GH_USER, [FILES_REPO, FALLBACK_REPO].filter(Boolean));
  }

  if (request.method === "DELETE") {
    return handleDelete(request, GH_TOKEN, GH_USER, env, [FILES_REPO, FALLBACK_REPO].filter(Boolean));
  }

  return json({ ok: false, msg: "方法错误" }, 405);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: CORS_HEADERS });
}

/* ---------- 文件列表：遍历主仓(新)与兜底仓(旧)合并，同名新仓优先 ---------- */
function listJson(files) {
  // 带 30s 短缓存头：CDN/浏览器复用，减少每次刷新都打 GitHub API
  const h = new Headers(CORS_HEADERS);
  h.set("Cache-Control", "public, max-age=30");
  return new Response(JSON.stringify({ ok: true, files }), { status: 200, headers: h });
}

async function handleList(requestUrl, token, user, repos, env) {
  const CACHE_KEY = "list:cache";
  // 30s 短缓存：GitHub 间歇 503 时直接回退缓存，列表稳定不空白
  if (env && env.TOKENS) {
    try {
      const hit = await env.TOKENS.get(CACHE_KEY);
      if (hit) {
        const parsed = JSON.parse(hit);
        if (parsed && Date.now() - parsed.at < 30000) return listJson(parsed.files);
      }
    } catch (e) { /* 缓存损坏忽略 */ }
  }

  // 两仓并行拉取，再按 repos 顺序合并（新仓优先，同名旧仓不覆盖）
  let fetched;
  try {
    fetched = await Promise.all(repos.map(async (repo) => {
      const apiRes = await fetch(`https://api.github.com/repos/${user}/${repo}/contents/uploads`, {
        headers: {
          Authorization: `token ${token}`,
          "User-Agent": "utau-sharing-proxy",
          Accept: "application/vnd.github+json",
        },
      });
      if (!apiRes.ok) return { repo, files: [] };
      const list = await apiRes.json();
      return { repo, files: Array.isArray(list) ? list.filter((f) => f.type === "file") : [] };
    }));
  } catch (e) {
    fetched = [];
  }

  const byName = new Map();
  for (const { repo, files } of fetched) {
    for (const x of files) {
      if (byName.has(x.name)) continue; // 同名先入为主：新仓优先，旧仓不覆盖
      byName.set(x.name, {
        name: x.name,
        raw: `https://raw.githubusercontent.com/${user}/${repo}/main/uploads/${encodeURIComponent(x.name)}`,
        mirror: `https://gcore.jsdelivr.net/gh/${user}/${repo}@main/uploads/${encodeURIComponent(x.name)}`,
        download: `${requestUrl.origin}/upload?download=${encodeURIComponent(x.name)}`,
        repo,
      });
    }
  }
  let files = [...byName.values()].sort((a, b) => b.name.localeCompare(a.name));

  // 拉到空（503/抖动）时回退缓存，避免列表变空
  if (files.length === 0 && env && env.TOKENS) {
    try {
      const hit = await env.TOKENS.get(CACHE_KEY);
      if (hit) {
        const parsed = JSON.parse(hit);
        if (parsed && Array.isArray(parsed.files)) files = parsed.files;
      }
    } catch (e) { /* ignore */ }
  } else if (files.length && env && env.TOKENS) {
    try { await env.TOKENS.put(CACHE_KEY, JSON.stringify({ at: Date.now(), files }), { expirationTtl: 30 }); } catch (e) {}
  }
  return listJson(files);
}

/* ---------- 上传 ----------
 * 优先接收 multipart/form-data（浏览器二进制直传：字段 filename + file Blob），
 * 服务端再转 base64 写 GitHub（Contents API 强制 base64，前端不转、不全量膨胀）。
 * 兼容旧的 JSON {filename,data:base64}。
 */
async function handleUpload(request, token, user, repos) {
  let rawName = "";
  let data = "";

  const ct = request.headers.get("content-type") || "";
  let targetRepo = "";
  if (ct.includes("multipart/form-data")) {
    let form;
    try { form = await request.formData(); }
    catch (e) { return json({ ok: false, msg: " multipart 解析失败" }, 400); }
    rawName = String(form.get("filename") || "");
    targetRepo = String(form.get("repo") || "");
    const part = form.get("file");
    if (!part || typeof part.arrayBuffer !== "function") {
      return json({ ok: false, msg: "缺少文件字段 file" }, 400);
    }
    const buf = new Uint8Array(await part.arrayBuffer());
    if (buf.length === 0) return json({ ok: false, msg: "文件为空" }, 400);
    if (buf.length > MAX_RAW_SIZE) {
      return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
    }
    data = uint8ToBase64(buf);
  } else {
    let body;
    try { body = await request.json(); }
    catch (e) { return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400); }
    rawName = typeof body.filename === "string" ? body.filename : "";
    targetRepo = typeof body.repo === "string" ? body.repo : "";
    data = typeof body.data === "string" ? body.data : "";
    const rawSize = Math.floor(data.length * 3 / 4);
    if (rawSize > MAX_RAW_SIZE) {
      return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
    }
  }

  // 用户指定仓库：仅允许写入已授权仓，指定仓排为首选，其余仓作回退
  let orderedRepos = repos;
  if (targetRepo && repos.indexOf(targetRepo) !== -1) {
    orderedRepos = [targetRepo, ...repos.filter((r) => r !== targetRepo)];
  }

  // 服务端再次校验扩展名（不信任前端）
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }

  // 服务端加时间戳，保证同名文件不会互相覆盖（每次都是新文件）
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = sanitizeFilename(ts + "_" + rawName);
  if (!filename) {
    return json({ ok: false, msg: "文件名不合法" }, 400);
  }

  // 依次尝试各仓（首选为用户指定仓）：首选授权失败/不可写时回退其余仓，全部失败才报错
  let lastErr = "GitHub 写入失败";
  for (const repo of orderedRepos) {
    const putUrl = `https://api.github.com/repos/${user}/${repo}/contents/uploads/${filename}`;
    let resp, result = {};
    try {
      resp = await fetch(putUrl, {
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
      try { result = await resp.json(); } catch (e) { /* 非 JSON */ }
    } catch (e) { lastErr = "网络错误：" + e.message; continue; }

    if (resp.ok) {
      return json({ ok: true, repo });
    }
    lastErr = String(result.message || result.errors || ("GitHub HTTP " + resp.status));
    // 403/404 授权类错误才回退下一仓；其余错误也继续尝试
  }
  return json({ ok: false, msg: lastErr }, 502);
}

// Uint8Array → base64（分块拼接，避免调用栈溢出）
function uint8ToBase64(bytes) {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/* ---------- 代理下载：强制浏览器保存文件，先找新仓再找旧仓 ---------- */
async function handleDownload(filename, token, user, request, env, repos) {
  // 安全校验：只允许文件名（不能含路径穿越）
  const safeName = String(filename).split(/[\\/]/).pop();
  const ext = safeName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return new Response("不允许的文件类型", { status: 400 });
  }

  // 记录下载日志（写旧仓 logs.json）
  logEvent(env, { type: "download", file: safeName, request });

  for (const repo of repos) {
    const rawUrl = `https://raw.githubusercontent.com/${user}/${repo}/main/uploads/${encodeURIComponent(safeName)}`;
    let resp;
    try {
      resp = await fetch(rawUrl, { headers: { "User-Agent": "utau-sharing-proxy" } });
    } catch (e) { continue; }
    if (!resp.ok) continue;

    // Content-Disposition: attachment 让浏览器下载而不是显示
    const headers = new Headers(resp.headers);
    headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`);
    headers.set("Content-Type", "application/octet-stream");
    headers.set("Access-Control-Allow-Origin", "*");
    return new Response(resp.body, { status: 200, headers });
  }
  return new Response("文件不存在", { status: 404 });
}

/* ---------- 日志记录（写入 GitHub 仓库 logs.json） ---------- */
async function logEvent(env, { type, file, request }) {
  try {
    const token = env.GH_TOKEN;
    const user = env.GH_USER;
    const repo = env.GH_REPO;
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const ua = (request.headers.get("User-Agent") || "unknown").substring(0, 200);
    const entry = { time: new Date().toISOString(), type, file: file || "", ip, ua };

    // 读取现有 logs.json
    let logs = [];
    let sha = null;
    const getRes = await fetch(`https://api.github.com/repos/${user}/${repo}/contents/logs.json`, {
      headers: { Authorization: `token ${token}`, "User-Agent": "utau-sharing-proxy" }
    });
    if (getRes.ok) {
      const meta = await getRes.json();
      sha = meta.sha;
      logs = JSON.parse(atob(meta.content));
    }
    logs.unshift(entry);
    logs = logs.slice(0, 200); // 只保留最近 200 条

    // 写回
    await fetch(`https://api.github.com/repos/${user}/${repo}/contents/logs.json`, {
      method: "PUT",
      headers: { Authorization: `token ${token}`, "User-Agent": "utau-sharing-proxy", "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "log: " + type,
        content: btoa(unescape(encodeURIComponent(JSON.stringify(logs)))),
        sha: sha || undefined
      })
    });
  } catch (e) { /* 静默失败 */ }
}

/* ---------- 记录页面访问 ---------- */
async function handleTrack(request, env, type) {
  await logEvent(env, { type, request });
  return json({ ok: true });
}

/* ---------- 高管站：查看日志 ---------- */
async function handleStats(request, password, env) {
  const SUPER_PWD = env.ADMIN_PASSWORD || "233677";
  if (password !== SUPER_PWD) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }
  // 从 GitHub 读取 logs.json
  const res = await fetch(`https://api.github.com/repos/${env.GH_USER}/${env.GH_REPO}/contents/logs.json`, {
    headers: { Authorization: `token ${env.GH_TOKEN}`, "User-Agent": "utau-sharing-proxy" }
  });
  if (!res.ok) {
    return json({ ok: true, logs: [] });
  }
  const meta = await res.json();
  const logs = JSON.parse(atob(meta.content));
  return json({ ok: true, logs });
}

/* ---------- Token 校验（与 functions/token.js 共用同一 KV 绑定 TOKENS） ---------- */
async function tokenIsValid(token, env) {
  if (!/^[A-Z0-9]{13}$/.test(token)) return false;
  if (!env.TOKENS) return false; // 未绑定 KV 时无法跨函数校验，视为无效
  try {
    const raw = await env.TOKENS.get(token);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (data.expire && data.expire < Date.now()) return false;
    return true;
  } catch (e) {
    return false;
  }
}

/* ---------- 删除文件（管理后台，需密码或 Token）：遍历新仓/旧仓定位后删除 ---------- */
async function handleDelete(request, token, user, env, repos) {
  // 管理密码：优先读环境变量 ADMIN_PASSWORD，默认 233677
  const ADMIN_PWD = env.ADMIN_PASSWORD || "233677";

  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体格式错误" }, 400);
  }

  // 校验密码或 Token（支持 13 位数字+大写字母 Token 直登后删除）
  const pwd = String(body.password || "");
  const tokenOk = await tokenIsValid(pwd, env);
  if (pwd !== ADMIN_PWD && !tokenOk) {
    return json({ ok: false, msg: "密码错误" }, 403);
  }

  const filename = String(body.filename || "").split(/[\\/]/).pop();
  if (!filename) {
    return json({ ok: false, msg: "缺少文件名" }, 400);
  }

  for (const repo of repos) {
    // 先查文件 SHA
    let metaRes;
    try {
      metaRes = await fetch(
        `https://api.github.com/repos/${user}/${repo}/contents/uploads/${encodeURIComponent(filename)}`,
        { headers: { Authorization: `token ${token}`, "User-Agent": "utau-sharing-proxy" } }
      );
    } catch (e) { continue; }
    if (!metaRes.ok) continue;
    let meta;
    try { meta = await metaRes.json(); } catch (e) { continue; }

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
    if (delRes.ok) return json({ ok: true, repo });
    return json({ ok: false, msg: "删除失败（GitHub " + delRes.status + "）" }, 502);
  }
  return json({ ok: false, msg: "文件不存在" }, 404);
}

/* 去掉路径部分、替换 GitHub 不允许的字符、限制长度 */
function sanitizeFilename(name) {
  let n = String(name).split(/[\\/]/).pop().trim();
  n = n.replace(/[:*?"<>|]/g, "_");
  if (!n || n.length > MAX_NAME_LEN) return "";
  return n;
}
