/**
 * 开放平台 —— 资源读写 API（文件上传 / 删除 / 列表）
 *   GET    /api/openplatform/api/files            文件列表（公开只读，无需 Token）
 *   POST   /api/openplatform/api/files            Bearer + write 权限 → 上传文件
 *   DELETE /api/openplatform/api/files            Bearer + write 权限 → 删除文件
 *
 * 底层复用主站 GitHub 存储（uploads/ 目录），与 /upload 同一套仓库逻辑。
 * 环境变量：GH_TOKEN / GH_USER / GH_REPO（已在主站配置）
 */
import { json, corsPreflight, kvGet } from "./_lib.js";

const MAX_RAW_SIZE = 50 * 1024 * 1024;
const ALLOWED_EXT = ["ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"];
const MAX_NAME_LEN = 200;

export async function onRequest(context) {
  const { request, env } = context;
  const { GH_TOKEN, GH_USER, GH_REPO } = env;

  if (!GH_TOKEN || !GH_USER || !GH_REPO) {
    return json({ ok: false, msg: "后端环境变量未配置（GH_TOKEN / GH_USER / GH_REPO）" }, 500);
  }
  if (request.method === "OPTIONS") return corsPreflight();

  // 列表公开只读
  if (request.method === "GET") {
    return handleList(GH_TOKEN, GH_USER, GH_REPO);
  }

  // 写操作：校验 Bearer token + write scope
  const auth = String(request.headers.get("Authorization") || "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const raw = await kvGet(env, "token:" + token);
  if (!raw) return json({ ok: false, msg: "access_token 无效或已过期" }, 401);
  let access;
  try { access = JSON.parse(raw); } catch (e) {
    return json({ ok: false, msg: "令牌数据损坏" }, 500);
  }
  if (access.type !== "access") return json({ ok: false, msg: "令牌类型错误" }, 401);
  if (!(access.scopes || []).includes("write")) {
    return json({ ok: false, msg: "该令牌没有 write 权限" }, 403);
  }

  if (request.method === "POST") return handleUpload(request, GH_TOKEN, GH_USER, GH_REPO);
  if (request.method === "DELETE") return handleDelete(request, GH_TOKEN, GH_USER, GH_REPO);
  return json({ ok: false, msg: "方法错误" }, 405);
}

/* ---------- 文件列表 ---------- */
async function handleList(token, user, repo) {
  const apiRes = await fetch(`https://api.github.com/repos/${user}/${repo}/contents/uploads`, {
    headers: {
      Authorization: `token ${token}`,
      "User-Agent": "utau-openplatform",
      Accept: "application/vnd.github+json",
    },
  });
  if (apiRes.status === 404) return json({ ok: true, files: [] });
  if (!apiRes.ok) return json({ ok: false, msg: "读取文件列表失败（GitHub " + apiRes.status + "）" }, 502);

  const list = await apiRes.json();
  const files = list
    .filter((x) => x.type === "file")
    .map((x) => ({
      name: x.name,
      size: x.size || 0,
      raw: `https://raw.githubusercontent.com/${user}/${repo}/main/uploads/${encodeURIComponent(x.name)}`,
    }))
    .sort((a, b) => b.name.localeCompare(a.name));
  return json({ ok: true, files, count: files.length });
}

/* ---------- 上传 ---------- */
async function handleUpload(request, token, user, repo) {
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体不是合法的 JSON" }, 400);
  }

  const rawName = String(body.filename || "");
  const data = String(body.data || "");
  const ext = rawName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return json({ ok: false, msg: "不允许的文件类型：" + (ext || "(无扩展名)") }, 400);
  }
  const rawSize = Math.floor(data.length * 3 / 4);
  if (rawSize > MAX_RAW_SIZE) {
    return json({ ok: false, msg: "文件过大，上限 " + Math.floor(MAX_RAW_SIZE / 1024 / 1024) + " MB" }, 413);
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = sanitizeFilename(ts + "_" + rawName);
  if (!filename) return json({ ok: false, msg: "文件名不合法" }, 400);

  const putUrl = `https://api.github.com/repos/${user}/${repo}/contents/uploads/${filename}`;
  const resp = await fetch(putUrl, {
    method: "PUT",
    headers: {
      Authorization: `token ${token}`,
      "User-Agent": "utau-openplatform",
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ message: `[开放平台] 上传: ${filename}`, content: data }),
  });

  let result = {};
  try { result = await resp.json(); } catch (e) { /* 非 JSON */ }
  if (resp.ok) return json({ ok: true, filename });
  const ghMsg = result.message || result.errors || "GitHub 写入失败";
  return json({ ok: false, msg: String(ghMsg) }, 502);
}

/* ---------- 删除 ---------- */
async function handleDelete(request, token, user, repo) {
  let body;
  try { body = await request.json(); } catch (e) {
    return json({ ok: false, msg: "请求体格式错误" }, 400);
  }
  const filename = String(body.filename || "").split(/[\\/]/).pop();
  if (!filename) return json({ ok: false, msg: "缺少文件名" }, 400);

  const metaRes = await fetch(
    `https://api.github.com/repos/${user}/${repo}/contents/uploads/${encodeURIComponent(filename)}`,
    { headers: { Authorization: `token ${token}`, "User-Agent": "utau-openplatform" } }
  );
  if (!metaRes.ok) return json({ ok: false, msg: "文件不存在" }, 404);
  const meta = await metaRes.json();

  const delRes = await fetch(
    `https://api.github.com/repos/${user}/${repo}/contents/uploads/${encodeURIComponent(filename)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `token ${token}`,
        "User-Agent": "utau-openplatform",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: `[开放平台] 删除: ${filename}`, sha: meta.sha }),
    }
  );
  if (delRes.ok) return json({ ok: true });
  return json({ ok: false, msg: "删除失败（GitHub " + delRes.status + "）" }, 502);
}

function sanitizeFilename(name) {
  let n = String(name).split(/[\\/]/).pop().trim();
  n = n.replace(/[:*?"<>|]/g, "_");
  if (!n || n.length > MAX_NAME_LEN) return "";
  return n;
}
