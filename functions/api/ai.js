// AI 助手后端代理
// 提供商可配置：优先调用环境变量指定的自定义 OpenAI 兼容提供商（DeepSeek 及其他小众兼容服务），
// 未配置或全部失败时，回退 Cloudflare Workers AI 托管模型。
// 密钥只存在服务端环境变量，绝不下发前端；前端仍只传 messages，收 reply/model。

const SYSTEM_PROMPT = "你是 UTAU 配布站开发者平台的 AI 助手。回答简洁、实用，用中文。";

// 回退链：Cloudflare 托管的 Qwen 文本模型。
const CF_MODEL_CHAIN = [
  "@cf/qwen/qwen3.8-27b",
  "@cf/qwen/qwen2.5-coder-32b-instruct",
  "@cf/qwen/qwq-32b",
];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

// 解析自定义提供商配置。环境变量：
//   AI_CUSTOM_BASE_URL  OpenAI 兼容基础地址，如 https://api.deepseek.com/v1
//   AI_CUSTOM_API_KEY   该提供商的 Bearer 密钥
//   AI_CUSTOM_MODELS    逗号分隔的模型降级链，如 deepseek-chat,deepseek-reasoner
//   AI_CUSTOM_MODEL     单个模型名（未配 AI_CUSTOM_MODELS 时使用）
function customProviders(env) {
  const base = (env.AI_CUSTOM_BASE_URL || "").trim().replace(/\/+$/, "");
  const key = (env.AI_CUSTOM_API_KEY || "").trim();
  if (!base || !key) return [];

  let parsed;
  try { parsed = new URL(base); } catch { return []; }
  if (!/^https?:$/.test(parsed.protocol)) return [];
  const origin = parsed.origin;

  const models = (env.AI_CUSTOM_MODELS || env.AI_CUSTOM_MODEL || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!models.length) return [];

  return models.map((model) => ({ base, origin, key, model }));
}

// 调用 OpenAI 兼容的 /chat/completions 接口。
async function callCustom(provider, messages) {
  const resp = await fetch(provider.base + "/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + provider.key,
    },
    body: JSON.stringify({ model: provider.model, messages, max_tokens: 1024 }),
    signal: AbortSignal.timeout(20000),
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error("HTTP " + resp.status + (detail ? " " + detail.slice(0, 120) : ""));
  }
  const data = await resp.json();
  return data.choices?.[0]?.message?.content || "";
}

// 调用 Cloudflare Workers AI 托管模型。
async function callCF(env, model, messages) {
  const resp = await env.AI.run(model, { messages, max_tokens: 1024 });
  return resp.response || (resp.choices && resp.choices[0]?.message?.content) || "";
}

export function onRequestOptions() {
  return new Response(null, { headers: CORS });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const messages = Array.isArray(body.messages) ? body.messages : [];
    const payload = [{ role: "system", content: SYSTEM_PROMPT }, ...messages];

    let lastErr = null;

    // 1. 自定义 OpenAI 兼容提供商（DeepSeek / 小众服务），按模型链依次尝试。
    for (const provider of customProviders(env)) {
      try {
        const reply = await callCustom(provider, payload);
        if (reply) {
          return Response.json(
            { reply, model: provider.model, provider: "custom" },
            { headers: CORS }
          );
        }
      } catch (e) {
        lastErr = e;
      }
    }

    // 2. 回退 Workers AI 托管模型链。
    if (env.AI) {
      for (const model of CF_MODEL_CHAIN) {
        try {
          const reply = await callCF(env, model, payload);
          if (reply) {
            return Response.json(
              { reply, model, provider: "cf" },
              { headers: CORS }
            );
          }
        } catch (e) {
          lastErr = e;
        }
      }
      return Response.json(
        { error: "所有模型均不可用：" + (lastErr?.message || "未知错误") },
        { headers: CORS, status: 502 }
      );
    }

    return Response.json(
      { error: "AI 服务未就绪：未配置自定义提供商，且缺少 Workers AI 绑定（变量名 AI）。" },
      { headers: CORS, status: 503 }
    );
  } catch (e) {
    return Response.json({ error: e.message || "AI 请求失败" }, { headers: CORS, status: 500 });
  }
}
