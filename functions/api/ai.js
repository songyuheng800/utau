// AI 助手后端代理
// 模型与端点全部内置在仓库内，前端不填 key、不下载模型，开箱即用。
// 优先走 Cloudflare Workers AI 绑定（env.AI），绑定名固定为 AI。

const SYSTEM_PROMPT = "你是 UTAU 配布站开发者平台的 AI 助手。回答简洁、实用，用中文。";

// 降级链：主模型失败自动切下一个，均为 Cloudflare 托管的 Qwen 文本模型。
const MODEL_CHAIN = [
  "@cf/qwen/qwen3.8-27b",
  "@cf/qwen/qwen2.5-coder-32b-instruct",
  "@cf/qwen/qwq-32b",
];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export async function onRequestPost(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

  try {
    const body = await request.json();
    const messages = Array.isArray(body.messages) ? body.messages : [];

    if (!env.AI) {
      return Response.json(
        { error: "AI 服务未就绪：项目缺少 Workers AI 绑定（变量名 AI）。" },
        { headers: CORS, status: 503 }
      );
    }

    const payload = {
      messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages],
      max_tokens: 1024,
    };

    let lastErr = null;
    for (const model of MODEL_CHAIN) {
      try {
        const resp = await env.AI.run(model, payload);
        const reply = resp.response || (resp.choices && resp.choices[0]?.message?.content) || "";
        if (reply) {
          return Response.json({ reply, model }, { headers: CORS });
        }
      } catch (e) {
        lastErr = e;
      }
    }

    return Response.json(
      { error: "所有模型均不可用：" + (lastErr?.message || "未知错误") },
      { headers: CORS, status: 502 }
    );
  } catch (e) {
    return Response.json({ error: e.message || "AI 请求失败" }, { headers: CORS, status: 500 });
  }
}
