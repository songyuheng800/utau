export async function onRequestPost(context) {
  const { request, env } = context;

  // CORS
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  if (request.method === "OPTIONS") return new Response(null, { headers: cors });

  try {
    const body = await request.json();
    const messages = body.messages || [];

    if (!env.AI) {
      return Response.json({ error: "AI binding 未配置，请在 Cloudflare Pages 设置 → Functions → AI binding 添加" }, { headers: cors });
    }

    const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
      messages: [
        { role: "system", content: "你是 UTAU 配布站开发者平台的 AI 助手。回答简洁、实用，用中文。" },
        ...messages,
      ],
      max_tokens: 1024,
    });

    return Response.json({ reply: response.response || "(空)" }, { headers: cors });
  } catch (e) {
    return Response.json({ error: e.message || "AI 请求失败" }, { headers: cors, status: 500 });
  }
}
