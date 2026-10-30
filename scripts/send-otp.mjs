// GitHub Actions 代发：多 SMTP 节点池，主备故障转移。
// 一号节点发不过去立刻转二号，依次轮转，第一个成功即返回。
// 节点来源：Secret SMTP_NODES（JSON 数组，多节点）；兜底单账号 SMTP_USER/SMTP_PASS。
import nodemailer from "nodemailer";

const { TO, CODE, SUBJECT, TEXT, MAGIC_URL, SMTP_NODES, SMTP_USER, SMTP_PASS } = process.env;

if (!TO) {
  console.error("缺少 TO 环境变量");
  process.exit(1);
}
// 一键授权模式：有 MAGIC_URL 就渲染授权按钮，不再展示数字验证码
const magicMode = !!MAGIC_URL;

// 组装节点池
let nodes = [];
if (SMTP_NODES) {
  try {
    const parsed = JSON.parse(SMTP_NODES);
    nodes = Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    console.error("SMTP_NODES 解析失败，回退单账号：", e.message);
  }
}
if (!nodes.length && SMTP_USER && SMTP_PASS) {
  nodes = [{ host: "smtp.qq.com", port: 465, secure: true, user: SMTP_USER, pass: SMTP_PASS }];
}
if (!nodes.length) {
  console.error("未配置任何 SMTP 节点（SMTP_NODES 或 SMTP_USER/SMTP_PASS）");
  process.exit(1);
}

const text = magicMode
  ? `UTAU 登录授权\n\n点击下面的链接一键登录（10分钟内有效）：\n${MAGIC_URL}\n\n或输入验证码：${CODE}\n\n（请勿泄露。非本人操作请忽略。）`
  : `你的登录验证码是：${CODE}\n\n（十分钟内有效，请勿泄露。非本人操作请忽略。）`;

// HTML 邮件：保留数字验证码，有 MAGIC_URL 时额外渲染一键授权按钮
let html;
if (magicMode) {
  html =
    `<div style="font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif;max-width:440px;margin:0 auto;padding:28px 24px;">` +
    `<h2 style="font-size:18px;margin:0 0 6px;">UTAU 登录授权</h2>` +
    `<p style="font-size:13px;color:#888;margin:0 0 20px;">点击下方按钮一键登录，或手动输入验证码</p>` +
    `<div style="text-align:center;margin:22px 0;">` +
    `<a href="${MAGIC_URL}" style="display:inline-block;background:#f5c542;color:#1a1a1a;text-decoration:none;font-size:16px;font-weight:700;padding:14px 40px;border-radius:10px;">一键授权登录</a>` +
    `</div>` +
    `<p style="font-size:11px;color:#999;word-break:break-all;margin:0 0 16px;">如按钮无法点击，复制此链接到浏览器：<br>${MAGIC_URL}</p>` +
    `<div style="border-top:1px solid #eee;padding-top:18px;margin-top:6px;">` +
    `<p style="font-size:13px;color:#666;margin:0 0 6px;">或输入验证码：</p>` +
    `<div style="font-size:30px;letter-spacing:8px;font-weight:bold;color:#4f7c8f;">${CODE}</div>` +
    `</div>` +
    `<p style="font-size:12px;color:#aaa;margin:18px 0 0;">（十分钟内有效，请勿泄露。非本人操作请忽略。）</p>` +
    `</div>`;
} else {
  html =
    `<div style="font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif;max-width:420px;margin:0 auto;padding:24px;">` +
    `<h2 style="font-size:18px;margin:0 0 16px;">邮箱登录验证码</h2>` +
    `<p style="font-size:14px;color:#333;">你的登录验证码是：</p>` +
    `<div style="font-size:32px;letter-spacing:6px;font-weight:bold;color:#4f7c8f;margin:12px 0;">${CODE}</div>` +
    `<p style="font-size:13px;color:#888;">（十分钟内有效，请勿泄露。非本人操作请忽略。）</p>` +
    `</div>`;
}

const errors = [];

// 逐个节点尝试，失败立即切下一个；短超时，快速轮转
for (let i = 0; i < nodes.length; i++) {
  const n = nodes[i];
  const host = n.host || "smtp.qq.com";
  const port = Number(n.port || 465);
  const secure = n.secure !== false;
  let transporter;
  try {
    transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      connectionTimeout: 5000,
      greetingTimeout: 5000,
      socketTimeout: 8000,
      auth: { user: n.user, pass: n.pass },
    });

    const fromName = n.fromName || "UTAU登录";
    const info = await transporter.sendMail({
      from: `${fromName} <${n.user}>`,
      to: TO,
      subject: SUBJECT || "邮箱登录验证码",
      text,
      html,
      headers: { "X-Mailer": "UTAU-OTP" },
    });

    const ok =
      (!info.rejected || info.rejected.length === 0) &&
      info.accepted && info.accepted.includes(TO);

    if (ok) {
      console.log(`节点${i + 1}(${n.user}@${host}) 成功`);
      console.log("accepted:", JSON.stringify(info.accepted));
      console.log("SMTP response:", info.response, "messageId:", info.messageId);
      await transporter.close();
      process.exit(0);
    }
    errors.push(`节点${i + 1}(${n.user}): 被拒绝 ${JSON.stringify(info.rejected)}`);
    console.log(`节点${i + 1} 未成功，切换下一节点`);
  } catch (e) {
    errors.push(`节点${i + 1}(${n.user}@${host}): ${e.code || ""} ${e.message.slice(0, 120)}`);
    console.log(`节点${i + 1}(${n.user}@${host}) 失败，切换下一节点：`, e.message.slice(0, 120));
  } finally {
    if (transporter) {
      try { await transporter.close(); } catch {}
    }
  }
}

console.error("全部 SMTP 节点失败：");
errors.forEach((x) => console.error(" -", x));
process.exit(2);
