// GitHub Actions 代发：接收 repository_dispatch 的 client_payload，
// 通过 QQ SMTP 465 发送验证码邮件。
import nodemailer from "nodemailer";

const { SMTP_USER, SMTP_PASS, TO, CODE, SUBJECT, TEXT } = process.env;

if (!SMTP_USER || !SMTP_PASS || !TO || !CODE) {
  console.error("缺少 SMTP_USER/SMTP_PASS/TO/CODE 环境变量");
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  host: "smtp.qq.com",
  port: 465,
  secure: true,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

const text =
  TEXT ||
  `你的登录验证码是：${CODE}\n\n（十分钟内有效，请勿泄露。非本人操作请忽略。）`;

const html =
  `<div style="font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif;max-width:420px;margin:0 auto;padding:24px;">` +
  `<h2 style="font-size:18px;margin:0 0 16px;">邮箱登录验证码</h2>` +
  `<p style="font-size:14px;color:#333;">你的登录验证码是：</p>` +
  `<div style="font-size:32px;letter-spacing:6px;font-weight:bold;color:#4f7c8f;margin:12px 0;">${CODE}</div>` +
  `<p style="font-size:13px;color:#888;">（十分钟内有效，请勿泄露。非本人操作请忽略。）</p>` +
  `</div>`;

const info = await transporter.sendMail({
  from: `"UTAU登录" <${SMTP_USER}>`,
  to: TO,
  subject: SUBJECT || "邮箱登录验证码",
  text,
  html,
  headers: {
    "X-Mailer": "UTAU-OTP",
    "List-Unsubscribe": `<mailto:${SMTP_USER}>`,
  },
});

console.log("投递结果 accepted:", JSON.stringify(info.accepted));
console.log("投递结果 rejected:", JSON.stringify(info.rejected));
console.log("SMTP response:", info.response, "messageId:", info.messageId);
if (info.rejected && info.rejected.length) process.exit(2);
