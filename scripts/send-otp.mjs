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

const info = await transporter.sendMail({
  from: `UTAU登录 <${SMTP_USER}>`,
  to: TO,
  subject: SUBJECT || "邮箱登录验证码",
  text,
});

console.log("邮件已发出 ->", TO, "messageId:", info.messageId);
