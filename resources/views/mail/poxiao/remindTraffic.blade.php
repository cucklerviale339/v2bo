<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{$name}} - 流量提醒</title>
  <style>
    body { margin:0; padding:0; background:#eef3f8; font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif; color:#172033; }
    table { border-collapse:collapse; }
    a { color:#1f5fd6; text-decoration:none; }
    .page { width:100%; background:linear-gradient(180deg,#eef7ff 0%,#f6f8fb 46%,#eef3f8 100%); padding:32px 12px; }
    .shell { width:100%; max-width:680px; margin:0 auto; }
    .brand { padding:0 0 18px; text-align:center; }
    .logo { max-width:168px; max-height:60px; border:0; vertical-align:middle; }
    .card { background:#ffffff; border:1px solid #dfeaf5; border-radius:20px; overflow:hidden; box-shadow:0 18px 45px rgba(27,54,93,.10); }
    .topline { height:5px; background:linear-gradient(90deg,#1856d8 0%,#2eb7ff 54%,#6ed6c8 100%); }
    .hero { padding:34px 38px 24px; border-bottom:1px solid #edf2f7; }
    .eyebrow { display:inline-block; color:#1856d8; background:#edf6ff; border:1px solid #d8e9ff; border-radius:999px; padding:7px 12px; font-size:12px; line-height:1; font-weight:700; }
    .title { margin:16px 0 0; color:#101828; font-size:28px; line-height:1.32; font-weight:800; }
    .desc { margin:12px 0 0; color:#5c6b80; font-size:15px; line-height:1.8; }
    .body { padding:30px 38px 36px; }
    .content { color:#344154; font-size:15px; line-height:1.9; }
    .progress { margin-top:18px; height:10px; border-radius:999px; background:#e8edf5; overflow:hidden; }
    .progress span { display:block; width:80%; height:10px; border-radius:999px; background:linear-gradient(90deg,#1f5fd6,#2eb7ff); }
    .info-box { margin-top:18px; padding:15px 16px; border-radius:14px; background:#f8fbff; border:1px solid #dfeaf5; color:#5c6b80; font-size:13px; line-height:1.8; }
    .button-wrap { margin-top:28px; text-align:center; }
    .button { display:inline-block; padding:14px 32px; border-radius:12px; background:#1f5fd6; color:#ffffff !important; font-size:14px; line-height:1; font-weight:800; }
    .footer { padding:18px 14px 0; text-align:center; color:#8a96a8; font-size:12px; line-height:1.8; }
    .footer strong { color:#5c6b80; }
    @media only screen and (max-width:640px) { .page{padding:18px 8px !important;} .hero,.body{padding-left:22px !important; padding-right:22px !important;} .title{font-size:24px !important;} .button{display:block !important;} }
  </style>
</head>
<body>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" class="page">
    <tr><td align="center">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" class="shell">
        <tr><td class="brand"><img class="logo" src="{{$logo}}" alt="{{$name}}"></td></tr>
        <tr><td class="card">
          <div class="topline"></div>
          <div class="hero">
            <span class="eyebrow">流量提醒</span>
            <h1 class="title">您的套餐流量即将用尽</h1>
            <p class="desc">系统检测到当前套餐流量使用较高，请及时关注剩余流量，避免影响使用。</p>
          </div>
          <div class="body">
            <div class="content">您的套餐流量已使用超过 80%，建议提前续费或升级套餐。</div>
            <div class="progress"><span></span></div>
            <div class="info-box">购买新套餐不会重置已使用流量，只会增加套餐时长和可用额度。</div>
            <div class="button-wrap"><a class="button" href="{{$url}}" target="_blank">查看套餐</a></div>
          </div>
        </td></tr>
        <tr><td class="footer"><strong>{{$name}}</strong><br>安全、稳定、清晰的网络服务体验<br>官网地址：{{$url}}</td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
