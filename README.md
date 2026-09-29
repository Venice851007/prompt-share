# Prompt Share — 提示词 + 图片分享小站 (Access 版)

把"提示词 + 出图"打包成一个短链接,发到 X / 小红书 / 微信都行。
技术栈: Cloudflare Workers + R2(图床) + KV(元数据) + Access(登录),
全免费额度。

## 角色与流程

- **管理员** (ADMIN_EMAILS 名单): 上传直接上架, 拿到分享链接;
  在 `/admin` 审核普通用户的待审内容。
- **普通用户** (Access 名单里、非管理员): 上传后进**待审队列**,
  管理员在 `/admin` 点"通过上架"或"驳回删除"。
- **访客**: 只能看公开的分享页 `/f/:id`, 不用登录。

不开放注册: 加人 = 管理员去 Access Policy 的邮箱名单里加一行。
50 人上限是 Access 免费版的硬上限, 加满 51 个时 Cloudflare 会提示升级,
程序里不用再限。

## 功能

- `GET /` 上传页 (需 Access 登录, 显示当前身份)
- `POST /api/share` 上传 (管理员直发, 普通用户进待审)
- `GET /f/:id` 分享页 (公开)
- `GET /img/:id` 图片代理 (公开, 不暴露 R2 直链)
- `GET /admin` 审核页 (仅管理员)
- `POST /api/admin/approve` / `reject` 审核操作 (仅管理员)

## 防刷

1. **防盗链** — 图片经 Worker 代理, Referer 非本站 403
   (空 Referer 放行: 直接打开、IM 内分享是正常行为)
2. **签名 URL** — 分享页里的图片地址带 HMAC 签名, 6 小时过期
3. **强缓存** — `Cache-Control: public, max-age=31536000, immutable`,
   重复访问不回源、不消耗 R2 读取次数
4. **限流** — 上传每 IP 每小时 20 次; 图片每 IP 每分钟 120 次
5. **JWT 二次校验** — Worker 侧校验 `Cf-Access-Jwt-Assertion` 的签名/aud/过期,
   绕过 Access 直接打 Worker 域名也进不来

## 部署步骤

### 1. 建 R2 bucket (图床)

Dashboard → R2 → Create bucket, 名字 `prompt-share-imgs`。
**不要**开公开访问 (保持私有)。

### 2. 建 KV namespace

Workers & Pages → KV → Create namespace, 如 `prompt-share`。

### 3. Workers 连 GitHub 自动部署

Workers & Pages → Create → Import a repository → 选 `prompt-share` 仓库 →
Deploy。记下分配的 `*.workers.dev` 域名, 建议再绑自己的域名
(Settings → Domains)。

### 4. 配绑定和变量

Workers → prompt-share → Settings → Bindings → Add binding:
- R2 bucket → Variable name `IMGS` → 选 `prompt-share-imgs`
- KV namespace → Variable name `SHARE` → 选第 2 步建的 namespace

Settings → Variables → Add variable:
- **Secret** `SIGN_SECRET` = 随机字符串 (电脑跑 `openssl rand -hex 32`)
- **Text** `ADMIN_EMAILS` = 你的邮箱 (多个逗号分隔)
- **Text** `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD` = 第 5 步建好 Access 应用后回填

改完点 Redeploy。

### 5. 配 Cloudflare Access (Zero Trust)

Zero Trust Dashboard → Access → Add an application → Self-hosted:
- Application domain: 填第 3 步的域名 (workers.dev 或你绑的自定义域名)
- **只保护这三条**: `/`, `/api/*`, `/admin/*`
  (Path-based例外: `/f/*` 和 `/img/*` 设为 Bypass, 公开访问)
- Policy → Allow → Emails: 填管理员 + 普通用户的邮箱 (≤50 人免费)
- 建好后把应用总览页的 **AUD** (一串 hex) 和你的 Team Domain
  (如 `yourteam.cloudflareaccess.com`) 回填到第 4 步的变量, 再 Redeploy。

加人/删人: 以后直接改这个 Policy 的邮箱名单, 即时生效, 不用动代码。

### 6. 验证

1. 浏览器无痕打开分享域名 → 应跳 Access 登录。
2. 管理员登录 → 上传一张图 → 直接拿到 `/f/` 链接。
3. 换个普通用户邮箱登录 (先加进 Policy) → 上传 → 提示"已提交审核"。
4. 管理员开 `/admin` → 看到待审 → 点通过 → 链接生效。

## 免费额度 (2026 年)

- R2: 每月 10GB 存储 + 100 万次写入 + 1000 万次读取, 出站流量免费
- KV: 存 1GB, 每天 10 万次读 / 1000 次写
- Workers: 每天 10 万次请求
- Access: 50 用户以内免费

## 本地开发 (可选)

```bash
npx wrangler dev
npx wrangler deploy
npx wrangler secret put SIGN_SECRET
```

## 文件结构

```
src/worker.js    全部逻辑 (单文件, 无依赖)
wrangler.toml    wrangler 部署配置 (走 Dashboard 可忽略)
README.md        本文件
```
