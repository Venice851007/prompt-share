# Prompt Share — 提示词 + 图片分享小站 (v2 公开画廊版)

把"提示词 + 出图"打包成一个短链接,发到 X / 小红书 / 微信都行。
首页是公开画廊: 访客不用登录就能逛精选和最新作品、搜标签;
登录后才能上传, 分享出去的灵感可以一键复制提示词。
技术栈: Cloudflare Workers + R2(图床) + KV(元数据) + Access(登录),
全免费额度。

## 角色与流程

- **管理员** (ADMIN_EMAILS 名单): 上传直接上架 (可设精选), 拿到分享链接;
  在 `/admin` 审核普通用户的待审内容、管理精选。
- **普通用户** (Access 名单里、非管理员): 上传后进**待审队列**,
  管理员在 `/admin` 点"通过上架 / 通过并精选 / 驳回删除";
  在 `/mine` 看自己的待审和已上架作品。
- **访客**: 不用登录, 首页画廊随便逛 (`/` 精选+最新+标签云、
  `/tag/:tag` 标签页、`/search` 搜索), 分享页 `/f/:id` 可看图、
  一键复制提示词。

不开放注册: 加人 = 管理员去 Access Policy 的邮箱名单里加一行。
50 人上限是 Access 免费版的硬上限, 加满 51 个时 Cloudflare 会提示升级,
程序里不用再限。

## 功能

- `GET /` 公开画廊首页 (精选 + 最新分页 + 标签云 + 搜索框)
- `GET /tag/:tag` 公开标签页
- `GET /search?q=` 公开搜索 (标题/标签/提示词, 近 150 条内过滤)
- `GET /f/:id` 分享详情页 (公开, 一键复制提示词)
- `GET /img/:id` 图片代理 (公开, 不暴露 R2 直链)
- `GET /upload` 上传页 (需 Access 登录, 显示当前身份; 管理员可设精选)
- `GET /mine` 我的作品 (需登录: 待审 + 已上架)
- `GET /admin` 审核 + 精选管理 (仅管理员)
- `POST /api/upload` 上传 (管理员直发, 普通用户进待审)
- `POST /api/review` 审核操作 approve/reject/unfeature (仅管理员)

**不做的**: 浏览/点赞统计、评论、关注 —— 50 人社区不需要,
KV 免费写额度 (每天 1000 次) 也撑不起全量计数。

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

Zero Trust Dashboard → Access → Applications:

**应用一 `prompt-share-public` (Bypass, 所有人)** —
两个域名 (workers.dev 和自定义域名) 各加:
`/`、`/tag/*`、`/search*`、`/f/*`、`/img/*`
(注意 `/` 是前缀匹配, 会覆盖全站; 登录区靠下面更具体的路径优先命中)

**应用二 `prompt-share` (Allow, 邮箱白名单)** —
两个域名各加: `/upload`、`/mine`、`/api/*`、`/admin/*`
- Policy → Allow → Emails: 填管理员 + 普通用户的邮箱 (≤50 人免费)
- 建好后把应用总览页的 **AUD** (一串 hex) 和你的 Team Domain
  (如 `yourteam.cloudflareaccess.com`) 回填到第 4 步的变量, 再 Redeploy。

加人/删人: 以后直接改这个 Policy 的邮箱名单, 即时生效, 不用动代码。

### 6. 验证

1. 浏览器无痕打开 https://prompt.minispacex.com/ → **不跳登录**,
   直接看到画廊首页 (精选/最新/标签云)。
2. 点"分享作品" → 跳 Access 登录。
3. 管理员登录 → `/upload` 上传一张图 (标题+标签, 勾选精选) →
   直接拿到 `/f/` 链接; 首页精选区出现这张。
4. 点开 `/f/` 链接 → 无痕也能看, "一键复制"按钮可用。
5. `/tag/人物`、`/search?q=人物` 有结果; `/mine` 能看到自己的作品。
6. 换个普通用户邮箱登录 (先加进 Policy) → 上传 → 提示"已提交审核",
   `/mine` 显示待审核; 管理员 `/admin` 点"通过并精选" → 上架。

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
