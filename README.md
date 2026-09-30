# Prompt Share

<p align="center">
  <img src="assets/logo.svg" width="96" alt="Prompt Share logo">
</p>

一个单文件 Cloudflare Worker 实现的「提示词 + 图片」分享小站。

**样品站**: https://prompt.minispacex.com/

把"提示词 + 出图"打包成一个短链接，发到 X / 小红书 / 微信都行。
访客不用登录就能逛画廊、看图、一键复制提示词；站长登录后上传，支持审核制多人协作。

## 功能

**访客（免登录）**
- 首页公开画廊：精选大图轮播（每次打开随机排序）+ 瀑布流最新作品
- 标签云、标签页、全文搜索（标题 / 标签 / 提示词）
- 作品详情页：一键复制提示词，多图左右滑动查看（支持手机手势）
- 最新区卡片：多图作品可直接在卡片上左右翻看

**站长 / 管理员（Access 登录）**
- 上传作品：标题、中英文提示词、标签，一次最多 8 张图
- 管理员上传直接上架（可设精选），普通用户上传进待审队列
- `/admin`：审核上架、精选管理、已发布作品随时设为精选 / 取消精选
- `/mine`：管理自己的待审和已上架作品，支持编辑（换标题、改图、增删图片）

**不做的**：浏览 / 点赞统计、评论、关注 —— 小圈子不需要，KV 免费写额度也撑不起。

## 技术栈

- **Cloudflare Workers**：全部逻辑在一个 `src/worker.js`（单文件，无依赖）
- **R2**：私有图床（图片经 Worker 代理，不暴露直链）
- **KV**：元数据 + 索引（最新 / 用户 / 标签 / 精选）
- **Cloudflare Access (Zero Trust)**：登录鉴权，50 用户内免费
- **Workers Builds**：连 GitHub 仓库，push 到 main 自动部署

## 安全设计

1. **防盗链**：图片经 Worker 代理，Referer 非本站 403（空 Referer 放行：直接打开、IM 内分享是正常行为）
2. **签名 URL**：图片地址带 HMAC 签名，6 小时过期
3. **强缓存**：`Cache-Control: public, max-age=31536000, immutable`
4. **限流**：上传每 IP 每小时 20 次；图片每 IP 每分钟 120 次
5. **JWT 二次校验**：Worker 侧校验 `Cf-Access-Jwt-Assertion` 的签名 / aud / 过期，绕过 Access 直接打 Worker 域名也进不来
6. **密钥不进仓库**：`SIGN_SECRET` 只放在 Dashboard Secrets 里

## 自己部署一套

### 1. 建 R2 bucket

Dashboard → R2 → Create bucket，如 `prompt-share-imgs`。**不要**开公开访问（保持私有）。

### 2. 建 KV namespace

Workers & Pages → KV → Create namespace，如 `prompt-share`。

### 3. Workers 连 GitHub 自动部署

Workers & Pages → Create → Import a repository → 选本仓库 → Deploy。
记下 `*.workers.dev` 域名，建议再绑自己的域名（Settings → Domains）。

### 4. 配绑定和变量

Workers → Settings → Bindings：
- R2 bucket → Variable name `IMGS` → 选第 1 步的 bucket
- KV namespace → Variable name `SHARE` → 选第 2 步的 namespace

Settings → Variables：
- **Secret** `SIGN_SECRET` = 随机字符串（`openssl rand -hex 32`）
- **Text** `ADMIN_EMAILS` = 你的邮箱（多个逗号分隔）
- **Text** `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD` = 第 5 步建好 Access 应用后回填

### 5. 配 Cloudflare Access (Zero Trust)

Zero Trust Dashboard → Access → Applications，建两个应用：

**应用一 `prompt-share-public`（Bypass，所有人）**，两个域名各加：
`/`、`/tag/*`、`/search*`、`/f/*`、`/img/*`

**应用二 `prompt-share`（Allow，邮箱白名单）**，两个域名各加：
`/upload`、`/mine`、`/api/*`、`/admin/*`
- Policy → Allow → Emails：填管理员 + 普通用户邮箱（≤50 人免费）
- 建好后把应用总览页的 **AUD** 和 Team Domain 回填到第 4 步，再 Redeploy

加人/删人：以后直接改 Policy 的邮箱名单，即时生效，不用动代码。

### 6. 验证

1. 无痕打开首页 → **不跳登录**，直接看到画廊
2. 点"分享作品" → 跳 Access 登录
3. 管理员上传一张图（勾选精选）→ 拿到 `/f/` 链接，首页精选区出现
4. `/mine`、`/admin` 功能正常

## 免费额度（2026 年）

| 资源 | 免费额度 |
|---|---|
| R2 | 10GB 存储 / 月，100 万次写入，1000 万次读取，出站流量免费 |
| KV | 1GB 存储，每天 10 万次读 / 1000 次写 |
| Workers | 每天 10 万次请求 |
| Access | 50 用户以内免费 |

## 本地开发

```bash
npx wrangler dev
npx wrangler deploy
npx wrangler secret put SIGN_SECRET
```

## 文件结构

```
src/worker.js    全部逻辑（单文件，无依赖）
wrangler.toml    部署配置
README.md        本文件
CHANGELOG.md     更新日志
```

## 更新日志

见 [CHANGELOG.md](CHANGELOG.md)。

## License

[MIT](LICENSE) — 随便用，留个出处就行。
