# Prompt Share

<p align="center">
  <img src="assets/logo.svg" width="96" alt="Prompt Share logo">
</p>

<p align="center">
  <a href="README.zh-CN.md">中文</a> | <strong>English</strong>
</p>

A single-file Cloudflare Worker that turns "prompt + generated images" into a shareable short link.

**Live demo**: https://prompt.minispacex.com/

Share your prompt and generations to X / Xiaohongshu / WeChat with one link.
Visitors browse the public gallery and copy prompts with one click — no login required.
Owners log in to upload, with support for moderated multi-user collaboration.

## Features

**Visitors (no login)**
- Public gallery homepage: featured hero carousel (shuffled on every load) + masonry feed of latest works
- Tag cloud, tag pages, full-text search (title / tags / prompt)
- Work detail page: one-click prompt copy, swipe through multiple images (touch gestures on mobile)
- Multi-image cards in the feed can be flipped through right on the card

**Owners / Admins (Access login)**
- Upload works: title, bilingual prompts, tags, up to 8 images per work
- Admin uploads go live instantly (can mark as featured); regular users' uploads enter a review queue
- `/admin`: review queue, featured management, toggle featured status on any published work
- `/mine`: manage your pending and published works, edit them (retitle, swap images, add/remove images)

**Deliberately not built**: view/like counters, comments, follows — a small circle doesn't need them, and KV's free write quota couldn't sustain them anyway.

## Tech Stack

- **Cloudflare Workers**: all logic in a single `src/worker.js` (zero dependencies)
- **R2**: private image storage (images proxied through the Worker, no direct URLs exposed)
- **KV**: metadata + indexes (latest / by-user / by-tag / featured)
- **Cloudflare Access (Zero Trust)**: authentication, free up to 50 users
- **Workers Builds**: connect the GitHub repo, push to `main` to deploy

## Security

1. **Hotlink protection**: images are proxied; non-local Referer gets 403 (empty Referer allowed: direct opens and IM shares are legitimate)
2. **Signed URLs**: image URLs carry an HMAC signature, expiring in 6 hours
3. **Aggressive caching**: `Cache-Control: public, max-age=31536000, immutable`
4. **Rate limiting**: 20 uploads / IP / hour; 120 image requests / IP / minute
5. **Server-side JWT verification**: the Worker verifies the `Cf-Access-Jwt-Assertion` signature / aud / expiry — hitting the Worker domain directly without Access still gets blocked
6. **Secrets stay out of the repo**: `SIGN_SECRET` lives only in Dashboard Secrets

## Deploy Your Own

### 1. Create an R2 bucket

Dashboard → R2 → Create bucket, e.g. `prompt-share-imgs`. Keep it **private** (no public access).

### 2. Create a KV namespace

Workers & Pages → KV → Create namespace, e.g. `prompt-share`.

### 3. Connect Workers to GitHub for auto-deploy

Workers & Pages → Create → Import a repository → select this repo → Deploy.
Note the assigned `*.workers.dev` domain; binding your own domain is recommended (Settings → Domains).

### 4. Configure bindings and variables

Workers → Settings → Bindings:
- R2 bucket → variable name `IMGS` → the bucket from step 1
- KV namespace → variable name `SHARE` → the namespace from step 2

Settings → Variables:
- **Secret** `SIGN_SECRET` = random string (`openssl rand -hex 32`)
- **Text** `ADMIN_EMAILS` = your email (comma-separated for multiple)
- **Text** `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD` = fill in after step 5, then Redeploy

### 5. Configure Cloudflare Access (Zero Trust)

Zero Trust Dashboard → Access → Applications. Create two applications:

**App 1 `prompt-share-public` (Bypass, everyone)**, add on both domains:
`/`、`/tag/*`、`/search*`、`/f/*`、`/img/*`

**App 2 `prompt-share` (Allow, email allowlist)**, add on both domains:
`/upload`、`/mine`、`/api/*`、`/admin/*`
- Policy → Allow → Emails: admin + regular users' emails (free up to 50 users)
- Copy the app's **AUD** and your Team Domain back into step 4, then Redeploy

Adding/removing people later: just edit the Policy's email list — takes effect immediately, no code changes.

### 6. Verify

1. Open the homepage in an incognito window → **no login redirect**, gallery visible
2. Click "Share a work" → Access login appears
3. Log in as admin → `/upload` a work (mark as featured) → get the `/f/` link, it shows up in the featured section
4. `/mine` and `/admin` work as expected

## Free Tier (2026)

| Resource | Free quota |
|---|---|
| R2 | 10 GB storage / month, 1M writes, 10M reads, free egress |
| KV | 1 GB storage, 100K reads / 1K writes per day |
| Workers | 100K requests / day |
| Access | free up to 50 users |

## Local Development

```bash
npx wrangler dev
npx wrangler deploy
npx wrangler secret put SIGN_SECRET
```

## Project Structure

```
src/worker.js    all logic (single file, zero dependencies)
assets/logo.svg  project logo
wrangler.toml    deploy configuration
README.md        this file (English)
README.zh-CN.md  中文文档
CHANGELOG.md     changelog (English)
CHANGELOG.zh-CN.md  更新日志
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) — do whatever you want, attribution appreciated.
