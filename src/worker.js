// prompt-share Worker v2 (公开画廊版)
// 提示词 + 图片分享小站: 公开浏览画廊, 登录上传, 管理员审核
//
// 绑定要求 (Dashboard -> Workers -> Settings -> Bindings):
//   R2  bucket    binding=IMGS   bucket 名: prompt-share-imgs (保持私有)
//   KV  namespace binding=SHARE
// 变量 / Secrets (Settings -> Variables):
//   SIGN_SECRET         [Secret] 图片 URL 签名密钥
//   ACCESS_TEAM_DOMAIN  [Var]    Zero Trust team 域名
//   ACCESS_AUD          [Var]    Access Application 的 AUD
//   ADMIN_EMAILS        [Var]    管理员邮箱, 逗号分隔
//
// 路由:
//   GET  /              公开画廊首页 (精选 + 最新 + 标签云 + 搜索)
//   GET  /tag/:tag      公开标签页
//   GET  /search?q=     公开搜索 (标题/标签/提示词子串, 近 150 条内过滤)
//   GET  /f/:id         分享详情页 (公开, 一键复制提示词)
//   GET  /img/:id       图片代理 (公开, 签名+防盗链+缓存+限流)
//   GET  /upload        上传页 (需 Access 登录; 管理员直发, 普通用户进待审)
//   GET  /mine          我的作品 (需登录)
//   GET  /admin         审核 + 精选管理 (仅管理员)
//   POST /api/upload    上传 (需登录)
//   POST /api/review    审核操作 approve/reject/unfeature (仅管理员)
//   POST /api/admin/reindex  给 v1 老数据补索引 (仅管理员, 幂等)
//   GET  /healthz       存活检查 (公开)
//
// KV 键设计:
//   s:{id}                       分享 JSON {id,title,prompt,tags[],author,featured,createdAt,...}
//   pending:{id}                 待审 JSON (30 天过期)
//   img:{id}                     R2 对象键
//   idx:new:{inv}:{id}           最新索引 (inv = 9999999999999-ts, 字典序即最新在前)
//   idx:tag:{tag}:{inv}:{id}     标签索引
//   idx:user:{email}:{inv}:{id}  用户作品索引
//   idx:featured:{inv}:{id}      精选索引
//   rl:*                         限流计数器
//
// Access 侧配置 (Zero Trust Dashboard):
//   prompt-share-public (Bypass): / /tag/* /search* /f/* /img/*
//   prompt-share        (Allow 邮箱白名单): /upload /mine /api/* /admin/*

var ID_LEN = 10;
var MAX_IMG_BYTES = 10 * 1024 * 1024;
var SIG_TTL_SEC = 6 * 3600;
var UPLOAD_LIMIT_PER_HOUR = 20;
var IMG_LIMIT_PER_MIN = 120;
var PAGE_SIZE = 24;
var MAX_TAGS = 5;
var SEARCH_SCAN = 150;
var TAG_CLOUD = ['人物', '摄影', '动漫', '风景', '建筑', '科幻', '产品', '插画', '动物', '美食'];

/* ---------- 工具 ---------- */

function newId(n) {
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  var buf = new Uint8Array(n || ID_LEN);
  crypto.getRandomValues(buf);
  var s = '';
  for (var i = 0; i < buf.length; i++) s += chars[buf[i] % chars.length];
  return s;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function b64urlEncode(bytes) {
  var bin = '';
  var u8 = new Uint8Array(bytes);
  for (var i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var bin = atob(s);
  var u8 = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function hmacSign(secret, msg) {
  var key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return b64urlEncode(sig);
}

function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 反转时间戳: 让 KV list 的字典序 = 最新在前, 分页直接用 limit/offset 思路
function invTs(ts) {
  return String(9999999999999 - ts).padStart(13, '0');
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}

function fmtDate(ts) {
  try { return new Date(ts).toLocaleString('zh-CN', { hour12: false }); }
  catch (e) { return ''; }
}

// 标签清洗: 切分、去重、最多 MAX_TAGS 个、每标签最多 20 字、只留文字数字_- (兼容中日韩)
function sanitizeTags(raw) {
  var parts = String(raw || '').split(/[,，、\s|｜]+/);
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var t = parts[i].trim().replace(/[^\p{L}\p{N}_-]+/gu, '').slice(0, 20);
    if (t && out.indexOf(t) < 0) out.push(t);
    if (out.length >= MAX_TAGS) break;
  }
  return out;
}

/* ---------- 页面骨架 ---------- */

function htmlPage(title, body, desc) {
  return new Response(
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="description" content="' + escapeHtml(desc || 'AI 提示词与图片灵感库') + '">' +
    '<title>' + escapeHtml(title) + '</title>' +
    '<style>' +
    'body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;' +
    'background:#0f1115;color:#e8eaf0;margin:0;padding:0;line-height:1.6}' +
    '.wrap{max-width:1080px;margin:0 auto;padding:24px 20px 60px}' +
    'header.top{display:flex;align-items:center;justify-content:space-between;padding:18px 0;flex-wrap:wrap;gap:12px}' +
    '.logo{font-size:22px;font-weight:700;color:#fff;text-decoration:none}' +
    '.logo span{color:#7aa2ff}' +
    'nav a{color:#aab2c5;text-decoration:none;margin-left:18px;font-size:14px}' +
    'nav a:hover{color:#fff}' +
    '.hero{text-align:center;padding:44px 10px 30px}' +
    '.hero h1{font-size:32px;margin:0 0 10px}' +
    '.hero p{color:#8b93a7;margin:0 0 22px}' +
    '.searchbar{display:flex;max-width:520px;margin:0 auto;gap:8px}' +
    '.searchbar input{flex:1}' +
    '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:18px;margin-top:8px}' +
    '.card-item{background:#171a21;border:1px solid #262b36;border-radius:12px;overflow:hidden;' +
    'text-decoration:none;color:inherit;display:block;transition:transform .15s}' +
    '.card-item:hover{transform:translateY(-3px);border-color:#4f7cff66}' +
    '.thumb{aspect-ratio:1/1;background:#0b0d11;overflow:hidden}' +
    '.thumb img{width:100%;height:100%;object-fit:cover;display:block}' +
    '.cmeta{padding:12px 14px}' +
    '.ct{font-size:15px;font-weight:600;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
    '.csub{font-size:12px;color:#8b93a7;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
    '.ctags{font-size:12px;color:#7aa2ff;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
    '.sec-t{display:flex;align-items:center;justify-content:space-between;margin:34px 0 6px}' +
    '.sec-t h2{font-size:20px;margin:0}' +
    '.tagcloud{margin:10px 0}' +
    '.tagcloud a{display:inline-block;margin:0 8px 8px 0;padding:6px 14px;border-radius:20px;' +
    'background:#171a21;border:1px solid #2c3342;color:#aab2c5;text-decoration:none;font-size:13px}' +
    '.tagcloud a:hover{border-color:#4f7cff;color:#fff}' +
    '.pager{text-align:center;margin:30px 0}' +
    '.pager a,.pager span{display:inline-block;padding:8px 16px;margin:0 4px;border-radius:8px;' +
    'background:#171a21;border:1px solid #2c3342;color:#aab2c5;text-decoration:none;font-size:14px}' +
    '.pager a:hover{border-color:#4f7cff;color:#fff}' +
    '.pager .cur{background:#4f7cff;border-color:#4f7cff;color:#fff}' +
    '.card{background:#171a21;border:1px solid #262b36;border-radius:12px;padding:20px;margin:16px 0}' +
    'img.full{max-width:100%;border-radius:8px;display:block}' +
    'pre{background:#0b0d11;border:1px solid #262b36;border-radius:8px;padding:14px;' +
    'white-space:pre-wrap;word-break:break-word;font-size:14px}' +
    'button{background:#4f7cff;border:0;color:#fff;padding:10px 18px;border-radius:8px;' +
    'font-size:15px;cursor:pointer;margin:4px 8px 4px 0}button:active{opacity:.8}' +
    'button.danger{background:#c0392b}button.okbtn{background:#1e9e5a}button.ghost{background:#2a3040}' +
    'input,textarea{width:100%;box-sizing:border-box;background:#0b0d11;color:#e8eaf0;' +
    'border:1px solid #262b36;border-radius:8px;padding:10px;font-size:14px;margin:6px 0}' +
    'textarea{min-height:120px}.hint{color:#8b93a7;font-size:13px}' +
    '.err{color:#ff7a7a}.ok{color:#7dff9b}' +
    '.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;' +
    'background:#4f7cff22;color:#9db8ff;border:1px solid #4f7cff66;margin-right:6px}' +
    '.badge.warn{background:#c07f2b22;color:#ffcf9d;border-color:#c07f2b66}' +
    '.badge.good{background:#1e9e5a22;color:#9dffb8;border-color:#1e9e5a66}' +
    'a{color:#7aa2ff}.empty{text-align:center;color:#8b93a7;padding:50px 0}' +
    'footer{margin-top:60px;padding-top:20px;border-top:1px solid #1d222c;color:#5b6373;' +
    'font-size:12px;text-align:center}' +
    '</style></head><body><div class="wrap">' +
    '<header class="top"><a class="logo" href="/">Prompt<span>Share</span></a>' +
    '<nav><a href="/">首页</a><a href="/upload">分享作品</a><a href="/mine">我的</a><a href="/admin">审核</a></nav></header>' +
    body +
    '<footer>PromptShare · AI 提示词灵感库 · 图片与提示词由社区成员分享</footer>' +
    '</div></body></html>',
    { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/* ---------- 限流 ---------- */

async function hitLimit(env, key, max, windowSec) {
  var k = 'rl:' + key;
  var n = parseInt((await env.SHARE.get(k)) || '0', 10) || 0;
  if (n >= max) return true;
  await env.SHARE.put(k, String(n + 1), { expirationTtl: windowSec });
  return false;
}

function clientIp(req) {
  return req.headers.get('cf-connecting-ip') || 'unknown';
}

/* ---------- Cloudflare Access JWT 校验 ---------- */

var certCache = null;
var certCacheAt = 0;

async function getAccessCerts(env) {
  var now = Date.now();
  if (certCache && now - certCacheAt < 3600 * 1000) return certCache;
  var r = await fetch('https://' + env.ACCESS_TEAM_DOMAIN + '/cdn-cgi/access/certs');
  if (!r.ok) throw new Error('access cert fetch failed: ' + r.status);
  var j = await r.json();
  certCache = j.keys || [];
  certCacheAt = now;
  return certCache;
}

async function verifyAccessJwt(env, token) {
  var parts = String(token).split('.');
  if (parts.length !== 3) return null;
  var header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  } catch (e) { return null; }

  var aud = payload.aud;
  var audOk = aud === env.ACCESS_AUD ||
    (Array.isArray(aud) && aud.indexOf(env.ACCESS_AUD) >= 0);
  if (!audOk) return null;

  if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
  if (!payload.email) return null;

  var keys = await getAccessCerts(env);
  var jwk = null;
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].kid === header.kid) { jwk = keys[i]; break; }
  }
  if (!jwk) return null;
  var key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  var data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  var sig = b64urlDecode(parts[2]);
  var ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  return ok ? payload.email : null;
}

// 返回登录邮箱; 未登录/伪造返回 null。作者身份只信这个头, 不信前端。
async function accessEmail(req, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  var token = req.headers.get('Cf-Access-Jwt-Assertion') || '';
  if (!token) {
    // 直连 workers.dev 调试时 Access 可能改走 Cookie, 尝试从 Cookie 读
    var ck = req.headers.get('Cookie') || '';
    var m = ck.match(/CF_Authorization=([^;]+)/);
    if (m) token = decodeURIComponent(m[1]);
  }
  if (!token) return null;
  try { return await verifyAccessJwt(env, token); }
  catch (e) { return null; }
}

function isAdmin(env, email) {
  var list = String(env.ADMIN_EMAILS || '').split(',');
  for (var i = 0; i < list.length; i++) {
    if (list[i].trim().toLowerCase() === String(email || '').toLowerCase()) return true;
  }
  return false;
}

function needLogin() {
  return new Response('请先登录 (Cloudflare Access)', { status: 401 });
}

/* ---------- 索引 ---------- */

async function indexPublish(env, meta) {
  var inv = invTs(meta.createdAt);
  var email = String(meta.owner || '').toLowerCase();
  var jobs = [
    env.SHARE.put('idx:new:' + inv + ':' + meta.id, meta.id),
    env.SHARE.put('idx:user:' + email + ':' + inv + ':' + meta.id, meta.id)
  ];
  for (var i = 0; i < meta.tags.length; i++) {
    jobs.push(env.SHARE.put('idx:tag:' + meta.tags[i] + ':' + inv + ':' + meta.id, meta.id));
  }
  if (meta.featured) {
    jobs.push(env.SHARE.put('idx:featured:' + inv + ':' + meta.id, meta.id));
  }
  await Promise.all(jobs);
}

async function unfeature(env, meta) {
  var inv = invTs(meta.createdAt);
  meta.featured = false;
  await Promise.all([
    env.SHARE.delete('idx:featured:' + inv + ':' + meta.id),
    env.SHARE.put('s:' + meta.id, JSON.stringify(meta))
  ]);
}

// 按索引前缀取一页分享 (page 从 1 开始)
async function listByIndex(env, prefix, page) {
  page = Math.max(1, Math.min(50, parseInt(page, 10) || 1));
  var need = page * PAGE_SIZE;
  var keys = [];
  var cursor = undefined;
  var complete = false;
  while (keys.length < need) {
    var r = await env.SHARE.list({ prefix: prefix, limit: Math.min(1000, need - keys.length), cursor: cursor });
    for (var i = 0; i < r.keys.length; i++) keys.push(r.keys[i].name);
    if (r.list_complete) { complete = true; break; }
    cursor = r.cursor;
  }
  var total = keys.length;
  var slice = keys.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  var ids = slice.map(function (k) { return k.split(':').pop(); });
  var metas = await Promise.all(ids.map(function (id) {
    return env.SHARE.get('s:' + id).then(function (raw) {
      return raw ? JSON.parse(raw) : null;
    });
  }));
  // 只有"取满了 need 条且 KV 说还没完"才认为有下一页
  return { items: metas.filter(Boolean), page: page, hasMore: !complete && total >= need };
}

async function signedImgUrl(env, id) {
  var exp = Math.floor(Date.now() / 1000) + SIG_TTL_SEC;
  var sig = await hmacSign(env.SIGN_SECRET, id + '.' + exp);
  return '/img/' + id + '?exp=' + exp + '&sig=' + encodeURIComponent(sig);
}

function cardHtml(imgUrl, meta) {
  var tags = (meta.tags || []).map(function (t) { return '#' + escapeHtml(t); }).join(' ');
  return '<a class="card-item" href="/f/' + escapeHtml(meta.id) + '">' +
    '<div class="thumb"><img loading="lazy" src="' + imgUrl + '" alt="' + escapeHtml(meta.title || '') + '"></div>' +
    '<div class="cmeta"><div class="ct">' + escapeHtml(meta.title || '未命名分享') + '</div>' +
    '<div class="csub">by ' + escapeHtml(meta.author || meta.owner || '?') + ' · ' + fmtDate(meta.createdAt) + '</div>' +
    (tags ? '<div class="ctags">' + tags + '</div>' : '') +
    '</div></a>';
}

async function gridHtml(env, metas) {
  var parts = [];
  for (var i = 0; i < metas.length; i++) {
    parts.push(cardHtml(await signedImgUrl(env, metas[i].id), metas[i]));
  }
  return '<div class="grid">' + parts.join('') + '</div>';
}

function pagerHtml(base, page, hasMore) {
  var h = '<div class="pager">';
  if (page > 1) h += '<a href="' + base + (page - 1) + '">← 上一页</a>';
  h += '<span class="cur">第 ' + page + ' 页</span>';
  if (hasMore) h += '<a href="' + base + (page + 1) + '">下一页 →</a>';
  return h + '</div>';
}

function tagCloudHtml() {
  return '<div class="tagcloud">' + TAG_CLOUD.map(function (t) {
    return '<a href="/tag/' + encodeURIComponent(t) + '">#' + escapeHtml(t) + '</a>';
  }).join('') + '</div>';
}

/* ---------- 公开: 首页画廊 ---------- */

async function galleryPage(env, url) {
  var u = new URL(url);
  var page = parseInt(u.searchParams.get('page') || '1', 10) || 1;

  // 精选
  var feat = await listByIndex(env, 'idx:featured:', 1);
  var featItems = feat.items.slice(0, 8);
  var featHtml = '';
  if (featItems.length) {
    featHtml = '<div class="sec-t"><h2>⭐ 精选</h2></div>' + await gridHtml(env, featItems);
  }

  // 最新
  var latest = await listByIndex(env, 'idx:new:', page);
  var latestHtml = latest.items.length
    ? await gridHtml(env, latest.items) + pagerHtml('/?page=', page, latest.hasMore)
    : '<div class="empty">还没有分享, 快来发布第一张吧 ✨</div>';

  var body =
    '<div class="hero"><h1>发现优秀 AI 作品, 复制提示词直接用</h1>' +
    '<p>社区成员分享的 AI 图片与提示词灵感库</p>' +
    '<form class="searchbar" action="/search" method="GET">' +
    '<input name="q" maxlength="60" placeholder="搜索标题 / 标签 / 提示词...">' +
    '<button type="submit" style="width:auto;white-space:nowrap">搜索</button></form>' +
    '<p style="margin-top:16px"><a href="/upload"><button>📤 分享我的作品</button></a></p></div>' +
    featHtml +
    '<div class="sec-t"><h2>🆕 最新分享</h2></div>' + latestHtml +
    '<div class="sec-t"><h2>🏷️ 热门标签</h2></div>' + tagCloudHtml();

  return htmlPage('PromptShare - AI 提示词灵感库', body,
    'AI 提示词与图片灵感库: 浏览社区分享的优秀 AI 作品, 一键复制提示词。');
}

/* ---------- 公开: 标签页 ---------- */

async function tagPage(env, url, tag) {
  var u = new URL(url);
  var page = parseInt(u.searchParams.get('page') || '1', 10) || 1;
  var r = await listByIndex(env, 'idx:tag:' + tag + ':', page);
  var body = '<div class="sec-t"><h2>🏷️ #' + escapeHtml(tag) + '</h2><a href="/">← 首页</a></div>' +
    (r.items.length
      ? await gridHtml(env, r.items) + pagerHtml('/tag/' + encodeURIComponent(tag) + '?page=', page, r.hasMore)
      : '<div class="empty">这个标签下还没有作品</div>') +
    '<div class="sec-t"><h2>🏷️ 更多标签</h2></div>' + tagCloudHtml();
  return htmlPage('#' + tag + ' - PromptShare', body);
}

/* ---------- 公开: 搜索 ---------- */

async function searchPage(env, url) {
  var u = new URL(url);
  var q = (u.searchParams.get('q') || '').trim().slice(0, 60);
  var body = '<div class="sec-t"><h2>🔍 搜索</h2><a href="/">← 首页</a></div>' +
    '<form class="searchbar" action="/search" method="GET" style="margin:0 0 20px">' +
    '<input name="q" maxlength="60" placeholder="搜索标题 / 标签 / 提示词..." value="' + escapeHtml(q) + '">' +
    '<button type="submit" style="width:auto;white-space:nowrap">搜索</button></form>';

  if (q) {
    var keys = [];
    var r = await env.SHARE.list({ prefix: 'idx:new:', limit: SEARCH_SCAN });
    keys = r.keys.map(function (k) { return k.name; });
    var ql = q.toLowerCase();
    var hits = [];
    // 分批取, 命中即停
    for (var i = 0; i < keys.length && hits.length < PAGE_SIZE; i += 20) {
      var batch = keys.slice(i, i + 20);
      var metas = await Promise.all(batch.map(function (k) {
        var id = k.split(':').pop();
        return env.SHARE.get('s:' + id).then(function (raw) { return raw ? JSON.parse(raw) : null; });
      }));
      for (var j = 0; j < metas.length && hits.length < PAGE_SIZE; j++) {
        var m = metas[j];
        if (!m) continue;
        var hay = ((m.title || '') + ' ' + (m.tags || []).join(' ') + ' ' + (m.prompt || '')).toLowerCase();
        if (hay.indexOf(ql) >= 0) hits.push(m);
      }
    }
    body += hits.length
      ? '<p class="hint">找到 ' + hits.length + ' 个结果 (近 ' + SEARCH_SCAN + ' 条内)</p>' + await gridHtml(env, hits)
      : '<div class="empty">没有找到 "' + escapeHtml(q) + '" 相关的内容, 换个词试试</div>';
  } else {
    body += '<div class="hint">输入关键词, 搜索标题、标签或提示词内容</div>' + tagCloudHtml();
  }
  return htmlPage('搜索 ' + q + ' - PromptShare', body);
}

/* ---------- 公开: 分享详情 ---------- */

async function sharePage(env, id) {
  var raw = await env.SHARE.get('s:' + id);
  if (!raw) {
    return htmlPage('不存在', '<div class="empty"><h2>😶 这个分享不存在、待审核或已删除</h2><p><a href="/">回首页看看</a></p></div>');
  }
  var meta = JSON.parse(raw);
  var imgUrl = await signedImgUrl(env, id);
  var title = meta.title || '未命名分享';
  var tags = (meta.tags || []).map(function (t) {
    return '<a href="/tag/' + encodeURIComponent(t) + '">#' + escapeHtml(t) + '</a>';
  }).join(' ');

  return htmlPage(title + ' - PromptShare',
    '<p class="hint"><a href="/">← 首页</a></p>' +
    '<h2 style="margin:6px 0">🖼️ ' + escapeHtml(title) + '</h2>' +
    '<p><span class="badge">' + escapeHtml(meta.author || meta.owner || '?') + '</span>' +
    '<span class="hint">' + fmtDate(meta.createdAt) + ' 分享</span></p>' +
    (tags ? '<p>' + tags + '</p>' : '') +
    '<div class="card"><img class="full" src="' + imgUrl + '" alt="分享图片"></div>' +
    '<div class="card"><div class="hint">提示词 ' +
    '<button style="padding:4px 14px;font-size:13px" onclick="copyP()">📋 一键复制</button></div>' +
    '<pre id="p">' + escapeHtml(meta.prompt) + '</pre>' +
    '<p class="hint">图片链接 ' + Math.round(SIG_TTL_SEC / 3600) + ' 小时内有效, 过期请刷新本页</p></div>' +
    '<p><a href="/upload"><button>我也分享一个 →</button></a></p>' +
    '<script>' +
    'var PT=' + JSON.stringify(meta.prompt).replace(/<\//g, '<\\/') + ';' +
    'function copyP(){' +
    'function done(){alert("提示词已复制, 去创作吧 ✨");}' +
    'if(navigator.clipboard&&navigator.clipboard.writeText){' +
    'navigator.clipboard.writeText(PT).then(done).catch(function(){fallback();});}else{fallback();}' +
    'function fallback(){var t=document.createElement("textarea");t.value=PT;' +
    'document.body.appendChild(t);t.select();try{document.execCommand("copy");done();}' +
    'catch(e){alert("复制失败, 请手动复制");}document.body.removeChild(t);}}' +
    '</script>',
    (meta.prompt || '').slice(0, 120));
}

/* ---------- 公开: 图片代理 (签名+防盗链+缓存+限流) ---------- */

async function serveImage(env, req, id, url) {
  var u = new URL(url);
  var exp = parseInt(u.searchParams.get('exp') || '0', 10);
  var sig = u.searchParams.get('sig') || '';
  if (!exp || exp < Math.floor(Date.now() / 1000)) {
    return new Response('链接已过期,请重新打开分享页', { status: 403 });
  }
  var expect = await hmacSign(env.SIGN_SECRET, id + '.' + exp);
  if (!timingSafeEqual(sig, expect)) {
    return new Response('签名无效', { status: 403 });
  }

  var ref = req.headers.get('Referer') || req.headers.get('Origin') || '';
  if (ref) {
    var refHost = '';
    try { refHost = new URL(ref).host; } catch (e) {}
    if (refHost !== u.host) return new Response('禁止外部引用', { status: 403 });
  }

  if (await hitLimit(env, 'img:' + clientIp(req), IMG_LIMIT_PER_MIN, 60)) {
    return new Response('请求过于频繁,请稍后再试', { status: 429 });
  }

  var obj = await env.IMGS.get('img:' + id);
  if (!obj) return new Response('图片不存在', { status: 404 });

  var headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('etag', obj.httpEtag);
  headers.set('cache-control', 'public, max-age=31536000, immutable');
  headers.set('content-type', obj.httpMetadata.contentType || 'image/jpeg');
  return new Response(obj.body, { headers: headers });
}

/* ---------- 登录: 上传页 ---------- */

function uploadPage(email, admin) {
  var note = admin
    ? '<p class="hint">你是管理员, 上传直接上架。</p>'
    : '<p class="hint">你的上传需要管理员审核通过后才能上架, 可在「<a href="/mine">我的</a>」查看状态。</p>';
  return htmlPage('分享作品 - PromptShare',
    '<h2>📤 分享提示词 + 图片</h2>' +
    '<p><span class="badge">' + escapeHtml(email) + '</span>' +
    (admin ? '<span class="badge">管理员</span>' : '<span class="badge">普通用户</span>') + '</p>' +
    note +
    '<div class="card">' +
    '<label class="hint">标题 (可选, 最多 80 字)</label>' +
    '<input id="title" maxlength="80" placeholder="给这次分享起个名字">' +
    '<label class="hint">提示词 *</label>' +
    '<textarea id="prompt" placeholder="粘贴你的提示词..."></textarea>' +
    '<label class="hint">标签 (可选, 最多 ' + MAX_TAGS + ' 个, 用逗号或空格分隔, 如: 人物, 摄影)</label>' +
    '<input id="tags" maxlength="120" placeholder="人物, 摄影, 动漫...">' +
    '<label class="hint">图片 * (最大 10MB)</label>' +
    '<input id="file" type="file" accept="image/*">' +
    (admin ? '<p><label class="hint"><input id="featured" type="checkbox" style="width:auto"> 设为精选 (首页展示)</label></p>' : '') +
    '<p><button id="btn" onclick="go()">上传</button></p>' +
    '<p id="msg" class="hint"></p><div id="out"></div></div>' +
    '<script>' +
    'async function go(){' +
    'var f=document.getElementById("file").files[0];' +
    'var p=document.getElementById("prompt").value.trim();' +
    'var msg=document.getElementById("msg"),out=document.getElementById("out");' +
    'if(!f){msg.innerHTML="<span class=err>请先选一张图片</span>";return;}' +
    'if(!p){msg.innerHTML="<span class=err>提示词不能为空</span>";return;}' +
    'msg.textContent="上传中...";out.innerHTML="";' +
    'var fd=new FormData();fd.append("image",f);fd.append("prompt",p);' +
    'fd.append("title",document.getElementById("title").value.trim());' +
    'fd.append("tags",document.getElementById("tags").value.trim());' +
    'var fc=document.getElementById("featured");if(fc&&fc.checked)fd.append("featured","1");' +
    'try{' +
    'var r=await fetch("/api/upload",{method:"POST",body:fd});' +
    'var d=await r.json();' +
    'if(!d.ok){msg.innerHTML="<span class=err>"+d.error+"</span>";return;}' +
    'if(d.pending){msg.innerHTML="<span class=ok>✅ 已提交审核, 通过后上架, 可在「<a href=/mine>我的</a>」查看状态</span>";return;}' +
    'msg.innerHTML="<span class=ok>✅ 已上架</span>";' +
    'out.innerHTML="<div class=card><div class=hint>分享链接:</div><p><a href="+d.url+">"+d.url+"</a></p>" +' +
    '"<button onclick=\\"navigator.clipboard.writeText(\\""+d.url+"\\").then(()=>alert(\\"已复制\\"))\\">复制链接</button> " +' +
    '"<a href=/><button class=ghost>回首页看看</button></a></div>";' +
    '}catch(e){msg.innerHTML="<span class=err>上传失败: "+e+"</span>";}' +
    '}' +
    '</script>');
}

/* ---------- 登录: 我的作品 ---------- */

async function minePage(env, email) {
  var em = email.toLowerCase();

  // 已发布
  var pub = await listByIndex(env, 'idx:user:' + em + ':', 1);
  var pubItems = pub.items.slice(0, 100);

  // 待审核 (pending 量小, 直接扫)
  var pendList = await env.SHARE.list({ prefix: 'pending:', limit: 200 });
  var pends = [];
  for (var i = 0; i < pendList.keys.length; i++) {
    var raw = await env.SHARE.get(pendList.keys[i].name);
    if (!raw) continue;
    var m = JSON.parse(raw);
    if (String(m.owner || '').toLowerCase() === em) {
      m.id = pendList.keys[i].name.slice('pending:'.length);
      pends.push(m);
    }
  }

  var body = '<h2>👤 我的作品</h2><p><span class="badge">' + escapeHtml(email) + '</span></p>';

  body += '<div class="sec-t"><h2>⏳ 待审核 (' + pends.length + ')</h2></div>';
  if (pends.length) {
    // 待审条目尚未上架, 不链到 /f/, 只做静态展示
    body += '<div class="grid">';
    for (var i = 0; i < pends.length; i++) {
      var pm = pends[i];
      var pimg = await signedImgUrl(env, pm.id);
      var ptags = (pm.tags || []).map(function (t) { return '#' + escapeHtml(t); }).join(' ');
      body += '<div class="card-item"><div class="thumb"><img loading="lazy" src="' + pimg + '"></div>' +
        '<div class="cmeta"><div class="ct">' + escapeHtml(pm.title || '未命名分享') + '</div>' +
        '<div class="csub"><span class="badge warn">待审核</span>' + fmtDate(pm.createdAt) + '</div>' +
        (ptags ? '<div class="ctags">' + ptags + '</div>' : '') + '</div></div>';
    }
    body += '</div>';
  } else {
    body += '<p class="hint">没有待审核的内容</p>';
  }

  body += '<div class="sec-t"><h2>✅ 已上架 (' + pubItems.length + ')</h2></div>';
  body += pubItems.length ? await gridHtml(env, pubItems) : '<p class="hint">还没有上架的作品, <a href="/upload">去分享第一张 →</a></p>';

  return htmlPage('我的作品 - PromptShare', body);
}

/* ---------- 管理员: 审核 + 精选管理 ---------- */

async function adminPage(env) {
  var list = await env.SHARE.list({ prefix: 'pending:' });
  var cards = '';
  for (var i = 0; i < list.keys.length; i++) {
    var raw = await env.SHARE.get(list.keys[i].name);
    if (!raw) continue;
    var m = JSON.parse(raw);
    var id = list.keys[i].name.slice('pending:'.length);
    var imgUrl = await signedImgUrl(env, id);
    var tags = (m.tags || []).map(function (t) { return '#' + escapeHtml(t); }).join(' ');
    cards += '<div class="card">' +
      '<p><span class="badge">' + escapeHtml(m.owner || '?') + '</span>' +
      '<span class="hint">' + fmtDate(m.createdAt) + '</span></p>' +
      '<p><b>' + escapeHtml(m.title || '未命名') + '</b></p>' +
      (tags ? '<p class="hint">' + tags + '</p>' : '') +
      '<img class="full" src="' + imgUrl + '" style="max-height:320px;width:auto">' +
      '<pre>' + escapeHtml(m.prompt) + '</pre>' +
      '<button class="okbtn" onclick="audit(\'' + id + '\',\'approve\',false)">✅ 通过上架</button>' +
      '<button class="okbtn" onclick="audit(\'' + id + '\',\'approve\',true)">⭐ 通过并精选</button>' +
      '<button class="danger" onclick="audit(\'' + id + '\',\'reject\')">🗑 驳回删除</button>' +
      '</div>';
  }
  if (!cards) cards = '<p class="hint">🎉 没有待审核的内容</p>';

  // 精选管理
  var feat = await listByIndex(env, 'idx:featured:', 1);
  var featItems = feat.items.slice(0, 50);
  var featCards = '';
  for (var k = 0; k < featItems.length; k++) {
    var fm = featItems[k];
    featCards += '<div class="card" style="display:flex;gap:14px;align-items:center">' +
      '<a href="/f/' + escapeHtml(fm.id) + '"><img src="' + await signedImgUrl(env, fm.id) +
      '" style="width:90px;height:90px;object-fit:cover;border-radius:8px"></a>' +
      '<div style="flex:1"><b>' + escapeHtml(fm.title || '未命名') + '</b>' +
      '<div class="hint">by ' + escapeHtml(fm.author || fm.owner || '?') + '</div></div>' +
      '<button class="ghost" onclick="audit(\'' + fm.id + '\',\'unfeature\')">取消精选</button></div>';
  }
  if (!featCards) featCards = '<p class="hint">暂无精选内容</p>';

  return htmlPage('审核 - PromptShare',
    '<div class="sec-t"><h2>🛡️ 待审核 (' + list.keys.length + ')</h2><a href="/">← 首页</a></div>' +
    '<div class="card"><b>🛠 维护</b> <span class="hint">给 v1 老数据补首页索引（幂等）</span> ' +
    '<button class="btn" id="reindex" style="width:auto;padding:8px 16px">补建索引</button> <span id="remsg" class="hint"></span></div>' +
    cards +
    '<div class="sec-t"><h2>⭐ 精选管理 (' + featItems.length + ')</h2></div>' +
    featCards +
    '<script>' +
    'async function audit(id, act, featured){' +
    'var tip = act==="approve" ? (featured?"通过并设为精选?":"通过上架?") : (act==="unfeature"?"取消精选?":"驳回并删除?");' +
    'if(!confirm(tip))return;' +
    'var r=await fetch("/api/review",{method:"POST",' +
    'headers:{"content-type":"application/json"},' +
    'body:JSON.stringify({id:id,action:act,featured:!!featured})});' +
    'var d=await r.json();' +
    'if(d.ok){location.reload();}else{alert(d.error||"失败");}' +
    '}' +
    'document.getElementById("reindex").onclick=async()=>{' +
    'var m=document.getElementById("remsg");m.textContent="处理中…";' +
    'try{var r=await fetch("/api/admin/reindex",{method:"POST"});var d=await r.json();' +
    'if(d.ok){m.textContent="已补 "+d.reindexed.length+" 条, 刷新页面查看";}else{m.textContent="失败: "+(d.error||r.status);}}' +
    'catch(e){m.textContent="失败: "+e;}};' +
    '</script>');
}

/* ---------- API: 上传 ---------- */

async function apiUpload(env, req, url) {
  var email = await accessEmail(req, env);
  if (!email) return json({ ok: false, error: '未登录, 请从正常入口访问' }, 401);

  if (await hitLimit(env, 'up:' + clientIp(req), UPLOAD_LIMIT_PER_HOUR, 3600)) {
    return json({ ok: false, error: '上传太频繁,请一小时后再试' }, 429);
  }

  var form;
  try { form = await req.formData(); }
  catch (e) { return json({ ok: false, error: '请用 multipart 表单上传' }, 400); }

  var file = form.get('image');
  var prompt = String(form.get('prompt') || '').trim().slice(0, 20000);
  var title = String(form.get('title') || '').trim().slice(0, 80);
  var tags = sanitizeTags(form.get('tags'));
  var wantFeatured = String(form.get('featured') || '') === '1';

  if (!file || typeof file.arrayBuffer !== 'function') {
    return json({ ok: false, error: '没收到图片文件' }, 400);
  }
  if (!prompt) return json({ ok: false, error: '提示词不能为空' }, 400);
  if (file.size > MAX_IMG_BYTES) return json({ ok: false, error: '图片超过 10MB' }, 413);
  if (!/^image\//.test(file.type || '')) return json({ ok: false, error: '只接受图片文件' }, 400);

  var admin = isAdmin(env, email);
  var id = newId();
  var buf = await file.arrayBuffer();
  await env.IMGS.put('img:' + id, buf, {
    httpMetadata: { contentType: file.type || 'image/jpeg' }
  });

  var meta = {
    id: id, title: title, prompt: prompt, tags: tags,
    contentType: file.type || 'image/jpeg',
    size: file.size, owner: email, author: email.split('@')[0],
    featured: admin && wantFeatured, createdAt: Date.now()
  };

  if (admin) {
    await env.SHARE.put('s:' + id, JSON.stringify(meta));
    await indexPublish(env, meta);
    var host = new URL(url).host;
    return json({ ok: true, id: id, url: 'https://' + host + '/f/' + id });
  }
  await env.SHARE.put('pending:' + id, JSON.stringify(meta), { expirationTtl: 30 * 86400 });
  return json({ ok: true, pending: true, msg: '已提交审核' });
}

/* ---------- API: 审核 ---------- */

async function apiReview(env, req) {
  var email = await accessEmail(req, env);
  if (!email || !isAdmin(env, email)) {
    return json({ ok: false, error: '只有管理员能操作' }, 403);
  }
  var body;
  try { body = await req.json(); } catch (e) { return json({ ok: false, error: '参数错误' }, 400); }
  var id = String(body.id || '');
  var action = String(body.action || '');
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return json({ ok: false, error: 'id 非法' }, 400);

  if (action === 'approve' || action === 'reject') {
    var raw = await env.SHARE.get('pending:' + id);
    if (!raw) return json({ ok: false, error: '这条不在待审队列' }, 404);
    if (action === 'approve') {
      var meta = JSON.parse(raw);
      meta.id = id;
      if (body.featured) meta.featured = true;
      await env.SHARE.put('s:' + id, JSON.stringify(meta));
      await indexPublish(env, meta);
      await env.SHARE.delete('pending:' + id);
      return json({ ok: true });
    }
    await env.IMGS.delete('img:' + id);
    await env.SHARE.delete('pending:' + id);
    return json({ ok: true });
  }

  if (action === 'unfeature') {
    var sraw = await env.SHARE.get('s:' + id);
    if (!sraw) return json({ ok: false, error: '分享不存在' }, 404);
    await unfeature(env, JSON.parse(sraw));
    return json({ ok: true });
  }

  return json({ ok: false, error: '未知操作' }, 400);
}

/* 一次性: 给 v1 老数据补 v2 索引 (管理员, 幂等, 多跑几次没关系) */
async function apiReindex(env, req) {
  const em = await accessEmail(req, env);
  if (!isAdmin(env, em)) return json({ ok: false, error: '仅管理员' }, 403);
  const ids = [];
  let cursor = undefined;
  for (;;) {
    const r = await env.SHARE.list({ prefix: 's:', cursor });
    for (const k of r.keys) {
      const meta = await env.SHARE.get(k.name, 'json');
      if (!meta || !meta.id) continue;
      meta.tags = sanitizeTags(meta.tags);
      if (!meta.createdAt) meta.createdAt = Date.now();
      await env.SHARE.put('s:' + meta.id, JSON.stringify(meta));
      await indexPublish(env, meta.id, meta);
      ids.push(meta.id);
    }
    if (r.list_complete) break;
    cursor = r.cursor;
  }
  return json({ ok: true, reindexed: ids });
}

/* ---------- 入口 ---------- */

export default {
  async fetch(req, env, ctx) {
    var url = req.url;
    var u = new URL(url);
    var path = u.pathname;

    if (!env.SIGN_SECRET) {
      return new Response('服务端未配置 SIGN_SECRET', { status: 500 });
    }

    if (path === '/healthz') return json({ ok: true });

    // ---- 公开区 (Access 侧 Bypass, Worker 侧不校验) ----
    if (path === '/' && req.method === 'GET') return galleryPage(env, url);
    var mT = path.match(/^\/tag\/([^/]+)$/);
    if (mT && req.method === 'GET') {
      return tagPage(env, url, decodeURIComponent(mT[1]).slice(0, 20));
    }
    if (path === '/search' && req.method === 'GET') return searchPage(env, url);
    var mF = path.match(/^\/f\/([A-Za-z0-9]{10})$/);
    if (mF && req.method === 'GET') return sharePage(env, mF[1]);
    var mI = path.match(/^\/img\/([A-Za-z0-9]{10})$/);
    if (mI && req.method === 'GET') return serveImage(env, req, mI[1], url);

    // ---- 登录区 (Access 保护 + Worker 侧二次校验 JWT) ----
    if (path === '/upload' && req.method === 'GET') {
      var emU = await accessEmail(req, env);
      if (!emU) return needLogin();
      return uploadPage(emU, isAdmin(env, emU));
    }
    if (path === '/mine' && req.method === 'GET') {
      var emM = await accessEmail(req, env);
      if (!emM) return needLogin();
      return minePage(env, emM);
    }
    if (path === '/admin' && req.method === 'GET') {
      var emA = await accessEmail(req, env);
      if (!emA || !isAdmin(env, emA)) return new Response('只有管理员能看', { status: 403 });
      return adminPage(env);
    }
    if (path === '/api/upload' && req.method === 'POST') return apiUpload(env, req, url);
    if (path === '/api/review' && req.method === 'POST') return apiReview(env, req);
    if (path === '/api/admin/reindex' && req.method === 'POST') return apiReindex(env, req);

    return new Response('Not found', { status: 404 });
  }
};
