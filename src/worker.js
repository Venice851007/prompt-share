// prompt-share Worker (Access 版)
// 提示词 + 图片分享小站, 登录鉴权走 Cloudflare Access
//
// 绑定要求 (Dashboard -> Workers -> Settings -> Bindings):
//   R2  bucket    binding=IMGS   bucket 名: prompt-share-imgs (保持私有)
//   KV  namespace binding=SHARE
// 变量 / Secrets (Settings -> Variables):
//   SIGN_SECRET         [Secret] 图片 URL 签名密钥 (openssl rand -hex 32)
//   ACCESS_TEAM_DOMAIN  [Var]    Zero Trust team 域名, 如 yourteam.cloudflareaccess.com
//   ACCESS_AUD          [Var]    Access Application 的 AUD (应用总览页里找)
//   ADMIN_EMAILS        [Var]    管理员邮箱, 逗号分隔, 如 a@x.com,b@x.com
//
// 路由:
//   GET  /              上传页 (需 Access 登录; 管理员直发, 普通用户进待审)
//   POST /api/share     上传图片+提示词
//   GET  /f/:id         分享页 (公开, 无需登录)
//   GET  /img/:id       图片代理 (公开, 签名+防盗链+缓存+限流)
//   GET  /admin         审核页 (仅管理员)
//   POST /api/admin/approve  {id}  通过上架
//   POST /api/admin/reject   {id}  驳回删除
//   GET  /healthz       存活检查
//
// Access 侧配置 (Zero Trust Dashboard):
//   建一个 Self-hosted Application, 保护路径 / /api/* /admin/*,
//   公开路径 /f/* /img/*; Policy 用 Allow + 指定邮箱名单 (≤50 人免费)。

var ID_LEN = 10;
var MAX_IMG_BYTES = 10 * 1024 * 1024;
var SIG_TTL_SEC = 6 * 3600;
var UPLOAD_LIMIT_PER_HOUR = 20;
var IMG_LIMIT_PER_MIN = 120;

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

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}

function htmlPage(title, body) {
  return new Response(
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + escapeHtml(title) + '</title>' +
    '<style>body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;' +
    'background:#0f1115;color:#e8eaf0;margin:0;padding:24px;line-height:1.6}' +
    '.wrap{max-width:720px;margin:0 auto}.card{background:#171a21;border:1px solid #262b36;' +
    'border-radius:12px;padding:20px;margin:16px 0}' +
    'img{max-width:100%;border-radius:8px;display:block}' +
    'pre{background:#0b0d11;border:1px solid #262b36;border-radius:8px;padding:14px;' +
    'white-space:pre-wrap;word-break:break-word;font-size:14px}' +
    'button{background:#4f7cff;border:0;color:#fff;padding:10px 18px;border-radius:8px;' +
    'font-size:15px;cursor:pointer;margin:4px 8px 4px 0}button:active{opacity:.8}' +
    'button.danger{background:#c0392b}button.okbtn{background:#1e9e5a}' +
    'input,textarea{width:100%;box-sizing:border-box;background:#0b0d11;color:#e8eaf0;' +
    'border:1px solid #262b36;border-radius:8px;padding:10px;font-size:14px;margin:6px 0}' +
    'textarea{min-height:120px}.hint{color:#8b93a7;font-size:13px}' +
    '.err{color:#ff7a7a}.ok{color:#7dff9b}.badge{display:inline-block;padding:2px 10px;' +
    'border-radius:20px;font-size:12px;background:#4f7cff22;color:#9db8ff;border:1px solid #4f7cff66}' +
    'a{color:#7aa2ff;word-break:break-all}</style>' +
    '</head><body><div class="wrap">' + body + '</div></body></html>',
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

  // aud 校验 (可能是字符串或数组)
  var aud = payload.aud;
  var audOk = aud === env.ACCESS_AUD ||
    (Array.isArray(aud) && aud.indexOf(env.ACCESS_AUD) >= 0);
  if (!audOk) return null;

  // 过期校验
  if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
  if (!payload.email) return null;

  // 签名校验 (RS256)
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

// 返回登录邮箱; 未登录/伪造返回 null
async function accessEmail(req, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  var token = req.headers.get('Cf-Access-Jwt-Assertion') || '';
  if (!token) return null;
  try { return await verifyAccessJwt(env, token); }
  catch (e) { return null; }
}

function isAdmin(env, email) {
  var list = String(env.ADMIN_EMAILS || '').split(',');
  for (var i = 0; i < list.length; i++) {
    if (list[i].trim().toLowerCase() === String(email).toLowerCase()) return true;
  }
  return false;
}

/* ---------- 上传页 ---------- */

function uploadPage(email, admin) {
  var note = admin
    ? '<p class="hint">你是管理员, 上传直接上架。</p>'
    : '<p class="hint">你的上传需要管理员审核通过后才能上架。</p>';
  return htmlPage('Prompt Share - 分享', '' +
    '<h2>📤 分享提示词 + 图片</h2>' +
    '<p><span class="badge">' + escapeHtml(email) + '</span> ' +
    (admin ? '<span class="badge">管理员</span>' : '<span class="badge">普通用户</span>') +
    ' <a href="/admin" style="font-size:13px">' + (admin ? '去审核 →' : '') + '</a></p>' +
    note +
    '<div class="card">' +
    '<label class="hint">标题 (可选)</label>' +
    '<input id="title" maxlength="80" placeholder="给这次分享起个名字">' +
    '<label class="hint">提示词</label>' +
    '<textarea id="prompt" placeholder="粘贴你的提示词..."></textarea>' +
    '<label class="hint">图片 (最大 10MB)</label>' +
    '<input id="file" type="file" accept="image/*">' +
    '<p><button id="btn" onclick="go()">上传</button></p>' +
    '<p id="msg" class="hint"></p>' +
    '<div id="out"></div>' +
    '</div>' +
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
    'try{' +
    'var r=await fetch("/api/share",{method:"POST",body:fd});' +
    'var d=await r.json();' +
    'if(!d.ok){msg.innerHTML="<span class=err>"+d.error+"</span>";return;}' +
    'if(d.pending){msg.innerHTML="<span class=ok>✅ 已提交审核, 通过后上架</span>";return;}' +
    'msg.innerHTML="<span class=ok>✅ 已上架</span>";' +
    'out.innerHTML="<div class=card><div class=hint>分享链接:</div>" +' +
    '"<p><a href="+d.url+">"+d.url+"</a></p>" +' +
    '"<button onclick=\\"navigator.clipboard.writeText(\\""+d.url+"\\").then(()=>alert(\\"已复制\\"))\\">复制链接</button></div>";' +
    '}catch(e){msg.innerHTML="<span class=err>上传失败: "+e+"</span>";}' +
    '}' +
    '</script>');
}

/* ---------- 分享页 /f/:id (公开) ---------- */

async function sharePage(env, id) {
  var raw = await env.SHARE.get('s:' + id);
  if (!raw) {
    return htmlPage('不存在', '<h2>😶 这个分享不存在、待审核或已删除</h2><p><a href="/">我也分享一个</a></p>');
  }
  var meta = JSON.parse(raw);
  var exp = Math.floor(Date.now() / 1000) + SIG_TTL_SEC;
  var sig = await hmacSign(env.SIGN_SECRET, id + '.' + exp);
  var imgUrl = '/img/' + id + '?exp=' + exp + '&sig=' + encodeURIComponent(sig);
  var title = meta.title || '未命名分享';

  return htmlPage(title, '' +
    '<h2>🖼️ ' + escapeHtml(title) + '</h2>' +
    '<div class="card"><img src="' + imgUrl + '" alt="分享图片"></div>' +
    '<div class="card"><div class="hint">提示词 <button style="padding:4px 12px;font-size:13px" ' +
    'onclick="copyP()">复制</button></div>' +
    '<pre id="p">' + escapeHtml(meta.prompt) + '</pre>' +
    '<p class="hint">图片签名 ' + Math.round(SIG_TTL_SEC / 3600) + ' 小时内有效 · ' +
    new Date(meta.createdAt).toLocaleString('zh-CN') + ' 分享</p></div>' +
    '<p><a href="/">我也分享一个 →</a></p>' +
    '<script>' +
    'var PT=' + JSON.stringify(meta.prompt) + ';' +
    'function copyP(){' +
    'if(navigator.clipboard&&navigator.clipboard.writeText){' +
    'navigator.clipboard.writeText(PT).then(()=>alert("提示词已复制"));}else{' +
    'var t=document.createElement("textarea");t.value=PT;document.body.appendChild(t);' +
    't.select();document.execCommand("copy");document.body.removeChild(t);alert("提示词已复制");}}' +
    '</script>');
}

/* ---------- 图片代理 /img/:id (公开, 防刷) ---------- */

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

  // 防盗链
  var ref = req.headers.get('Referer') || req.headers.get('Origin') || '';
  if (ref) {
    var refHost = '';
    try { refHost = new URL(ref).host; } catch (e) {}
    if (refHost !== u.host) return new Response('禁止外部引用', { status: 403 });
  }

  // 限流
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

/* ---------- 上传 API ---------- */

async function apiShare(env, req, url) {
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

  if (!file || typeof file.arrayBuffer !== 'function') {
    return json({ ok: false, error: '没收到图片文件' }, 400);
  }
  if (!prompt) return json({ ok: false, error: '提示词不能为空' }, 400);
  if (file.size > MAX_IMG_BYTES) return json({ ok: false, error: '图片超过 10MB' }, 413);
  if (!/^image\//.test(file.type || '')) return json({ ok: false, error: '只接受图片文件' }, 400);

  var id = newId();
  var buf = await file.arrayBuffer();
  await env.IMGS.put('img:' + id, buf, {
    httpMetadata: { contentType: file.type || 'image/jpeg' }
  });

  var meta = {
    title: title, prompt: prompt,
    contentType: file.type || 'image/jpeg',
    size: file.size, owner: email, createdAt: Date.now()
  };

  if (isAdmin(env, email)) {
    // 管理员: 直接上架
    await env.SHARE.put('s:' + id, JSON.stringify(meta));
    var host = new URL(url).host;
    return json({ ok: true, id: id, url: 'https://' + host + '/f/' + id });
  }
  // 普通用户: 进待审队列
  await env.SHARE.put('pending:' + id, JSON.stringify(meta), { expirationTtl: 30 * 86400 });
  return json({ ok: true, pending: true, msg: '已提交审核' });
}

/* ---------- 审核页 (仅管理员) ---------- */

async function adminPage(env) {
  var list = await env.SHARE.list({ prefix: 'pending:' });
  var cards = '';
  for (var i = 0; i < list.keys.length; i++) {
    var raw = await env.SHARE.get(list.keys[i].name);
    if (!raw) continue;
    var m = JSON.parse(raw);
    var id = list.keys[i].name.slice('pending:'.length);
    var exp = Math.floor(Date.now() / 1000) + SIG_TTL_SEC;
    var sig = await hmacSign(env.SIGN_SECRET, id + '.' + exp);
    var imgUrl = '/img/' + id + '?exp=' + exp + '&sig=' + encodeURIComponent(sig);
    cards += '<div class="card">' +
      '<p><span class="badge">' + escapeHtml(m.owner || '?') + '</span> ' +
      '<span class="hint">' + new Date(m.createdAt).toLocaleString('zh-CN') + '</span></p>' +
      '<p><b>' + escapeHtml(m.title || '未命名') + '</b></p>' +
      '<img src="' + imgUrl + '" style="max-height:320px">' +
      '<pre>' + escapeHtml(m.prompt) + '</pre>' +
      '<button class="okbtn" onclick="audit(\'' + id + '\',\'approve\')">✅ 通过上架</button>' +
      '<button class="danger" onclick="audit(\'' + id + '\',\'reject\')">🗑 驳回删除</button>' +
      '</div>';
  }
  if (!cards) cards = '<div class="card"><p class="hint">🎉 没有待审核的内容</p></div>';
  return htmlPage('审核', '' +
    '<h2>🛡️ 待审核 (' + list.keys.length + ')</h2>' +
    '<p><a href="/">← 回上传页</a></p>' +
    cards +
    '<script>' +
    'async function audit(id, act){' +
    'if(!confirm(act==="approve"?"通过上架?":"驳回并删除?"))return;' +
    'var r=await fetch("/api/admin/"+act,{method:"POST",' +
    'headers:{"content-type":"application/json"},body:JSON.stringify({id:id})});' +
    'var d=await r.json();' +
    'if(d.ok){location.reload();}else{alert(d.error||"失败");}' +
    '}' +
    '</script>');
}

async function apiAdmin(env, req, act) {
  var email = await accessEmail(req, env);
  if (!email || !isAdmin(env, email)) {
    return json({ ok: false, error: '只有管理员能操作' }, 403);
  }
  var body;
  try { body = await req.json(); } catch (e) { return json({ ok: false, error: '参数错误' }, 400); }
  var id = String(body.id || '');
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return json({ ok: false, error: 'id 非法' }, 400);

  var raw = await env.SHARE.get('pending:' + id);
  if (!raw) return json({ ok: false, error: '这条不在待审队列' }, 404);

  if (act === 'approve') {
    await env.SHARE.put('s:' + id, raw);
    await env.SHARE.delete('pending:' + id);
    return json({ ok: true });
  }
  // reject: 删图 + 删记录
  await env.IMGS.delete('img:' + id);
  await env.SHARE.delete('pending:' + id);
  return json({ ok: true });
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

    // 公开区: 分享页 + 图片代理 (Access 侧也放行这两条路径)
    var mF = path.match(/^\/f\/([A-Za-z0-9]{10})$/);
    if (mF && req.method === 'GET') return sharePage(env, mF[1]);
    var mI = path.match(/^\/img\/([A-Za-z0-9]{10})$/);
    if (mI && req.method === 'GET') return serveImage(env, req, mI[1], url);

    // 以下需要 Access 登录 (Worker 侧二次校验 JWT, 防绕过)
    if (path === '/' && req.method === 'GET') {
      var email = await accessEmail(req, env);
      if (!email) return new Response('请先登录 (Cloudflare Access)', { status: 401 });
      return uploadPage(email, isAdmin(env, email));
    }
    if (path === '/api/share' && req.method === 'POST') {
      return apiShare(env, req, url);
    }
    if (path === '/admin' && req.method === 'GET') {
      var em = await accessEmail(req, env);
      if (!em || !isAdmin(env, em)) return new Response('只有管理员能看', { status: 403 });
      return adminPage(env);
    }
    var mA = path.match(/^\/api\/admin\/(approve|reject)$/);
    if (mA && req.method === 'POST') return apiAdmin(env, req, mA[1]);

    return new Response('Not found', { status: 404 });
  }
};
