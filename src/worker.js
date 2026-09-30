// prompt-share Worker v3.3 (双语版 + 管理员删除 + 编辑 + 多图)
// v3.3 新增: 一个提示词可配多张图 (上传多选/编辑加图/勾选删一张或多张), GET /img/:id/:seq
// 中 / EN 一键切换: 界面全双语, 提示词支持中英双版本 (上传时可各填一版, 切换时跟着切)
// 语言判定: Cookie lang > Accept-Language > 默认中文; 右上角切换键写 Cookie 后刷新
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
//   GET  /search?q=     公开搜索 (标题/标签/中英提示词子串, 近 150 条内过滤)
//   GET  /f/:id         分享详情页 (公开, 一键复制当前语言提示词)
//   GET  /img/:id[/:seq] 图片代理 (公开, 签名+防盗链+缓存+限流; seq 为多图序号, 缺省=封面)
//   GET  /upload        上传页 (需 Access 登录; 管理员直发, 普通用户进待审)
//   GET  /mine          我的作品 (需登录)
//   GET  /edit/:id      编辑页 (需登录; 仅作者或管理员)
//   GET  /admin         审核 + 精选管理 (仅管理员)
//   POST /api/upload    上传 (需登录; prompt_zh / prompt_en 双字段)
//   POST /api/edit      更新作品: 标题/中英提示词/标签/可选换图 (作者或管理员; 标签索引差异更新, createdAt 不变)
//   POST /api/review    审核操作 approve/reject/unfeature (仅管理员)
//   POST /api/admin/delete   删除作品 KV + R2 图片 + 全部索引 (仅管理员, 幂等)
//   POST /api/admin/reindex  给 v1 老数据补索引 (仅管理员, 幂等; GET 亦可, 供自动化兜底)
//   GET  /healthz       存活检查 (公开)
//
// KV 键设计:
//   s:{id}                       分享 JSON {id,title,prompt,prompt_zh,prompt_en,tags[],author,featured,createdAt,...}
//                                (prompt 为兼容老数据的兜底字段)
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
var MAX_IMGS = 8;
var SIG_TTL_SEC = 6 * 3600;
var UPLOAD_LIMIT_PER_HOUR = 20;
var IMG_LIMIT_PER_MIN = 120;
var PAGE_SIZE = 24;
var MAX_TAGS = 5;
var SEARCH_SCAN = 150;
var TAG_CLOUD = ['人物', '摄影', '动漫', '风景', '建筑', '科幻', '产品', '插画', '动物', '美食'];
var TAG_CLOUD_EN = { '人物': 'People', '摄影': 'Photography', '动漫': 'Anime', '风景': 'Landscape', '建筑': 'Architecture', '科幻': 'Sci-Fi', '产品': 'Product', '插画': 'Illustration', '动物': 'Animals', '美食': 'Food' };

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

function fmtDate(ts, lang) {
  try { return new Date(ts).toLocaleString(lang === 'en' ? 'en-US' : 'zh-CN', { hour12: false }); }
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

function getCookie(req, name) {
  var ck = req.headers.get('Cookie') || '';
  var m = ck.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

// 语言判定: Cookie > Accept-Language > 默认中文
function getLang(req) {
  var c = getCookie(req, 'lang');
  if (c === 'zh' || c === 'en') return c;
  var al = req.headers.get('accept-language') || '';
  var first = al.split(',')[0].trim().toLowerCase();
  return first.indexOf('en') === 0 ? 'en' : 'zh';
}

// 取当前语言的提示词: en 优先 prompt_en, zh 优先 prompt_zh, 都没有则回退到 prompt (老数据)
function promptFor(meta, lang) {
  if (!meta) return '';
  if (lang === 'en') return meta.prompt_en || meta.prompt || meta.prompt_zh || '';
  return meta.prompt_zh || meta.prompt || meta.prompt_en || '';
}

/* ---------- 中英字典 ---------- */

var STR = {
zh: {
  tagline: 'AI 提示词灵感库',
  home: '首页', upload: '分享作品', mine: '我的', admin: '审核',
  heroH1: '发现优秀 AI 作品, 复制提示词直接用',
  heroP: '社区成员分享的 AI 图片与提示词灵感库',
  searchPh: '搜索标题 / 标签 / 提示词...', searchBtn: '搜索',
  shareCta: '📤 分享我的作品',
  featured: '⭐ 精选', latest: '🆕 最新分享',
  tags: '🏷️ 热门标签', moreTags: '🏷️ 更多标签',
  page: '第', pageOf: '页', prev: '← 上一页', next: '下一页 →',
  emptyHome: '还没有分享, 快来发布第一张吧 ✨',
  backHome: '← 首页', backHomeLink: '回首页看看',
  uploadTitle: '📤 分享提示词 + 图片',
  roleAdmin: '管理员', roleUser: '普通用户',
  noteAdmin: '你是管理员, 上传直接上架。',
  noteUser: '你的上传需要管理员审核通过后才能上架, 可在「<a href="/mine">我的</a>」查看状态。',
  titleLabel: '标题 (可选, 最多 80 字)', titlePh: '给这次分享起个名字',
  promptZhLabel: '中文提示词', promptEnLabel: '英文提示词',
  promptHint: '至少填写一种语言, 两种都填则中英文切换时自动对应',
  promptZhPh: '粘贴中文提示词...', promptEnPh: 'Paste the English prompt...',
  tagsLabel: '标签 (可选, 最多 5 个, 用逗号或空格分隔, 如: 人物, 摄影)',
  tagsPh: '人物, 摄影, 动漫...',
  imgLabel: '图片 * (最大 10MB)',
  featuredLabel: '设为精选 (首页展示)',
  submit: '上传', uploading: '上传中...',
  errNoImg: '请先选一张图片', errNoPrompt: '至少填写一种语言的提示词',
  errUpload: '上传失败: ',
  errTooBig: '有图片超过 10MB, 请压缩后再传',
  errTotalBig: '图片总体积超过 60MB, 请分批上传',
  errNet: '网络连接中断, 请检查网络后重试',
  errTimeout: '上传超时(超过3分钟), 请检查网络后重试',
  okPending: '✅ 已提交审核, 通过后上架, 可在「<a href=/mine>我的</a>」查看状态',
  okLive: '✅ 已上架', shareLink: '分享链接:', copyLink: '复制链接', copied: '已复制',
  promptLabel: '提示词', copyPrompt: '📋 一键复制',
  copiedPrompt: '提示词已复制, 去创作吧 ✨', copyFail: '复制失败, 请手动复制',
  sharedBy: '分享', imgExpiry: '图片链接 {h} 小时内有效, 过期请刷新本页',
  shareCta2: '我也分享一个 →',
  viewOther: 'View in English', viewOtherZh: '查看中文版',
  notFound: '😶 这个分享不存在、待审核或已删除', untitled: '未命名分享',
  tagEmpty: '这个标签下还没有作品',
  searchTitle: '🔍 搜索', searchHint: '输入关键词, 搜索标题、标签或提示词内容',
  foundN: '找到 {n} 个结果 (近 {s} 条内)',
  notFoundQ: '没有找到相关的内容, 换个词试试',
  myTitle: '👤 我的作品', pending: '⏳ 待审核', published: '✅ 已上架',
  nonePending: '没有待审核的内容',
  noPub: '还没有上架的作品, <a href="/upload">去分享第一张 →</a>',
  badgePending: '待审核',
  reviewTitle: '🛡️ 待审核', featTitle: '⭐ 精选管理', noFeat: '暂无精选内容',
  approve: '✅ 通过上架', approveFeat: '⭐ 通过并精选',
  reject: '🗑 驳回删除', unfeature: '取消精选',
  maint: '🛠 维护', maintHint: '给 v1 老数据补首页索引（幂等）', reindexBtn: '补建索引',
  working: '处理中…', reindexed: '已补 {n} 条, 刷新页面查看', failed: '失败: ',
  cfApproveFeat: '通过并设为精选?', cfApprove: '通过上架?',
  cfUnfeature: '取消精选?', cfReject: '驳回并删除?',
  delShare: '🗑 删除作品', delSure: '⚠️ 确认删除？不可恢复', deletedMsg: '已删除',
  edit: '✏️ 编辑', editTitle: '编辑作品', save: '💾 保存修改', backToShare: '← 返回作品页',
  curImg: '当前图片', keepImg: '换图（不换请留空）', saved: '已保存',
  eNotOwner: '只有作者或管理员能编辑',
  imgsLabel: '图片（可多选，最多 8 张）', curImgs: '当前图片（勾选要删除的）',
  addImgs: '继续加图（可多选）', imgsLeft: '还能再加 {n} 张',
  eImgCount: '一张分享最多放 8 张图片', eKeepOne: '至少保留一张图片', delOne: '删除',
  noPendingAdmin: '🎉 没有待审核的内容', adminOnly: '只有管理员能看',
  eLogin: '未登录, 请从正常入口访问', eFreq: '上传太频繁,请一小时后再试',
  eForm: '请用 multipart 表单上传', eNoFile: '没收到图片文件',
  eNoPrompt: '至少填写一种语言的提示词', eBig: '图片超过 10MB', eImgOnly: '只接受图片文件',
  eForbidden: '只有管理员能操作', eBadParam: '参数错误', eBadId: 'id 非法',
  eNotPending: '这条不在待审队列', eNotFound: '分享不存在', eUnknown: '未知操作',
  eAdminOnly: '仅管理员',
  footer: 'PromptShare · AI 提示词灵感库 · 图片与提示词由社区成员分享',
  needLogin: '请先登录 (Cloudflare Access)',
  imgExpired: '链接已过期,请重新打开分享页', imgBadSig: '签名无效',
  imgNoRef: '禁止外部引用', imgFreq: '请求过于频繁,请稍后再试', img404: '图片不存在'
},
en: {
  tagline: 'AI Prompt Inspiration Gallery',
  home: 'Home', upload: 'Share', mine: 'Mine', admin: 'Review',
  heroH1: 'Discover great AI artwork, copy the prompt and create',
  heroP: 'A gallery of AI images and prompts shared by the community',
  searchPh: 'Search titles / tags / prompts...', searchBtn: 'Search',
  shareCta: '📤 Share my work',
  featured: '⭐ Featured', latest: '🆕 Latest',
  tags: '🏷️ Popular tags', moreTags: '🏷️ More tags',
  page: 'Page ', pageOf: '', prev: '← Prev', next: 'Next →',
  emptyHome: 'No shares yet — be the first to post ✨',
  backHome: '← Home', backHomeLink: 'Back to home',
  uploadTitle: '📤 Share a prompt + image',
  roleAdmin: 'Admin', roleUser: 'Member',
  noteAdmin: 'You are an admin — uploads go live immediately.',
  noteUser: 'Your upload goes public after review. Track status under "<a href="/mine">Mine</a>".',
  titleLabel: 'Title (optional, up to 80 chars)', titlePh: 'Give this share a name',
  promptZhLabel: 'Prompt (Chinese)', promptEnLabel: 'Prompt (English)',
  promptHint: 'Fill in at least one language. Fill both and the toggle switches between them.',
  promptZhPh: 'Paste the Chinese prompt...', promptEnPh: 'Paste the English prompt...',
  tagsLabel: 'Tags (optional, up to 5, comma/space separated, e.g. portrait, photography)',
  tagsPh: 'portrait, photography, anime...',
  imgLabel: 'Image * (max 10MB)',
  featuredLabel: 'Feature this (show on homepage)',
  submit: 'Upload', uploading: 'Uploading...',
  errNoImg: 'Please choose an image first', errNoPrompt: 'Please fill in the prompt in at least one language',
  errUpload: 'Upload failed: ',
  errTooBig: 'One image exceeds 10MB, please compress and retry',
  errTotalBig: 'Total size over 60MB, please upload in batches',
  errNet: 'Network interrupted, please check connection and retry',
  errTimeout: 'Upload timed out (over 3 min), please check connection and retry',
  okPending: '✅ Submitted for review. Track status under "<a href=/mine>Mine</a>"',
  okLive: '✅ Published', shareLink: 'Share link:', copyLink: 'Copy link', copied: 'Copied',
  promptLabel: 'Prompt', copyPrompt: '📋 Copy prompt',
  copiedPrompt: 'Prompt copied — go create ✨', copyFail: 'Copy failed, please copy manually',
  sharedBy: 'shared', imgExpiry: 'Image link valid for {h}h — refresh this page if it expires',
  shareCta2: 'Share one too →',
  viewOther: 'View in English', viewOtherZh: '查看中文版',
  notFound: "😶 This share doesn't exist, is under review, or was removed", untitled: 'Untitled',
  tagEmpty: 'No works under this tag yet',
  searchTitle: '🔍 Search', searchHint: 'Type a keyword to search titles, tags, or prompt text',
  foundN: '{n} result(s) found (within latest {s})',
  notFoundQ: 'Nothing found — try another keyword',
  myTitle: '👤 My shares', pending: '⏳ Pending review', published: '✅ Published',
  nonePending: 'Nothing pending review',
  noPub: 'No published works yet — <a href="/upload">share your first →</a>',
  badgePending: 'Pending',
  reviewTitle: '🛡️ Pending review', featTitle: '⭐ Featured', noFeat: 'No featured items',
  approve: '✅ Approve', approveFeat: '⭐ Approve & feature',
  reject: '🗑 Reject & delete', unfeature: 'Unfeature',
  maint: '🛠 Maintenance', maintHint: 'Backfill index for legacy data (idempotent)', reindexBtn: 'Rebuild index',
  working: 'Working…', reindexed: 'Done: {n} item(s) — refresh to view', failed: 'Failed: ',
  cfApproveFeat: 'Approve and feature?', cfApprove: 'Approve?',
  cfUnfeature: 'Unfeature?', cfReject: 'Reject and delete?',
  delShare: '🗑 Delete share', delSure: '⚠️ Confirm delete? Cannot be undone', deletedMsg: 'Deleted',
  edit: '✏️ Edit', editTitle: 'Edit share', save: '💾 Save changes', backToShare: '← Back to share',
  curImg: 'Current image', keepImg: 'Replace image (leave empty to keep current)', saved: 'Saved',
  eNotOwner: 'Only the author or admin can edit',
  imgsLabel: 'Images (select multiple, up to 8)', curImgs: 'Current images (check to delete)',
  addImgs: 'Add more images (multiple ok)', imgsLeft: 'You can add {n} more',
  eImgCount: 'A share can have at most 8 images', eKeepOne: 'Keep at least one image', delOne: 'Delete',
  noPendingAdmin: '🎉 Nothing pending review', adminOnly: 'Admins only',
  eLogin: 'Not signed in — please enter via the normal flow', eFreq: 'Too many uploads — try again in an hour',
  eForm: 'Please upload via multipart form', eNoFile: 'No image file received',
  eNoPrompt: 'Please fill in the prompt in at least one language', eBig: 'Image exceeds 10MB', eImgOnly: 'Images only',
  eForbidden: 'Admins only', eBadParam: 'Bad parameters', eBadId: 'Invalid id',
  eNotPending: 'Not in the review queue', eNotFound: 'Share not found', eUnknown: 'Unknown action',
  eAdminOnly: 'Admins only',
  footer: 'PromptShare · AI prompt inspiration gallery · Images & prompts shared by the community',
  needLogin: 'Please sign in (Cloudflare Access)',
  imgExpired: 'Link expired — reopen the share page', imgBadSig: 'Invalid signature',
  imgNoRef: 'Hotlinking forbidden', imgFreq: 'Too many requests — try again later', img404: 'Image not found'
}};

/* ---------- 页面骨架 ---------- */

function htmlPage(title, body, lang, desc) {
  lang = lang === 'en' ? 'en' : 'zh';
  var t = STR[lang];
  var other = lang === 'en' ? 'zh' : 'en';
  var otherLabel = lang === 'en' ? '中文' : 'EN';
  return new Response(
    '<!DOCTYPE html><html lang="' + (lang === 'en' ? 'en' : 'zh-CN') + '"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="description" content="' + escapeHtml(desc || t.tagline) + '">' +
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
    'nav a.langbtn{border:1px solid #2c3342;border-radius:16px;padding:4px 12px;font-weight:600}' +
    '.hero{text-align:center;padding:44px 10px 30px}' +
    '.hero h1{font-size:32px;margin:0 0 10px}' +
    '.hero p{color:#8b93a7;margin:0 0 22px}' +
    '.searchbar{display:flex;max-width:520px;margin:0 auto;gap:8px}' +
    '.searchbar input{flex:1}' +
    '.masonry{columns:2;column-gap:14px;margin-top:8px}' +
    '@media(min-width:760px){.masonry{columns:3;column-gap:16px}}' +
    '@media(min-width:1100px){.masonry{columns:4}}' +
    '.masonry .card-item{break-inside:avoid;margin:0 0 14px}' +
    '.card-item{background:#171a21;border:1px solid #262b36;border-radius:12px;overflow:hidden;' +
    'text-decoration:none;color:inherit;display:block;transition:transform .15s}' +
    '.card-item:hover{transform:translateY(-3px);border-color:#4f7cff66}' +
    '.thumb{background:#0b0d11;overflow:hidden}' +
    '.thumb img{width:100%;height:auto;display:block}' +
    '.fhero{position:relative;margin:10px calc(50% - 50vw) 0;overflow:hidden;background:#0b0d11}' +
    '.ftrack{display:flex;transition:transform .35s ease;height:min(62vh,560px);min-height:300px}' +
    '.fslide{min-width:100%;position:relative;display:flex;align-items:center;justify-content:center;overflow:hidden}' +
    '.fslide .fbg{position:absolute;inset:-20px;background-size:cover;background-position:center;filter:blur(28px) brightness(.5)}' +
    '.fslide img.main{position:relative;max-width:100%;max-height:100%;object-fit:contain;z-index:1}' +
    '.fcap{position:absolute;left:0;right:0;bottom:0;padding:44px 20px 18px;z-index:2;' +
    'background:linear-gradient(transparent,rgba(0,0,0,.78));color:#fff;text-decoration:none}' +
    '.fcap .t{font-size:20px;font-weight:700}' +
    '.fcap .s{font-size:13px;color:#cdd5e8;margin-top:4px}' +
    '.cnav{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.45);border:none;' +
    'color:#fff;font-size:24px;line-height:1;width:46px;height:46px;border-radius:50%;cursor:pointer;z-index:3}' +
    '.cnav.prev{left:12px}.cnav.next{right:12px}' +
    '.cdots{position:absolute;bottom:16px;left:50%;transform:translateX(-50%);display:flex;gap:7px;z-index:3}' +
    '.cdots i{width:7px;height:7px;border-radius:50%;background:rgba(255,255,255,.35)}' +
    '.cdots i.on{background:#fff}' +
    '.ccount{position:absolute;top:12px;right:14px;background:rgba(0,0,0,.55);color:#fff;' +
    'font-size:12px;padding:4px 11px;border-radius:12px;z-index:3}' +
    '.dcar{position:relative;background:#0b0d11;border-radius:12px;overflow:hidden}' +
    '.dtrack{display:flex;transition:transform .3s ease}' +
    '.dslide{min-width:100%;aspect-ratio:4/3;display:flex;align-items:center;justify-content:center;' +
    'position:relative;overflow:hidden;cursor:zoom-in}' +
    '.dslide .dbg{position:absolute;inset:-16px;background-size:cover;background-position:center;filter:blur(22px) brightness(.5)}' +
    '.dslide img{position:relative;max-width:100%;max-height:100%;object-fit:contain;z-index:1}' +
    '.lbox{position:fixed;inset:0;background:rgba(0,0,0,.94);z-index:99;display:none;align-items:center;justify-content:center}' +
    '.lbox.open{display:flex}' +
    '.lbox img{max-width:96vw;max-height:90vh;object-fit:contain}' +
    '.lbox .lx{position:absolute;top:12px;right:16px;background:rgba(255,255,255,.12);border:none;color:#fff;' +
    'font-size:20px;width:42px;height:42px;border-radius:50%;cursor:pointer;z-index:2}' +
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
    '<nav><a href="/">' + t.home + '</a><a href="/upload">' + t.upload + '</a>' +
    '<a href="/mine">' + t.mine + '</a><a href="/admin">' + t.admin + '</a>' +
    '<a class="langbtn" href="javascript:void(0)" onclick="setLang(\'' + other + '\')">' + otherLabel + '</a></nav></header>' +
    '<script>function setLang(l){document.cookie="lang="+l+";path=/;max-age=31536000;SameSite=Lax";location.reload();}</script>' +
    body +
    '<footer>' + t.footer + '</footer>' +
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

function needLogin(lang) {
  return new Response(STR[lang === 'en' ? 'en' : 'zh'].needLogin, { status: 401 });
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

/* 图片列表: [{seq,ct,size}]; seq '' 为封面(对应 R2 key 'img:<id>'), 其余为 'img:<id>:<seq>'.
   老数据没有 images 数组时, 视为只有一张封面图, 保持兼容. */
function imgList(meta) {
  if (meta && meta.images && meta.images.length) return meta.images;
  return [{ seq: '', ct: (meta && meta.contentType) || 'image/jpeg', size: (meta && meta.size) || 0 }];
}
function imgR2Key(id, seq) {
  return seq ? 'img:' + id + ':' + seq : 'img:' + id;
}

async function signedImgUrl(env, id, seq) {
  seq = seq || '';
  var exp = Math.floor(Date.now() / 1000) + SIG_TTL_SEC;
  var base = seq ? id + '.' + seq : id;
  var sig = await hmacSign(env.SIGN_SECRET, base + '.' + exp);
  return '/img/' + id + (seq ? '/' + seq : '') + '?exp=' + exp + '&sig=' + encodeURIComponent(sig);
}

function cardHtml(imgUrl, meta, lang) {
  var tags = (meta.tags || []).map(function (t) { return '#' + escapeHtml(t); }).join(' ');
  return '<a class="card-item" href="/f/' + escapeHtml(meta.id) + '">' +
    '<div class="thumb"><img loading="lazy" src="' + imgUrl + '" alt="' + escapeHtml(meta.title || '') + '"></div>' +
    '<div class="cmeta"><div class="ct">' + escapeHtml(meta.title || STR[lang].untitled) + '</div>' +
    '<div class="csub">by ' + escapeHtml(meta.author || meta.owner || '?') + ' · ' + fmtDate(meta.createdAt, lang) + '</div>' +
    (tags ? '<div class="ctags">' + tags + '</div>' : '') +
    '</div></a>';
}

async function masonryHtml(env, metas, lang) {
  var parts = [];
  for (var i = 0; i < metas.length; i++) {
    parts.push(cardHtml(await signedImgUrl(env, metas[i].id), metas[i], lang));
  }
  return '<div class="masonry">' + parts.join('') + '</div>';
}

/* 精选 hero: 全幅大图轮播, 客户端随机排序 */
async function featHeroHtml(env, metas, lang) {
  var slides = [];
  for (var i = 0; i < metas.length; i++) {
    var m = metas[i];
    var u = await signedImgUrl(env, m.id);
    var tags = (m.tags || []).map(function (x) { return '#' + escapeHtml(x); }).join(' ');
    slides.push(
      '<div class="fslide"><div class="fbg" style="background-image:url(\'' + u + '\')"></div>' +
      '<img class="main" src="' + u + '" alt="' + escapeHtml(m.title || '') + '" draggable="false">' +
      '<a class="fcap" href="/f/' + escapeHtml(m.id) + '">' +
      '<div class="t">' + escapeHtml(m.title || STR[lang].untitled) + '</div>' +
      '<div class="s">by ' + escapeHtml(m.author || m.owner || '?') + (tags ? ' · ' + tags : '') + '</div>' +
      '</a></div>');
  }
  return '<div class="fhero"><div class="ftrack" id="ftrack">' + slides.join('') + '</div>' +
    (slides.length > 1 ?
      '<button class="cnav prev" onclick="fgo(fi-1)" aria-label="prev">‹</button>' +
      '<button class="cnav next" onclick="fgo(fi+1)" aria-label="next">›</button>' +
      '<div class="cdots" id="fdots"></div><div class="ccount" id="fcount"></div>'
      : '') +
    '<script>' +
    'var fi=0,fN=' + slides.length + ';' +
    'function fgo(n){fi=(n+fN)%fN;' +
    'document.getElementById("ftrack").style.transform="translateX(-"+(fi*100)+"%)";' +
    'var ds=document.querySelectorAll("#fdots i");for(var i=0;i<ds.length;i++)ds[i].className=i===fi?"on":"";' +
    'var c=document.getElementById("fcount");if(c)c.textContent=(fi+1)+"/"+fN;}' +
    '(function(){var tr=document.getElementById("ftrack");if(!tr||fN<2)return;' +
    'var sl=Array.prototype.slice.call(tr.children);' +
    'for(var i=sl.length-1;i>0;i--){var j=Math.floor(Math.random()*(i+1));var tmp=sl[i];sl[i]=sl[j];sl[j]=tmp;}' +
    'for(var k=0;k<sl.length;k++)tr.appendChild(sl[k]);' +
    'var dt=document.getElementById("fdots");' +
    'for(var d=0;d<fN;d++){var el=document.createElement("i");if(d===0)el.className="on";dt.appendChild(el);}' +
    'fgo(0);' +
    'var x0=null;tr.addEventListener("touchstart",function(e){x0=e.touches[0].clientX;},{passive:true});' +
    'tr.addEventListener("touchend",function(e){if(x0===null)return;' +
    'var dx=e.changedTouches[0].clientX-x0;if(Math.abs(dx)>40)fgo(fi+(dx<0?1:-1));x0=null;},{passive:true});' +
    '})();</script></div>';
}

function pagerHtml(base, page, hasMore, t) {
  var h = '<div class="pager">';
  if (page > 1) h += '<a href="' + base + (page - 1) + '">' + t.prev + '</a>';
  h += '<span class="cur">' + t.page + page + t.pageOf + '</span>';
  if (hasMore) h += '<a href="' + base + (page + 1) + '">' + t.next + '</a>';
  return h + '</div>';
}

function tagCloudHtml(lang) {
  return '<div class="tagcloud">' + TAG_CLOUD.map(function (t) {
    var label = (lang === 'en' && TAG_CLOUD_EN[t]) ? TAG_CLOUD_EN[t] : t;
    return '<a href="/tag/' + encodeURIComponent(t) + '">#' + escapeHtml(label) + '</a>';
  }).join('') + '</div>';
}

/* ---------- 公开: 首页画廊 ---------- */

async function galleryPage(env, url, lang) {
  var t = STR[lang];
  var u = new URL(url);
  var page = parseInt(u.searchParams.get('page') || '1', 10) || 1;

  // 精选: 全幅大图轮播 (随机顺序)
  var feat = await listByIndex(env, 'idx:featured:', 1);
  var featItems = feat.items.slice(0, 8);
  var featHtml = '';
  if (featItems.length) {
    featHtml = '<div class="sec-t"><h2>' + t.featured + '</h2></div>' + await featHeroHtml(env, featItems, lang);
  }

  // 最新: 小红书式瀑布流
  var latest = await listByIndex(env, 'idx:new:', page);
  var latestHtml = latest.items.length
    ? await masonryHtml(env, latest.items, lang) + pagerHtml('/?page=', page, latest.hasMore, t)
    : '<div class="empty">' + t.emptyHome + '</div>';

  var body =
    '<div class="hero"><h1>' + t.heroH1 + '</h1>' +
    '<p>' + t.heroP + '</p>' +
    '<form class="searchbar" action="/search" method="GET">' +
    '<input name="q" maxlength="60" placeholder="' + escapeHtml(t.searchPh) + '">' +
    '<button type="submit" style="width:auto;white-space:nowrap">' + t.searchBtn + '</button></form>' +
    '<p style="margin-top:16px"><a href="/upload"><button>' + t.shareCta + '</button></a></p></div>' +
    featHtml +
    '<div class="sec-t"><h2>' + t.latest + '</h2></div>' + latestHtml +
    '<div class="sec-t"><h2>' + t.tags + '</h2></div>' + tagCloudHtml(lang);

  return htmlPage('PromptShare - ' + t.tagline, body, lang);
}

/* ---------- 公开: 标签页 ---------- */

async function tagPage(env, url, tag, lang) {
  var t = STR[lang];
  var u = new URL(url);
  var page = parseInt(u.searchParams.get('page') || '1', 10) || 1;
  var r = await listByIndex(env, 'idx:tag:' + tag + ':', page);
  var body = '<div class="sec-t"><h2>🏷️ #' + escapeHtml(tag) + '</h2><a href="/">' + t.backHome + '</a></div>' +
    (r.items.length
      ? await masonryHtml(env, r.items, lang) + pagerHtml('/tag/' + encodeURIComponent(tag) + '?page=', page, r.hasMore, t)
      : '<div class="empty">' + t.tagEmpty + '</div>') +
    '<div class="sec-t"><h2>' + t.moreTags + '</h2></div>' + tagCloudHtml(lang);
  return htmlPage('#' + tag + ' - PromptShare', body, lang);
}

/* ---------- 公开: 搜索 ---------- */

async function searchPage(env, url, lang) {
  var t = STR[lang];
  var u = new URL(url);
  var q = (u.searchParams.get('q') || '').trim().slice(0, 60);
  var body = '<div class="sec-t"><h2>' + t.searchTitle + '</h2><a href="/">' + t.backHome + '</a></div>' +
    '<form class="searchbar" action="/search" method="GET" style="margin:0 0 20px">' +
    '<input name="q" maxlength="60" placeholder="' + escapeHtml(t.searchPh) + '" value="' + escapeHtml(q) + '">' +
    '<button type="submit" style="width:auto;white-space:nowrap">' + t.searchBtn + '</button></form>';

  if (q) {
    var r = await env.SHARE.list({ prefix: 'idx:new:', limit: SEARCH_SCAN });
    var keys = r.keys.map(function (k) { return k.name; });
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
        var hay = ((m.title || '') + ' ' + (m.tags || []).join(' ') + ' ' +
          (m.prompt_zh || '') + ' ' + (m.prompt_en || '') + ' ' + (m.prompt || '')).toLowerCase();
        if (hay.indexOf(ql) >= 0) hits.push(m);
      }
    }
    body += hits.length
      ? '<p class="hint">' + t.foundN.replace('{n}', hits.length).replace('{s}', SEARCH_SCAN) + '</p>' + await masonryHtml(env, hits, lang)
      : '<div class="empty">' + t.notFoundQ + '</div>';
  } else {
    body += '<div class="hint">' + t.searchHint + '</div>' + tagCloudHtml(lang);
  }
  return htmlPage(t.searchTitle + (q ? ' ' + q : '') + ' - PromptShare', body, lang);
}

/* ---------- 公开: 分享详情 ---------- */

async function sharePage(env, id, lang, email, isAdm) {
  var t = STR[lang];
  var raw = await env.SHARE.get('s:' + id);
  if (!raw) {
    return htmlPage(t.untitled,
      '<div class="empty"><h2>' + t.notFound + '</h2><p><a href="/">' + t.backHomeLink + '</a></p></div>', lang);
  }
  var meta = JSON.parse(raw);
  var imgs = imgList(meta);
  var imgUrls = [];
  for (var hi = 0; hi < imgs.length; hi++) imgUrls.push(await signedImgUrl(env, id, imgs[hi].seq));
  var dslides = imgUrls.map(function (u, i) {
    return '<div class="dslide" onclick="zoomChk(' + i + ')"><div class="dbg" style="background-image:url(\'' + u + '\')"></div>' +
      '<img src="' + u + '" alt="分享图片" draggable="false"></div>';
  }).join('');
  var carHtml =
    '<div class="dcar" id="dcar"><div class="dtrack" id="dtrack">' + dslides + '</div>' +
    (imgUrls.length > 1 ?
      '<button class="cnav prev" onclick="event.stopPropagation();dgo(di-1)" aria-label="prev">‹</button>' +
      '<button class="cnav next" onclick="event.stopPropagation();dgo(di+1)" aria-label="next">›</button>' +
      '<div class="cdots" id="ddots"></div><div class="ccount" id="dcount"></div>'
      : '') +
    '</div>' +
    '<div class="lbox" id="lbox"><button class="lx" onclick="closeLb()">✕</button>' +
    '<button class="cnav prev" onclick="event.stopPropagation();lgo(li-1)" aria-label="prev">‹</button>' +
    '<button class="cnav next" onclick="event.stopPropagation();lgo(li+1)" aria-label="next">›</button>' +
    '<img id="lbimg" alt="大图" draggable="false"><div class="ccount" id="lcount"></div></div>' +
    '<script>' +
    'var DIMGS=' + JSON.stringify(imgUrls) + ';var di=0,li=0;' +
    'function dgo(n){di=(n+DIMGS.length)%DIMGS.length;' +
    'document.getElementById("dtrack").style.transform="translateX(-"+(di*100)+"%)";' +
    'var ds=document.querySelectorAll("#ddots i");for(var i=0;i<ds.length;i++)ds[i].className=i===di?"on":"";' +
    'var c=document.getElementById("dcount");if(c)c.textContent=(di+1)+"/"+DIMGS.length;}' +
    'function zoomChk(i){if(Date.now()-(window.__swp||0)<400)return;openLb(i);}' +
    'function openLb(i){li=i;document.getElementById("lbox").classList.add("open");lshow();}' +
    'function lshow(){document.getElementById("lbimg").src=DIMGS[li];' +
    'var c=document.getElementById("lcount");if(c)c.textContent=(li+1)+"/"+DIMGS.length;}' +
    'function lgo(n){li=(n+DIMGS.length)%DIMGS.length;lshow();}' +
    'function closeLb(){document.getElementById("lbox").classList.remove("open");}' +
    '(function(){var dt=document.getElementById("ddots");' +
    'if(dt){for(var d=0;d<DIMGS.length;d++){var el=document.createElement("i");if(d===0)el.className="on";dt.appendChild(el);}}' +
    'dgo(0);' +
    'function swipe(elm,fn){var x0=null;' +
    'elm.addEventListener("touchstart",function(e){x0=e.touches[0].clientX;},{passive:true});' +
    'elm.addEventListener("touchend",function(e){if(x0===null)return;' +
    'var dx=e.changedTouches[0].clientX-x0;if(Math.abs(dx)>40){window.__swp=Date.now();fn(dx<0?1:-1);}x0=null;},{passive:true});}' +
    'swipe(document.getElementById("dcar"),function(d){dgo(di+d);});' +
    'swipe(document.getElementById("lbox"),function(d){lgo(li+d);});' +
    'document.getElementById("lbox").addEventListener("click",function(e){if(e.target===this)closeLb();});' +
    'document.addEventListener("keydown",function(e){' +
    'var open=document.getElementById("lbox").classList.contains("open");' +
    'if(e.key==="Escape"&&open)closeLb();' +
    'else if(e.key==="ArrowRight"){if(open)lgo(li+1);else dgo(di+1);}' +
    'else if(e.key==="ArrowLeft"){if(open)lgo(li-1);else dgo(di-1);}});' +
    '})();</script>';
  var title = meta.title || t.untitled;
  var prompt = promptFor(meta, lang);
  var canEd = isAdm || canEdit(env, email, meta);
  var tags = (meta.tags || []).map(function (t2) {
    return '<a href="/tag/' + encodeURIComponent(t2) + '">#' + escapeHtml(t2) + '</a>';
  }).join(' ');

  // 若另一语言版本存在, 给一个就近切换入口
  var otherLink = '';
  if (lang === 'zh' && meta.prompt_en) {
    otherLink = ' <a href="?lang=en" class="hint">' + t.viewOther + '</a>';
  } else if (lang === 'en' && (meta.prompt_zh || (!meta.prompt_en && meta.prompt))) {
    otherLink = ' <a href="?lang=zh" class="hint">' + t.viewOtherZh + '</a>';
  }

  return htmlPage(title + ' - PromptShare',
    '<p class="hint"><a href="/">' + t.backHome + '</a></p>' +
    '<h2 style="margin:6px 0">🖼️ ' + escapeHtml(title) + '</h2>' +
    '<p><span class="badge">' + escapeHtml(meta.author || meta.owner || '?') + '</span>' +
    '<span class="hint">' + fmtDate(meta.createdAt, lang) + ' ' + t.sharedBy + '</span></p>' +
    (tags ? '<p>' + tags + '</p>' : '') +
    '<div class="card" style="padding:12px">' + carHtml + '</div>' +
    '<div class="card"><div class="hint">' + t.promptLabel + ' ' +
    '<button style="padding:4px 14px;font-size:13px" onclick="copyP()">' + t.copyPrompt + '</button>' + otherLink + '</div>' +
    '<pre id="p">' + escapeHtml(prompt) + '</pre>' +
    '<p class="hint">' + t.imgExpiry.replace('{h}', Math.round(SIG_TTL_SEC / 3600)) + '</p></div>' +
    '<p><a href="/upload"><button>' + t.shareCta2 + '</button></a>' +
    (canEd ? ' <a href="/edit/' + escapeHtml(id) + '"><button>' + t.edit + '</button></a>' : '') +
    (isAdm ? ' <button class="danger" id="delbtn" onclick="delShare()">' + t.delShare + '</button>' : '') + '</p>' +
    '<script>' +
    (isAdm ?
    'var SID=' + JSON.stringify(id) + ';' +
    'var DEL_TXT=' + JSON.stringify(t.delShare) + ';' +
    'var DEL_SURE=' + JSON.stringify(t.delSure) + ';' +
    'var MSG_DEL=' + JSON.stringify(t.deletedMsg) + ';' +
    'var delArm=false,delTimer=null;' +
    'function delShare(){' +
    'var b=document.getElementById("delbtn");' +
    'if(!delArm){delArm=true;b.textContent=DEL_SURE;' +
    'delTimer=setTimeout(function(){delArm=false;var b2=document.getElementById("delbtn");if(b2)b2.textContent=DEL_TXT;},6000);return;}' +
    'if(delTimer)clearTimeout(delTimer);delArm=false;' +
    'b.disabled=true;b.textContent=MSG_DEL+"…";' +
    'fetch("/api/admin/delete",{method:"POST",headers:{"content-type":"application/json"},' +
    'body:JSON.stringify({id:SID})}).then(function(r){return r.json();})' +
    '.then(function(d){if(d.ok){alert(MSG_DEL);location.href="/";}else{alert(d.error||"fail");b.disabled=false;b.textContent=DEL_TXT;}})' +
    '.catch(function(e){alert(String(e));b.disabled=false;b.textContent=DEL_TXT;});}'
    : '') +
    'var PT=' + JSON.stringify(prompt).replace(/<\//g, '<\\/') + ';' +
    'var MSG_OK=' + JSON.stringify(t.copiedPrompt) + ';' +
    'var MSG_FAIL=' + JSON.stringify(t.copyFail) + ';' +
    'function copyP(){' +
    'function done(){alert(MSG_OK);}' +
    'if(navigator.clipboard&&navigator.clipboard.writeText){' +
    'navigator.clipboard.writeText(PT).then(done).catch(function(){fallback();});}else{fallback();}' +
    'function fallback(){var t2=document.createElement("textarea");t2.value=PT;' +
    'document.body.appendChild(t2);t2.select();try{document.execCommand("copy");done();}' +
    'catch(e){alert(MSG_FAIL);}document.body.removeChild(t2);}}' +
    '</script>',
    lang,
    (prompt || '').slice(0, 120));
}

/* ---------- 公开: 图片代理 (签名+防盗链+缓存+限流) ---------- */

async function serveImage(env, req, id, seq, url, lang) {
  var t = STR[lang];
  var u = new URL(url);
  var exp = parseInt(u.searchParams.get('exp') || '0', 10);
  var sig = u.searchParams.get('sig') || '';
  if (!exp || exp < Math.floor(Date.now() / 1000)) {
    return new Response(t.imgExpired, { status: 403 });
  }
  seq = seq || '';
  var base = seq ? id + '.' + seq : id;
  var expect = await hmacSign(env.SIGN_SECRET, base + '.' + exp);
  if (!timingSafeEqual(sig, expect)) {
    return new Response(t.imgBadSig, { status: 403 });
  }

  var ref = req.headers.get('Referer') || req.headers.get('Origin') || '';
  if (ref) {
    var refHost = '';
    try { refHost = new URL(ref).host; } catch (e) {}
    if (refHost !== u.host) return new Response(t.imgNoRef, { status: 403 });
  }

  if (await hitLimit(env, 'img:' + clientIp(req), IMG_LIMIT_PER_MIN, 60)) {
    return new Response(t.imgFreq, { status: 429 });
  }

  var obj = await env.IMGS.get(imgR2Key(id, seq));
  if (!obj) return new Response(t.img404, { status: 404 });

  var headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('etag', obj.httpEtag);
  headers.set('cache-control', 'public, max-age=31536000, immutable');
  headers.set('content-type', obj.httpMetadata.contentType || 'image/jpeg');
  return new Response(obj.body, { headers: headers });
}

/* ---------- 登录: 上传页 ---------- */

function uploadPage(email, admin, lang) {
  var t = STR[lang];
  var note = admin ? '<p class="hint">' + t.noteAdmin + '</p>' : '<p class="hint">' + t.noteUser + '</p>';
  return htmlPage(t.upload + ' - PromptShare',
    '<h2>' + t.uploadTitle + '</h2>' +
    '<p><span class="badge">' + escapeHtml(email) + '</span>' +
    (admin ? '<span class="badge">' + t.roleAdmin + '</span>' : '<span class="badge">' + t.roleUser + '</span>') + '</p>' +
    note +
    '<div class="card">' +
    '<label class="hint">' + t.titleLabel + '</label>' +
    '<input id="title" maxlength="80" placeholder="' + escapeHtml(t.titlePh) + '">' +
    '<label class="hint">' + t.promptZhLabel + '</label>' +
    '<textarea id="pzh" placeholder="' + escapeHtml(t.promptZhPh) + '"></textarea>' +
    '<label class="hint">' + t.promptEnLabel + '</label>' +
    '<textarea id="pen" placeholder="' + escapeHtml(t.promptEnPh) + '"></textarea>' +
    '<p class="hint">' + t.promptHint + '</p>' +
    '<label class="hint">' + t.tagsLabel + '</label>' +
    '<input id="tags" maxlength="120" placeholder="' + escapeHtml(t.tagsPh) + '">' +
    '<label class="hint">' + t.imgsLabel + '</label>' +
    '<input id="file" type="file" accept="image/*" multiple>' +
    (admin ? '<p><label class="hint"><input id="featured" type="checkbox" style="width:auto"> ' + t.featuredLabel + '</label></p>' : '') +
    '<p><button id="btn" onclick="go()">' + t.submit + '</button></p>' +
    '<p id="msg" class="hint"></p><div id="out"></div></div>' +
    '<script>' +
    'var E_NOIMG=' + JSON.stringify(t.errNoImg) + ';' +
    'var E_NOPROMPT=' + JSON.stringify(t.errNoPrompt) + ';' +
    'var E_UPLOAD=' + JSON.stringify(t.errUpload) + ';' +
    'var E_TOOBIG=' + JSON.stringify(t.errTooBig) + ';' +
    'var E_TOTALBIG=' + JSON.stringify(t.errTotalBig) + ';' +
    'var E_NET=' + JSON.stringify(t.errNet) + ';' +
    'var E_TIMEOUT=' + JSON.stringify(t.errTimeout) + ';' +
    'var T_UPLOADING=' + JSON.stringify(t.uploading) + ';' +
    'var T_OKP=' + JSON.stringify(t.okPending) + ';' +
    'var T_OKL=' + JSON.stringify(t.okLive) + ';' +
    'var T_LINK=' + JSON.stringify(t.shareLink) + ';' +
    'var T_COPYL=' + JSON.stringify(t.copyLink) + ';' +
    'var T_COPIED=' + JSON.stringify(t.copied) + ';' +
    'async function go(){' +
    'var fs=document.getElementById("file").files;' +
    'var pz=document.getElementById("pzh").value.trim();' +
    'var pe=document.getElementById("pen").value.trim();' +
    'var msg=document.getElementById("msg"),out=document.getElementById("out");' +
    'if(!fs.length){msg.innerHTML="<span class=err>"+E_NOIMG+"</span>";return;}' +
    'if(fs.length>8){msg.innerHTML="<span class=err>"+E_IMGCOUNT+"</span>";return;}' +
    'if(!pz&&!pe){msg.innerHTML="<span class=err>"+E_NOPROMPT+"</span>";return;}' +
    'var total=0,si;for(si=0;si<fs.length;si++){if(fs[si].size>10485760){msg.innerHTML="<span class=err>"+E_TOOBIG+"</span>";return;}total+=fs[si].size;}' +
    'if(total>62914560){msg.innerHTML="<span class=err>"+E_TOTALBIG+"</span>";return;}' +
    'msg.textContent=T_UPLOADING;out.innerHTML="";' +
    'var fd=new FormData();' +
    'for(var i=0;i<fs.length;i++)fd.append("images",fs[i]);' +
    'fd.append("prompt_zh",pz);fd.append("prompt_en",pe);' +
    'fd.append("title",document.getElementById("title").value.trim());' +
    'fd.append("tags",document.getElementById("tags").value.trim());' +
    'var fc=document.getElementById("featured");if(fc&&fc.checked)fd.append("featured","1");' +
    'var ctl=new AbortController();var tm=setTimeout(function(){ctl.abort();},180000);' +
    'try{' +
    'var r=await fetch("/api/upload",{method:"POST",body:fd,signal:ctl.signal});' +
    'clearTimeout(tm);' +
    'var d=await r.json();' +
    'if(!d.ok){msg.innerHTML="<span class=err>"+d.error+"</span>";return;}' +
    'if(d.pending){msg.innerHTML="<span class=ok>"+T_OKP+"</span>";return;}' +
    'msg.innerHTML="<span class=ok>"+T_OKL+"</span>";' +
    'out.innerHTML="<div class=card><div class=hint>"+T_LINK+"</div><p><a href="+d.url+">"+d.url+"</a></p>" +' +
    '"<button onclick=\\"navigator.clipboard.writeText(\\""+d.url+"\\").then(()=>alert(\\""+T_COPIED+"\\"))\\">"+T_COPYL+"</button>";' +
    '}catch(e){clearTimeout(tm);var em=E_NET;if(e&&e.name==="AbortError")em=E_TIMEOUT;' +
    'else if(e&&/failed to fetch|networkerror/i.test(String(e&&e.message||e)))em=E_NET;' +
    'else em=E_UPLOAD+String(e);msg.innerHTML="<span class=err>"+em+"</span>";}' +
    '}' +
    '</script>', lang);
}

/* ---------- 登录: 我的作品 ---------- */

function canEdit(env, email, meta) {
  if (!email || !meta) return false;
  if (isAdmin(env, email)) return true;
  return String(meta.owner || '').toLowerCase() === String(email).toLowerCase();
}

/* 编辑页: 标题/中英提示词/标签可改, 图片可加可删 (作者或管理员) */
async function editPage(env, id, email, lang) {
  var t = STR[lang];
  var raw = await env.SHARE.get('s:' + id);
  if (!raw) {
    return htmlPage(t.untitled,
      '<div class="empty"><h2>' + t.notFound + '</h2><p><a href="/">' + t.backHomeLink + '</a></p></div>', lang);
  }
  var meta = JSON.parse(raw);
  if (!canEdit(env, email, meta)) return new Response(t.eNotOwner, { status: 403 });
  var imgs = imgList(meta);
  var thumbs = '';
  for (var ti = 0; ti < imgs.length; ti++) {
    var turl = await signedImgUrl(env, id, imgs[ti].seq);
    thumbs += '<label style="display:inline-block;text-align:center;margin:0 10px 10px 0;cursor:pointer">' +
      '<img src="' + turl + '" style="width:120px;height:120px;object-fit:cover;border-radius:8px;display:block">' +
      '<span class="hint"><input type="checkbox" class="delcb" value="' + escapeHtml(imgs[ti].seq) + '" style="width:auto"> ' + t.delOne + '</span></label>';
  }
  var canAdd = MAX_IMGS - imgs.length;
  return htmlPage(t.editTitle + ' - PromptShare',
    '<p class="hint"><a href="/f/' + escapeHtml(id) + '">' + t.backToShare + '</a></p>' +
    '<h2>' + t.editTitle + '</h2>' +
    '<div class="card"><p class="hint">' + t.curImgs + '</p>' + thumbs + '</div>' +
    '<div class="card">' +
    '<label class="hint">' + t.titleLabel + '</label>' +
    '<input id="title" maxlength="80" value="' + escapeHtml(meta.title || '') + '">' +
    '<label class="hint">' + t.promptZhLabel + '</label>' +
    '<textarea id="pzh">' + escapeHtml(meta.prompt_zh || meta.prompt || '') + '</textarea>' +
    '<label class="hint">' + t.promptEnLabel + '</label>' +
    '<textarea id="pen">' + escapeHtml(meta.prompt_en || '') + '</textarea>' +
    '<p class="hint">' + t.promptHint + '</p>' +
    '<label class="hint">' + t.tagsLabel + '</label>' +
    '<input id="tags" maxlength="120" value="' + escapeHtml((meta.tags || []).join(' ')) + '">' +
    '<label class="hint">' + t.addImgs + '</label>' +
    '<input id="file" type="file" accept="image/*" multiple>' +
    '<p class="hint">' + t.imgsLeft.replace('{n}', canAdd) + '</p>' +
    '<p><button id="btn" onclick="go()">' + t.save + '</button></p>' +
    '<p id="msg" class="hint"></p></div>' +
    '<script>' +
    'var SID=' + JSON.stringify(id) + ';' +
    'var E_NOPROMPT=' + JSON.stringify(t.errNoPrompt) + ';' +
    'var E_UPLOAD=' + JSON.stringify(t.errUpload) + ';' +
    'var E_TOOBIG=' + JSON.stringify(t.errTooBig) + ';' +
    'var E_TOTALBIG=' + JSON.stringify(t.errTotalBig) + ';' +
    'var E_NET=' + JSON.stringify(t.errNet) + ';' +
    'var E_TIMEOUT=' + JSON.stringify(t.errTimeout) + ';' +
    'var T_UPLOADING=' + JSON.stringify(t.uploading) + ';' +
    'var T_SAVED=' + JSON.stringify(t.saved) + ';' +
    'async function go(){' +
    'var pz=document.getElementById("pzh").value.trim();' +
    'var pe=document.getElementById("pen").value.trim();' +
    'var msg=document.getElementById("msg");' +
    'if(!pz&&!pe){msg.innerHTML="<span class=err>"+E_NOPROMPT+"</span>";return;}' +
    'var fs=document.getElementById("file").files;' +
    'var total=0,fi;for(fi=0;fi<fs.length;fi++){if(fs[fi].size>10485760){msg.innerHTML="<span class=err>"+E_TOOBIG+"</span>";return;}total+=fs[fi].size;}' +
    'if(total>62914560){msg.innerHTML="<span class=err>"+E_TOTALBIG+"</span>";return;}' +
    'var cbs=document.querySelectorAll(".delcb");' +
    'var del=[];for(var i=0;i<cbs.length;i++)if(cbs[i].checked)del.push(cbs[i].value);' +
    'var keep=cbs.length-del.length;' +
    'if(keep+fs.length>8){msg.innerHTML="<span class=err>"+E_IMGCOUNT+"</span>";return;}' +
    'msg.textContent=T_UPLOADING;' +
    'var fd=new FormData();fd.append("id",SID);' +
    'for(var k=0;k<del.length;k++)fd.append("delSeq",del[k]);' +
    'for(var j=0;j<fs.length;j++)fd.append("images",fs[j]);' +
    'fd.append("prompt_zh",pz);fd.append("prompt_en",pe);' +
    'fd.append("title",document.getElementById("title").value.trim());' +
    'fd.append("tags",document.getElementById("tags").value.trim());' +
    'var ctl=new AbortController();var tm=setTimeout(function(){ctl.abort();},180000);' +
    'try{' +
    'var r=await fetch("/api/edit",{method:"POST",body:fd,signal:ctl.signal});' +
    'clearTimeout(tm);' +
    'var d=await r.json();' +
    'if(!d.ok){msg.innerHTML="<span class=err>"+(d.error||"fail")+"</span>";return;}' +
    'msg.innerHTML="<span class=ok>"+T_SAVED+"</span>";' +
    'setTimeout(function(){location.href="/f/"+SID;},800);' +
    '}catch(e){clearTimeout(tm);var em=E_NET;if(e&&e.name==="AbortError")em=E_TIMEOUT;' +
    'else if(e&&/failed to fetch|networkerror/i.test(String(e&&e.message||e)))em=E_NET;' +
    'else em=E_UPLOAD+String(e);msg.innerHTML="<span class=err>"+em+"</span>";}' +
    '}' +
    '</script>', lang);
}

async function minePage(env, email, lang) {
  var t = STR[lang];
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

  var body = '<h2>' + t.myTitle + '</h2><p><span class="badge">' + escapeHtml(email) + '</span></p>';

  body += '<div class="sec-t"><h2>' + t.pending + ' (' + pends.length + ')</h2></div>';
  if (pends.length) {
    // 待审条目尚未上架, 不链到 /f/, 只做静态展示
    body += '<div class="grid">';
    for (var i = 0; i < pends.length; i++) {
      var pm = pends[i];
      var pimg = await signedImgUrl(env, pm.id);
      var ptags = (pm.tags || []).map(function (x) { return '#' + escapeHtml(x); }).join(' ');
      body += '<div class="card-item"><div class="thumb"><img loading="lazy" src="' + pimg + '"></div>' +
        '<div class="cmeta"><div class="ct">' + escapeHtml(pm.title || t.untitled) + '</div>' +
        '<div class="csub"><span class="badge warn">' + t.badgePending + '</span>' + fmtDate(pm.createdAt, lang) + '</div>' +
        (ptags ? '<div class="ctags">' + ptags + '</div>' : '') + '</div></div>';
    }
    body += '</div>';
  } else {
    body += '<p class="hint">' + t.nonePending + '</p>';
  }

  body += '<div class="sec-t"><h2>' + t.published + ' (' + pubItems.length + ')</h2></div>';
  if (pubItems.length) {
    body += '<div class="grid">';
    for (var gi = 0; gi < pubItems.length; gi++) {
      var gm = pubItems[gi];
      body += '<div>' + cardHtml(await signedImgUrl(env, gm.id), gm, lang) +
        '<p style="margin:6px 0"><a href="/edit/' + escapeHtml(gm.id) + '">' + t.edit + '</a></p></div>';
    }
    body += '</div>';
  } else {
    body += '<p class="hint">' + t.noPub + '</p>';
  }

  return htmlPage(t.mine + ' - PromptShare', body, lang);
}

/* ---------- 管理员: 审核 + 精选管理 ---------- */

function promptPreviewHtml(meta, lang) {
  // 审核卡片里中英都展示, 方便管理员一眼看全
  var zh = escapeHtml(meta.prompt_zh || meta.prompt || '');
  var en = escapeHtml(meta.prompt_en || '');
  var h = '<pre>' + zh + '</pre>';
  if (en && en !== zh) h += '<pre>' + en + '</pre>';
  return h;
}

async function adminPage(env, lang) {
  var t = STR[lang];
  var list = await env.SHARE.list({ prefix: 'pending:' });
  var cards = '';
  for (var i = 0; i < list.keys.length; i++) {
    var raw = await env.SHARE.get(list.keys[i].name);
    if (!raw) continue;
    var m = JSON.parse(raw);
    var id = list.keys[i].name.slice('pending:'.length);
    var imgUrl = await signedImgUrl(env, id);
    var tags = (m.tags || []).map(function (x) { return '#' + escapeHtml(x); }).join(' ');
    cards += '<div class="card">' +
      '<p><span class="badge">' + escapeHtml(m.owner || '?') + '</span>' +
      '<span class="hint">' + fmtDate(m.createdAt, lang) + '</span></p>' +
      '<p><b>' + escapeHtml(m.title || t.untitled) + '</b></p>' +
      (tags ? '<p class="hint">' + tags + '</p>' : '') +
      '<img class="full" src="' + imgUrl + '" style="max-height:320px;width:auto">' +
      promptPreviewHtml(m, lang) +
      '<button class="okbtn" onclick="audit(\'' + id + '\',\'approve\',false)">' + t.approve + '</button>' +
      '<button class="okbtn" onclick="audit(\'' + id + '\',\'approve\',true)">' + t.approveFeat + '</button>' +
      '<button class="danger" onclick="audit(\'' + id + '\',\'reject\')">' + t.reject + '</button>' +
      '</div>';
  }
  if (!cards) cards = '<p class="hint">' + t.noPendingAdmin + '</p>';

  // 精选管理
  var feat = await listByIndex(env, 'idx:featured:', 1);
  var featItems = feat.items.slice(0, 50);
  var featCards = '';
  for (var k = 0; k < featItems.length; k++) {
    var fm = featItems[k];
    featCards += '<div class="card" style="display:flex;gap:14px;align-items:center">' +
      '<a href="/f/' + escapeHtml(fm.id) + '"><img src="' + await signedImgUrl(env, fm.id) +
      '" style="width:90px;height:90px;object-fit:cover;border-radius:8px"></a>' +
      '<div style="flex:1"><b>' + escapeHtml(fm.title || t.untitled) + '</b>' +
      '<div class="hint">by ' + escapeHtml(fm.author || fm.owner || '?') + '</div></div>' +
      '<button class="ghost" onclick="audit(\'' + fm.id + '\',\'unfeature\')">' + t.unfeature + '</button></div>';
  }
  if (!featCards) featCards = '<p class="hint">' + t.noFeat + '</p>';

  return htmlPage(t.admin + ' - PromptShare',
    '<div class="sec-t"><h2>' + t.reviewTitle + ' (' + list.keys.length + ')</h2><a href="/">' + t.backHome + '</a></div>' +
    '<div class="card"><b>' + t.maint + '</b> <span class="hint">' + t.maintHint + '</span> ' +
    '<button class="btn" id="reindex" style="width:auto;padding:8px 16px">' + t.reindexBtn + '</button> <span id="remsg" class="hint"></span></div>' +
    cards +
    '<div class="sec-t"><h2>' + t.featTitle + ' (' + featItems.length + ')</h2></div>' +
    featCards +
    '<script>' +
    'var CF_AF=' + JSON.stringify(t.cfApproveFeat) + ';' +
    'var CF_A=' + JSON.stringify(t.cfApprove) + ';' +
    'var CF_UF=' + JSON.stringify(t.cfUnfeature) + ';' +
    'var CF_RJ=' + JSON.stringify(t.cfReject) + ';' +
    'var T_WORKING=' + JSON.stringify(t.working) + ';' +
    'var T_DONE=' + JSON.stringify(t.reindexed) + ';' +
    'var T_FAIL=' + JSON.stringify(t.failed) + ';' +
    'async function audit(id, act, featured){' +
    'var tip = act==="approve" ? (featured?CF_AF:CF_A) : (act==="unfeature"?CF_UF:CF_RJ);' +
    'if(!confirm(tip))return;' +
    'var r=await fetch("/api/review",{method:"POST",' +
    'headers:{"content-type":"application/json"},' +
    'body:JSON.stringify({id:id,action:act,featured:!!featured})});' +
    'var d=await r.json();' +
    'if(d.ok){location.reload();}else{alert(d.error||"fail");}' +
    '}' +
    'document.getElementById("reindex").onclick=async()=>{' +
    'var m=document.getElementById("remsg");m.textContent=T_WORKING;' +
    'try{var r=await fetch("/api/admin/reindex",{method:"POST"});var d=await r.json();' +
    'if(d.ok){var s=T_DONE.replace("{n}",d.reindexed.length);if(d.skipped&&d.skipped.length){s+=" [跳过: "+d.skipped.join("; ")+"]";}m.textContent=s;}else{m.textContent=T_FAIL+(d.error||r.status);}}' +
    'catch(e){m.textContent=T_FAIL+e;}};' +
    '</script>', lang);
}

/* ---------- API: 上传 ---------- */

async function apiUpload(env, req, url, lang) {
  var t = STR[lang];
  var email = await accessEmail(req, env);
  if (!email) return json({ ok: false, error: t.eLogin }, 401);

  if (await hitLimit(env, 'up:' + clientIp(req), UPLOAD_LIMIT_PER_HOUR, 3600)) {
    return json({ ok: false, error: t.eFreq }, 429);
  }

  var form;
  try { form = await req.formData(); }
  catch (e) { return json({ ok: false, error: t.eForm }, 400); }

  // 多图: 优先取 'images' (多选), 兼容老客户端单 'image' 字段
  var files = [];
  try {
    var all = form.getAll('images');
    for (var fi = 0; fi < all.length; fi++) {
      var af = all[fi];
      if (af && typeof af.arrayBuffer === 'function' && af.size > 0) files.push(af);
    }
  } catch (e) {}
  var single = form.get('image');
  if (!files.length && single && typeof single.arrayBuffer === 'function' && single.size > 0) {
    files.push(single);
  }
  // prompt_zh / prompt_en 双字段; 兼容老客户端的 prompt 单字段
  var pzh = String(form.get('prompt_zh') || form.get('prompt') || '').trim().slice(0, 20000);
  var pen = String(form.get('prompt_en') || '').trim().slice(0, 20000);
  var title = String(form.get('title') || '').trim().slice(0, 80);
  var tags = sanitizeTags(form.get('tags'));
  var wantFeatured = String(form.get('featured') || '') === '1';

  if (!files.length) {
    return json({ ok: false, error: t.eNoFile }, 400);
  }
  if (files.length > MAX_IMGS) return json({ ok: false, error: t.eImgCount }, 400);
  if (!pzh && !pen) return json({ ok: false, error: t.eNoPrompt }, 400);
  for (var vi = 0; vi < files.length; vi++) {
    if (files[vi].size > MAX_IMG_BYTES) return json({ ok: false, error: t.eBig }, 413);
    if (!/^image\//.test(files[vi].type || '')) return json({ ok: false, error: t.eImgOnly }, 400);
  }

  var admin = isAdmin(env, email);
  var id = newId();
  // 第 0 张为封面, 存 'img:<id>'; 其余存 'img:<id>:<seq>'
  var images = [];
  var puts = [];
  for (var pi = 0; pi < files.length; pi++) {
    (function (f, n) {
      puts.push(f.arrayBuffer().then(function (buf) {
        var key = n === 0 ? 'img:' + id : 'img:' + id + ':' + (n - 1);
        images[n] = { seq: n === 0 ? '' : String(n - 1), ct: f.type || 'image/jpeg', size: f.size };
        return env.IMGS.put(key, buf, { httpMetadata: { contentType: f.type || 'image/jpeg' } });
      }));
    })(files[pi], pi);
  }
  await Promise.all(puts);

  var meta = {
    id: id, title: title,
    prompt: pzh || pen, prompt_zh: pzh, prompt_en: pen,
    tags: tags,
    images: images, imgSeq: files.length - 1,
    contentType: images[0].ct, size: images[0].size,
    owner: email, author: email.split('@')[0],
    featured: admin && wantFeatured, createdAt: Date.now()
  };

  if (admin) {
    await env.SHARE.put('s:' + id, JSON.stringify(meta));
    await indexPublish(env, meta);
    var host = new URL(url).host;
    return json({ ok: true, id: id, url: 'https://' + host + '/f/' + id });
  }
  await env.SHARE.put('pending:' + id, JSON.stringify(meta), { expirationTtl: 30 * 86400 });
  return json({ ok: true, pending: true, msg: 'pending review' });
}

/* 纯函数: 根据当前图片 seq 列表 / 删除列表 / 新增数量, 算出图片变更计划 (可单元测试)
   返回 {error} 或 {del, keep, delCover, promoteSeq, addedSeqs, finalSeqs, nextImgSeq}。
   约定: 封面 seq 为 '', 对应 R2 key 'img:<id>'; 其余为 'img:<id>:<seq>'。 */
function planImages(curSeqs, delSeqs, newCount, imgSeqMeta) {
  var del = (delSeqs || []).filter(function (s) { return curSeqs.indexOf(s) !== -1; });
  del = del.filter(function (s, i) { return del.indexOf(s) === i; });
  var keep = curSeqs.filter(function (s) { return del.indexOf(s) === -1; });
  if (!keep.length) return { error: 'keepOne' };
  if (keep.length + newCount > MAX_IMGS) return { error: 'tooMany' };
  var delCover = del.indexOf('') !== -1;
  var promoteSeq = delCover ? keep[0] : null;
  var imgSeq = imgSeqMeta || 0;
  if (!imgSeqMeta) {
    for (var q = 0; q < curSeqs.length; q++) {
      var qn = parseInt(curSeqs[q], 10);
      if (!isNaN(qn) && qn >= imgSeq) imgSeq = qn + 1;
    }
  }
  var addedSeqs = [];
  for (var i = 0; i < newCount; i++) addedSeqs.push(String(imgSeq++));
  // 最终顺序: 封面位('') + 其余保留(原顺序, 被提上来的除外) + 新增
  var finalSeqs = [''];
  for (var k = 0; k < keep.length; k++) {
    if (keep[k] === '') continue;
    if (delCover && keep[k] === promoteSeq) continue;
    finalSeqs.push(keep[k]);
  }
  for (var a = 0; a < addedSeqs.length; a++) finalSeqs.push(addedSeqs[a]);
  return { error: null, del: del, keep: keep, delCover: delCover, promoteSeq: promoteSeq,
           addedSeqs: addedSeqs, finalSeqs: finalSeqs, nextImgSeq: imgSeq };
}

/* ---------- API: 编辑作品 (作者或管理员; createdAt 不变, 图片可加可删) ---------- */

async function apiEdit(env, req, url, lang) {
  var t = STR[lang];
  var email = await accessEmail(req, env);
  if (!email) return json({ ok: false, error: t.eLogin }, 401);

  var form;
  try { form = await req.formData(); }
  catch (e) { return json({ ok: false, error: t.eForm }, 400); }
  var id = String(form.get('id') || '');
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return json({ ok: false, error: t.eBadId }, 400);

  var raw = await env.SHARE.get('s:' + id);
  if (!raw) return json({ ok: false, error: t.eNotFound }, 404);
  var meta = JSON.parse(raw);
  if (!canEdit(env, email, meta)) return json({ ok: false, error: t.eNotOwner }, 403);

  var pzh = String(form.get('prompt_zh') || '').trim().slice(0, 20000);
  var pen = String(form.get('prompt_en') || '').trim().slice(0, 20000);
  var title = String(form.get('title') || '').trim().slice(0, 80);
  var tags = sanitizeTags(form.get('tags'));
  if (!pzh && !pen) return json({ ok: false, error: t.eNoPrompt }, 400);

  // ---- 图片: 加图 / 删一张或多张 (至少保留 1 张, 最多 MAX_IMGS 张) ----
  var cur = imgList(meta);
  var curSeqs = cur.map(function (x) { return x.seq; });
  var delSeqs = form.getAll('delSeq').map(function (s) { return String(s).trim(); });

  var newFiles = [];
  try {
    var nfAll = form.getAll('images');
    for (var nfi = 0; nfi < nfAll.length; nfi++) {
      var nf = nfAll[nfi];
      if (nf && typeof nf.arrayBuffer === 'function' && nf.size > 0) newFiles.push(nf);
    }
  } catch (e) {}
  var nsingle = form.get('image');
  if (!newFiles.length && nsingle && typeof nsingle.arrayBuffer === 'function' && nsingle.size > 0) {
    newFiles.push(nsingle);
  }
  for (var nvi = 0; nvi < newFiles.length; nvi++) {
    if (newFiles[nvi].size > MAX_IMG_BYTES) return json({ ok: false, error: t.eBig }, 413);
    if (!/^image\//.test(newFiles[nvi].type || '')) return json({ ok: false, error: t.eImgOnly }, 400);
  }

  var plan = planImages(curSeqs, delSeqs, newFiles.length, meta.imgSeq);
  if (plan.error === 'keepOne') return json({ ok: false, error: t.eKeepOne }, 400);
  if (plan.error === 'tooMany') return json({ ok: false, error: t.eImgCount }, 400);

  var bySeq = {};
  for (var bsi = 0; bsi < cur.length; bsi++) bySeq[cur[bsi].seq] = cur[bsi];
  var jobs = [];
  var coverEntry = null;
  if (plan.delCover) {
    // 删封面: 把保留中的第一张提上来 (R2 复制到 'img:<id>', 封面 key 恒为 img:<id>)
    var pold = bySeq[plan.promoteSeq];
    var pobj = await env.IMGS.get(imgR2Key(id, plan.promoteSeq));
    if (pobj) {
      var pbuf = await pobj.arrayBuffer();
      var pct = (pold && pold.ct) || 'image/jpeg';
      try { pct = pobj.httpMetadata.contentType || pct; } catch (e2) {}
      jobs.push(env.IMGS.put('img:' + id, pbuf, { httpMetadata: { contentType: pct } }));
      jobs.push(env.IMGS.delete(imgR2Key(id, plan.promoteSeq)));
      coverEntry = { seq: '', ct: pct, size: pbuf.byteLength };
    } else {
      // R2 里找不到候选图 (数据不一致的极端情况): 取消删除封面, 保留原封面
      plan = planImages(curSeqs, delSeqs.filter(function (s) { return s !== ''; }), newFiles.length, meta.imgSeq);
    }
  }
  for (var di = 0; di < plan.del.length; di++) {
    var ds = plan.del[di];
    if (ds === '') continue; // 封面已在上面处理 (复制覆盖, 无需删除 'img:<id>')
    jobs.push(env.IMGS.delete(imgR2Key(id, ds)));
  }
  var added = [];
  for (var ai = 0; ai < newFiles.length; ai++) {
    var afile = newFiles[ai];
    var aseq = plan.addedSeqs[ai];
    var abuf = await afile.arrayBuffer();
    jobs.push(env.IMGS.put(imgR2Key(id, aseq), abuf, {
      httpMetadata: { contentType: afile.type || 'image/jpeg' }
    }));
    added.push({ seq: aseq, ct: afile.type || 'image/jpeg', size: afile.size });
  }

  // 重建 images 数组: 按 plan.finalSeqs 顺序组装 (封面/保留/新增)
  var addedBySeq = {};
  for (var abI = 0; abI < added.length; abI++) addedBySeq[added[abI].seq] = added[abI];
  var newImages = [];
  for (var fsi = 0; fsi < plan.finalSeqs.length; fsi++) {
    var fs = plan.finalSeqs[fsi];
    if (fs === '' && coverEntry) { newImages.push(coverEntry); continue; }
    if (addedBySeq[fs]) { newImages.push(addedBySeq[fs]); continue; }
    if (bySeq[fs]) newImages.push(bySeq[fs]);
  }
  meta.images = newImages;
  meta.imgSeq = plan.nextImgSeq;
  meta.contentType = newImages[0].ct;
  meta.size = newImages[0].size;

  // 标签索引: createdAt 不变, inv 可直接复算; 只删减/新增差异部分
  var inv = invTs(meta.createdAt);
  var oldTags = meta.tags || [];
  for (var i = 0; i < oldTags.length; i++) {
    if (tags.indexOf(oldTags[i]) === -1)
      jobs.push(env.SHARE.delete('idx:tag:' + oldTags[i] + ':' + inv + ':' + id));
  }
  for (var j = 0; j < tags.length; j++) {
    if (oldTags.indexOf(tags[j]) === -1)
      jobs.push(env.SHARE.put('idx:tag:' + tags[j] + ':' + inv + ':' + id, id));
  }

  meta.title = title;
  meta.prompt_zh = pzh;
  meta.prompt_en = pen;
  meta.prompt = pzh || pen;
  meta.tags = tags;
  meta.updatedAt = Date.now();
  jobs.push(env.SHARE.put('s:' + id, JSON.stringify(meta)));
  await Promise.all(jobs);
  return json({ ok: true, id: id });
}

/* ---------- API: 审核 ---------- */

async function apiReview(env, req, lang) {
  var t = STR[lang];
  var email = await accessEmail(req, env);
  if (!email || !isAdmin(env, email)) {
    return json({ ok: false, error: t.eForbidden }, 403);
  }
  var body;
  try { body = await req.json(); } catch (e) { return json({ ok: false, error: t.eBadParam }, 400); }
  var id = String(body.id || '');
  var action = String(body.action || '');
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return json({ ok: false, error: t.eBadId }, 400);

  if (action === 'approve' || action === 'reject') {
    var raw = await env.SHARE.get('pending:' + id);
    if (!raw) return json({ ok: false, error: t.eNotPending }, 404);
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
    if (!sraw) return json({ ok: false, error: t.eNotFound }, 404);
    await unfeature(env, JSON.parse(sraw));
    return json({ ok: true });
  }

  return json({ ok: false, error: t.eUnknown }, 400);
}

/* 管理员删除作品: KV 主记录 + 待审(若有) + R2 图片 + 全部索引 (仅管理员, 幂等) */
async function apiDelete(env, req, lang) {
  var t = STR[lang];
  var em = await accessEmail(req, env);
  if (!isAdmin(env, em)) return json({ ok: false, error: t.eAdminOnly }, 403);
  var body;
  try { body = await req.json(); } catch (e) { return json({ ok: false, error: t.eBadParam }, 400); }
  var id = String(body.id || '');
  if (!/^[A-Za-z0-9]{10}$/.test(id)) return json({ ok: false, error: t.eBadId }, 400);

  var meta = null;
  try { meta = await env.SHARE.get('s:' + id, 'json'); } catch (e) {}

  if (meta) {
    // 索引 key 可按规则直接构造, 无需全表扫描
    var inv = invTs(meta.createdAt);
    var jobs = [
      env.SHARE.delete('idx:new:' + inv + ':' + id),
      env.SHARE.delete('idx:user:' + String(meta.owner || '').toLowerCase() + ':' + inv + ':' + id),
      env.SHARE.delete('idx:featured:' + inv + ':' + id)
    ];
    var tags = meta.tags || [];
    for (var i = 0; i < tags.length; i++) {
      jobs.push(env.SHARE.delete('idx:tag:' + tags[i] + ':' + inv + ':' + id));
    }
    jobs.push(env.SHARE.delete('s:' + id));
    jobs.push(env.SHARE.delete('pending:' + id));
    await Promise.all(jobs);
  } else {
    // 主记录已不在: 兜底清掉可能残留的索引 (按后缀匹配)
    var prefixes = ['idx:new:', 'idx:user:', 'idx:tag:', 'idx:featured:'];
    for (var p = 0; p < prefixes.length; p++) {
      var cursor = undefined;
      for (;;) {
        var r = await env.SHARE.list({ prefix: prefixes[p], cursor: cursor });
        var dels = [];
        for (var k = 0; k < r.keys.length; k++) {
          var kn = r.keys[k].name;
          if (kn.slice(-11) === ':' + id) dels.push(env.SHARE.delete(kn));
        }
        await Promise.all(dels);
        if (r.list_complete) break;
        cursor = r.cursor;
        if (!cursor) break;
      }
    }
    await env.SHARE.delete('s:' + id);
    await env.SHARE.delete('pending:' + id);
  }
  // R2: 删掉该分享的全部图片 (封面 + 多图); 老数据兜底删 'img:<id>'
  try {
    var delImgs = meta ? imgList(meta) : [{ seq: '' }];
    var r2jobs = [];
    for (var ri = 0; ri < delImgs.length; ri++) {
      r2jobs.push(env.IMGS.delete(imgR2Key(id, delImgs[ri].seq)));
    }
    await Promise.all(r2jobs);
  } catch (e) {}
  return json({ ok: true });
}

/* 一次性: 给 v1 老数据补 v2 索引 (管理员, 幂等, 多跑几次没关系) */
async function apiReindex(env, req, lang) {
  var t = STR[lang];
  var em = await accessEmail(req, env);
  if (!isAdmin(env, em)) return json({ ok: false, error: t.eAdminOnly }, 403);
  var ids = [];
  var skipped = [];
  var cursor = undefined;
  for (;;) {
    var r = await env.SHARE.list({ prefix: 's:', cursor: cursor });
    for (var i = 0; i < r.keys.length; i++) {
      var keyName = r.keys[i].name;
      var meta = await env.SHARE.get(keyName, 'json');
      if (!meta) { skipped.push(keyName + ':empty'); continue; }
      if (!meta.id) meta.id = keyName.slice(2); // v1 老数据: id 只在 key 里, JSON 里没有
      if (!meta.owner && meta.authorEmail) meta.owner = meta.authorEmail; // v1 字段名兼容
      try {
        meta.tags = sanitizeTags(meta.tags);
        if (!meta.createdAt) meta.createdAt = Date.now();
        await env.SHARE.put('s:' + meta.id, JSON.stringify(meta));
        await indexPublish(env, meta);
        ids.push(meta.id);
      } catch (e) {
        skipped.push(meta.id + ':' + String((e && e.message) || e).slice(0, 120));
      }
    }
    if (r.list_complete) break;
    cursor = r.cursor;
    if (!cursor) break;
  }
  return json({ ok: true, reindexed: ids, skipped: skipped });
}

/* ---------- 入口 ---------- */

export default {
  async fetch(req, env, ctx) {
    var url = req.url;
    var u = new URL(url);
    var path = u.pathname;
    var lang = getLang(req);

    if (!env.SIGN_SECRET) {
      return new Response('服务端未配置 SIGN_SECRET', { status: 500 });
    }

    if (path === '/healthz') return json({ ok: true, version: 'v3.4-xiaohongshu' });

    // 语言切换: ?lang=zh|en -> 写 Cookie 后跳回干净地址 (仅 GET)
    if (req.method === 'GET') {
      var lq = u.searchParams.get('lang');
      if (lq === 'zh' || lq === 'en') {
        u.searchParams.delete('lang');
        var qs = u.searchParams.toString();
        var dest = u.pathname + (qs ? '?' + qs : '');
        return new Response(null, {
          status: 302,
          headers: {
            'Location': dest,
            'Set-Cookie': 'lang=' + lq + '; Path=/; Max-Age=31536000; SameSite=Lax'
          }
        });
      }
    }

    // ---- 公开区 (Access 侧 Bypass, Worker 侧不校验) ----
    if (path === '/' && req.method === 'GET') return galleryPage(env, url, lang);
    var mT = path.match(/^\/tag\/([^/]+)$/);
    if (mT && req.method === 'GET') {
      return tagPage(env, url, decodeURIComponent(mT[1]).slice(0, 20), lang);
    }
    if (path === '/search' && req.method === 'GET') return searchPage(env, url, lang);
    var mF = path.match(/^\/f\/([A-Za-z0-9]{10})$/);
    if (mF && req.method === 'GET') {
      var emF = await accessEmail(req, env);
      return sharePage(env, mF[1], lang, emF, isAdmin(env, emF));
    }
    var mI = path.match(/^\/img\/([A-Za-z0-9]{10})(?:\/([A-Za-z0-9]+))?$/);
    if (mI && req.method === 'GET') return serveImage(env, req, mI[1], mI[2] || '', url, lang);

    // ---- 登录区 (Access 保护 + Worker 侧二次校验 JWT) ----
    if (path === '/upload' && req.method === 'GET') {
      var emU = await accessEmail(req, env);
      if (!emU) return needLogin(lang);
      return uploadPage(emU, isAdmin(env, emU), lang);
    }
    if (path === '/mine' && req.method === 'GET') {
      var emM = await accessEmail(req, env);
      if (!emM) return needLogin(lang);
      return minePage(env, emM, lang);
    }
    var mE = path.match(/^\/edit\/([A-Za-z0-9]{10})$/);
    if (mE && req.method === 'GET') {
      var emE = await accessEmail(req, env);
      if (!emE) return needLogin(lang);
      return editPage(env, mE[1], emE, lang);
    }
    if (path === '/admin' && req.method === 'GET') {
      var emA = await accessEmail(req, env);
      if (!emA || !isAdmin(env, emA)) return new Response(STR[lang].adminOnly, { status: 403 });
      return adminPage(env, lang);
    }
    if (path === '/api/upload' && req.method === 'POST') return apiUpload(env, req, url, lang);
    if (path === '/api/edit' && req.method === 'POST') return apiEdit(env, req, url, lang);
    if (path === '/api/review' && req.method === 'POST') return apiReview(env, req, lang);
    if (path === '/api/admin/delete' && req.method === 'POST') return apiDelete(env, req, lang);
    if (path === '/api/admin/reindex' && (req.method === 'POST' || req.method === 'GET')) return apiReindex(env, req, lang);

    return new Response('Not found', { status: 404 });
  }
};
