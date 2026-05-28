const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1); // Render 프록시 설정

// ══ 보안 미들웨어 ══
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));

const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];
app.use(cors({
  origin: (origin, cb) => { if (!origin || allowedOrigins.includes(origin)) cb(null, true); else cb(new Error('CORS 차단')); },
  credentials: true,
}));
// 헬스체크 (UptimeRobot용)
app.get('/', (req, res) => res.json({ status: 'ok', service: '에브리유니 서버' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));


app.use(express.json({ limit: '25mb' }));

// ══ Rate Limiters ══
const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 300, message: { error: '요청이 너무 많아요. 잠시 후 다시 시도해주세요.' } });
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5, message: { error: '로그인 시도가 너무 많아요. 15분 후 다시 시도해주세요.' }, skipSuccessfulRequests: true });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '회원가입 시도가 너무 많아요. 1시간 후 다시 시도해주세요.' } });
const postLimiter = rateLimit({ windowMs: 60*1000, max: 3, message: { error: '게시글을 너무 빨리 올리고 있어요. 잠시 후 다시 시도해주세요.' } });
const commentLimiter = rateLimit({ windowMs: 60*1000, max: 10, message: { error: '댓글을 너무 빨리 달고 있어요.' } });
const dmLimiter = rateLimit({ windowMs: 60*1000, max: 20, message: { error: '쪽지를 너무 빨리 보내고 있어요.' } });
app.use(globalLimiter);

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = (process.env.JWT_SECRET || '') + '_refresh';

// ══ 금지어 ══
let bannedWords = [];
async function loadBannedWords() {
  const { data } = await supabase.from('banned_words').select('word');
  bannedWords = (data || []).map(r => r.word.toLowerCase());
}
loadBannedWords();
setInterval(loadBannedWords, 5 * 60 * 1000);

function filterBadWords(text) {
  if (!text) return text;
  let r = text;
  bannedWords.forEach(w => { r = r.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'gi'), '*'.repeat(w.length)); });
  return r;
}
function hasBadWords(text) { return bannedWords.some(w => (text||'').toLowerCase().includes(w)); }

// ══ Sanitize ══
function san(s) { return validator.escape(String(s||'').trim()); }
function sanBody(t) { return String(t||'').trim().replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

// ══ 미들웨어 ══
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '로그인이 필요해요.' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch(e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'TOKEN_EXPIRED' });
    res.status(401).json({ error: '유효하지 않은 토큰이에요.' });
  }
}
function adminOnly(req, res, next) { if (req.user.role !== 'admin') return res.status(403).json({ error: '관리자만 접근 가능해요.' }); next(); }
async function checkSuspended(req, res, next) {
  const { data } = await supabase.from('users').select('suspended').eq('id', req.user.id).single();
  if (data?.suspended) return res.status(403).json({ error: '정지된 계정이에요.' });
  next();
}

// ══ 회원가입 ══
app.post('/api/register', registerLimiter, async (req, res) => {
  const { id, name, bday, password, securityQuestion, securityAnswer } = req.body;
  if (!id||!name||!password) return res.status(400).json({ error: '필수 항목이 빠졌어요.' });
  if (!/^[a-zA-Z0-9]{4,20}$/.test(id)) return res.status(400).json({ error: '아이디는 영문·숫자 4~20자이어야 해요.' });
  if (password.length < 6 || password.length > 50) return res.status(400).json({ error: '비밀번호는 6~50자이어야 해요.' });
  if (name.length < 2 || name.length > 20) return res.status(400).json({ error: '이름은 2~20자이어야 해요.' });
  if (hasBadWords(id)||hasBadWords(name)) return res.status(400).json({ error: '사용할 수 없는 단어가 포함됐어요.' });
  const { data: exists } = await supabase.from('users').select('id').eq('id', id).single();
  if (exists) return res.status(400).json({ error: '이미 사용 중인 아이디예요.' });
  const hashed = await bcrypt.hash(password, 12);
  const { error } = await supabase.from('users').insert({ id: san(id), name: san(name), bday, password: hashed, role:'user', suspended:false, warnings:0 });
  if (error) {
    console.error('회원가입 DB 오류:', error);
    return res.status(500).json({ error: '서버 오류가 발생했어요.' });
  }
  await supabase.from('logs').insert({ uid: id, action: '회원가입', type: 'login' });
  res.json({ ok: true });
});

// ══ 로그인 ══
app.post('/api/login', loginLimiter, async (req, res) => {
  const { id, password } = req.body;
  console.log('로그인 시도:', id);
  if (!id||!password) return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
  const { data: user, error: dbError } = await supabase.from('users').select('*').eq('id', id).single();
  console.log('DB 조회:', user ? '찾음' : '없음', dbError ? dbError.message : '');
  if (!user||user.deleted) { await bcrypt.compare(password,'$2b$12$dummy'); return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' }); }
  if (user.suspended) return res.status(403).json({ error: '정지된 계정입니다. 관리자에게 문의하세요.' });
  const ok = await bcrypt.compare(password, user.password);
  console.log('bcrypt 결과:', ok);
  if (!ok) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
  await supabase.from('logs').insert({ uid: id, action: '로그인', type: 'login' });
  res.json({ token, refreshToken, user: { id: user.id, name: user.name, role: user.role, bday: user.bday, warnings: user.warnings } });
});

// 토큰 갱신
app.post('/api/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: '리프레시 토큰이 없어요.' });
  try {
    const p = jwt.verify(refreshToken, REFRESH_SECRET);
    const { data: user } = await supabase.from('users').select('id,role,name,suspended').eq('id', p.id).single();
    if (!user||user.suspended) return res.status(403).json({ error: '사용할 수 없는 계정이에요.' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch { res.status(401).json({ error: '다시 로그인해주세요.' }); }
});

// 비밀번호 찾기
app.post('/api/find-password', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '시도 횟수를 초과했어요.' } }), async (req, res) => {
  const { id, name, bday } = req.body;
  const { data: user } = await supabase.from('users').select('id,name,bday').eq('id', id).single();
  await new Promise(r => setTimeout(r, 300));
  if (!user||user.name!==name||user.bday!==bday) return res.status(404).json({ error: '일치하는 계정을 찾을 수 없어요.' });
  res.json({ ok: true });
});

app.post('/api/reset-password', async (req, res) => {
  const { id, name, bday, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('id', id).single();
  if (!user||user.name!==name||user.bday!==bday) return res.status(403).json({ error: '본인 확인 실패' });
  if (newPassword.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 해요.' });
  await supabase.from('users').update({ password: await bcrypt.hash(newPassword, 12) }).eq('id', id);
  res.json({ ok: true });
});

app.post('/api/change-password', auth, checkSuspended, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('password').eq('id', req.user.id).single();
  if (!await bcrypt.compare(currentPassword, user.password)) return res.status(401).json({ error: '현재 비밀번호가 틀렸어요.' });
  if (newPassword.length < 6) return res.status(400).json({ error: '새 비밀번호는 6자 이상이어야 해요.' });
  await supabase.from('users').update({ password: await bcrypt.hash(newPassword, 12) }).eq('id', req.user.id);
  res.json({ ok: true });
});

app.delete('/api/account', auth, async (req, res) => {
  await supabase.from('users').update({ deleted: true, suspended: true }).eq('id', req.user.id);
  await supabase.from('logs').insert({ uid: req.user.id, action: '계정 탈퇴', type: 'login' });
  res.json({ ok: true });
});

// ══ 게시글 ══
app.get('/api/posts', auth, async (req, res) => {
  const page = parseInt(req.query.page)||1, limit = parseInt(req.query.limit)||20;
  let query = supabase.from('posts').select('id,uid,author,anon,cat,title,body,imgs,files,likes,dislikes,deleted,pinned,edited,created_at,views,tags').eq('deleted', false).order('pinned',{ascending:false}).order('created_at',{ascending:false}).range((page-1)*limit, page*limit-1);
  if (req.query.cat) query = query.eq('cat', req.query.cat);
  const { data } = await query;
  const ids = (data||[]).map(p=>p.id);
  // 댓글 수
  const { data: cc } = ids.length ? await supabase.from('comments').select('post_id').in('post_id',ids).eq('deleted',false) : {data:[]};
  const cm = {}; (cc||[]).forEach(c=>{ cm[c.post_id]=(cm[c.post_id]||0)+1; });
  // 신고 수
  const { data: rc } = ids.length ? await supabase.from('reports').select('post_id').in('post_id',ids) : {data:[]};
  const rm = {}; (rc||[]).forEach(r=>{ rm[r.post_id]=(rm[r.post_id]||0)+1; });
  res.json((data||[]).map(p=>({...p, comment_count:cm[p.id]||0, report_count:rm[p.id]||0})));
});

app.get('/api/posts/hot', auth, async (req, res) => {
  const { data } = await supabase.from('posts').select('*').eq('deleted',false).gte('likes',10).order('likes',{ascending:false}).limit(20);
  res.json(data||[]);
});

app.get('/api/posts/:id', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('*').eq('id',req.params.id).single();
  if (!post||post.deleted) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id) await supabase.from('posts').update({ views:(post.views||0)+1 }).eq('id',req.params.id);
  const { data: comments } = await supabase.from('comments').select('*').eq('post_id',req.params.id).eq('deleted',false).order('created_at');
  res.json({...post, comments:comments||[]});
});

app.post('/api/posts', auth, checkSuspended, postLimiter, async (req, res) => {
  const { cat, title, body, anon, imgs, files } = req.body;
  if (!cat||!title||!body) return res.status(400).json({ error: '필수 항목이 빠졌어요.' });
  if (title.length>100) return res.status(400).json({ error: '제목은 100자 이내로 입력해주세요.' });
  if (body.length>10000) return res.status(400).json({ error: '내용은 10,000자 이내로 입력해주세요.' });
  const { data, error } = await supabase.from('posts').insert({ uid:req.user.id, author:req.user.name, cat, title:filterBadWords(san(title)), body:filterBadWords(sanBody(body)), anon, imgs:imgs||[], files:files||[], likes:0, dislikes:0, deleted:false, pinned:false, views:0 }).select().single();
  if (error) return res.status(500).json({ error: '게시글 등록에 실패했어요.' });
  await supabase.from('logs').insert({ uid:req.user.id, action:'게시글 등록: '+title, type:'post' });
  res.json(data);
});

app.put('/api/posts/:id', auth, checkSuspended, async (req, res) => {
  const { cat, title, body, anon, imgs, files } = req.body;
  const { data: post } = await supabase.from('posts').select('uid').eq('id',req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error: '수정 권한이 없어요.' });
  await supabase.from('posts').update({ cat, title:filterBadWords(san(title)), body:filterBadWords(sanBody(body)), anon, imgs:imgs||[], files:files||[], edited:true }).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid:req.user.id, action:'게시글 수정: '+title, type:'edit' });
  res.json({ ok:true });
});

// 좋아요/싫어요
app.post('/api/posts/:id/like', auth, checkSuspended, async (req, res) => {
  const pid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('likes').select('id').eq('post_id',pid).eq('uid',uid).single();
  if (ex) { await supabase.from('likes').delete().eq('post_id',pid).eq('uid',uid); await supabase.rpc('decrement_likes',{post_id:parseInt(pid)}); const {data:pp}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); return res.json({liked:false, likes:pp?.likes||0, dislikes:pp?.dislikes||0}); }
  await supabase.from('dislikes').delete().eq('post_id',pid).eq('uid',uid);
  await supabase.from('likes').insert({post_id:pid,uid});
  await Promise.all([supabase.rpc('increment_likes',{post_id:parseInt(pid)}), supabase.rpc('decrement_dislikes',{post_id:parseInt(pid)})]);
  const { data: p } = await supabase.from('posts').select('uid,title,likes,dislikes').eq('id',pid).single();
  if (p&&p.uid!==uid) await supabase.from('notifications').insert({to_uid:p.uid,text:'회원님의 글 "'+p.title+'"에 좋아요가 달렸어요! ❤️',post_id:pid,read:false});
  res.json({liked:true, likes:p?.likes||0, dislikes:p?.dislikes||0});
});

app.post('/api/posts/:id/dislike', auth, checkSuspended, async (req, res) => {
  const pid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('dislikes').select('id').eq('post_id',pid).eq('uid',uid).single();
  if (ex) { await supabase.from('dislikes').delete().eq('post_id',pid).eq('uid',uid); await supabase.rpc('decrement_dislikes',{post_id:parseInt(pid)}); const {data:pp}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); return res.json({disliked:false, likes:pp?.likes||0, dislikes:pp?.dislikes||0}); }
  await supabase.from('likes').delete().eq('post_id',pid).eq('uid',uid);
  await supabase.from('dislikes').insert({post_id:pid,uid});
  await Promise.all([supabase.rpc('increment_dislikes',{post_id:parseInt(pid)}), supabase.rpc('decrement_likes',{post_id:parseInt(pid)})]);
  const {data:p2}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single();
  res.json({disliked:true, likes:p2?.likes||0, dislikes:p2?.dislikes||0});
});

// ══ 댓글 ══
app.post('/api/posts/:id/comments', auth, checkSuspended, commentLimiter, async (req, res) => {
  const { body, parentId } = req.body;
  if (!body||body.trim().length===0) return res.status(400).json({ error: '댓글 내용을 입력해주세요.' });
  if (body.length>500) return res.status(400).json({ error: '댓글은 500자 이내로 작성해주세요.' });
  const postId = parseInt(req.params.id);
  if (isNaN(postId)) return res.status(400).json({ error: '잘못된 게시글 ID예요.' });
  const { data, error } = await supabase.from('comments').insert({ post_id:postId, uid:req.user.id, author:req.user.name, body:filterBadWords(sanBody(body)), anon:true, parent_id:parentId?parseInt(parentId):null, likes:0, dislikes:0 }).select().single();
  if (error) return res.status(500).json({ error: '댓글 등록에 실패했어요: ' + error.message });
  const { data: post } = await supabase.from('posts').select('uid,title').eq('id',postId).single();
  if (post&&post.uid!==req.user.id) await supabase.from('notifications').insert({to_uid:post.uid,text:'회원님의 글 "'+post.title+'"에 댓글이 달렸어요. 💬',post_id:postId,read:false});
  if (parentId) { const { data: pc } = await supabase.from('comments').select('uid').eq('id',parseInt(parentId)).single(); if (pc&&pc.uid!==req.user.id) await supabase.from('notifications').insert({to_uid:pc.uid,text:'회원님의 댓글에 답글이 달렸어요. ↩',post_id:postId,read:false}); }
  res.json(data);
});

app.put('/api/comments/:id', auth, checkSuspended, async (req, res) => {
  const { body } = req.body;
  const { data: c } = await supabase.from('comments').select('uid').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '수정 권한이 없어요.' });
  await supabase.from('comments').update({ body:filterBadWords(sanBody(body)), edited:true }).eq('id',req.params.id);
  res.json({ok:true});
});

app.delete('/api/comments/:id/mine', auth, async (req, res) => {
  const { data: c } = await supabase.from('comments').select('uid').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('comments').update({deleted:true}).eq('id',req.params.id);
  res.json({ok:true});
});

app.post('/api/comments/:id/like', auth, checkSuspended, async (req, res) => {
  const cid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('comment_likes').select('id').eq('comment_id',cid).eq('uid',uid).single();
  if (ex) { await supabase.from('comment_likes').delete().eq('comment_id',cid).eq('uid',uid); await supabase.rpc('decrement_comment_likes',{comment_id:parseInt(cid)}); return res.json({liked:false}); }
  await supabase.from('comment_dislikes').delete().eq('comment_id',cid).eq('uid',uid);
  await supabase.from('comment_likes').insert({comment_id:cid,uid});
  await supabase.rpc('increment_comment_likes',{comment_id:parseInt(cid)});
  await supabase.rpc('decrement_comment_dislikes',{comment_id:parseInt(cid)});
  res.json({liked:true});
});

app.post('/api/comments/:id/dislike', auth, checkSuspended, async (req, res) => {
  const cid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('comment_dislikes').select('id').eq('comment_id',cid).eq('uid',uid).single();
  if (ex) { await supabase.from('comment_dislikes').delete().eq('comment_id',cid).eq('uid',uid); await supabase.rpc('decrement_comment_dislikes',{comment_id:parseInt(cid)}); return res.json({disliked:false}); }
  await supabase.from('comment_likes').delete().eq('comment_id',cid).eq('uid',uid);
  await supabase.from('comment_dislikes').insert({comment_id:cid,uid});
  await supabase.rpc('increment_comment_dislikes',{comment_id:parseInt(cid)});
  await supabase.rpc('decrement_comment_likes',{comment_id:parseInt(cid)});
  res.json({disliked:true});
});

// ══ 검색 ══
app.get('/api/search', auth, async (req, res) => {
  const { q, cat, sort, hasImg } = req.query;
  if (!q||q.trim().length<2) return res.status(400).json({ error: '검색어는 2자 이상 입력해주세요.' });
  let query = supabase.from('posts').select('*').eq('deleted',false).or(`title.ilike.%${q}%,body.ilike.%${q}%`);
  if (cat&&cat!=='전체') query = query.eq('cat',cat);
  if (hasImg==='true') query = query.not('imgs','eq','{}');
  if (sort==='likes') query = query.order('likes',{ascending:false});
  else if (sort==='comments') query = query.order('comment_count',{ascending:false});
  else query = query.order('created_at',{ascending:false});
  const { data } = await query.limit(50);
  await supabase.from('logs').insert({ uid:req.user.id, action:'검색: "'+q+'"', type:'search' });
  res.json(data||[]);
});

// ══ DM ══
app.get('/api/dm', auth, async (req, res) => {
  const { data } = await supabase.from('dms').select('*').or(`from_uid.eq.${req.user.id},to_uid.eq.${req.user.id}`).order('created_at',{ascending:false});
  const threads = {};
  (data||[]).forEach(dm => { const partner = dm.from_uid===req.user.id?dm.to_uid:dm.from_uid; if (!threads[partner]||new Date(dm.created_at)>new Date(threads[partner].created_at)) threads[partner]=dm; });
  // 상대방 이름 조회
  const partnerIds = Object.keys(threads);
  if (partnerIds.length) {
    const { data: users } = await supabase.from('users').select('id,name').in('id', partnerIds);
    const nameMap = {};
    (users||[]).forEach(u => nameMap[u.id] = u.name);
    Object.values(threads).forEach(dm => {
      const pid = dm.from_uid===req.user.id ? dm.to_uid : dm.from_uid;
      dm.partner_name = nameMap[pid] || '알 수 없음';
      dm.from_name = nameMap[dm.from_uid] || '알 수 없음';
      dm.to_name = nameMap[dm.to_uid] || '알 수 없음';
    });
  }
  res.json(Object.values(threads));
});

app.get('/api/dm/:partnerId', auth, async (req, res) => {
  const me=req.user.id, p=req.params.partnerId;
  const { data } = await supabase.from('dms').select('*').or(`and(from_uid.eq.${me},to_uid.eq.${p}),and(from_uid.eq.${p},to_uid.eq.${me})`).order('created_at');
  await supabase.from('dms').update({read:true}).eq('to_uid',me).eq('from_uid',p);
  res.json(data||[]);
});

app.post('/api/dm/:partnerId', auth, checkSuspended, dmLimiter, async (req, res) => {
  const { body } = req.body;
  if (!body||body.trim().length===0) return res.status(400).json({ error: '내용을 입력해주세요.' });
  if (body.length>500) return res.status(400).json({ error: '쪽지는 500자 이내로 작성해주세요.' });
  const { data: target } = await supabase.from('users').select('id,suspended').eq('id',req.params.partnerId).single();
  if (!target) return res.status(404).json({ error: '존재하지 않는 사용자예요.' });
  if (target.suspended) return res.status(400).json({ error: '정지된 사용자에게는 쪽지를 보낼 수 없어요.' });
  const { data } = await supabase.from('dms').insert({ from_uid:req.user.id, to_uid:req.params.partnerId, body:filterBadWords(sanBody(body)), read:false, from_name:req.user.name }).select().single();
  await supabase.from('notifications').insert({to_uid:req.params.partnerId,text:req.user.name+'님에게 쪽지가 도착했어요. 📩',read:false});
  res.json(data);
});

// ══ 신고 ══
app.post('/api/reports', auth, checkSuspended, async (req, res) => {
  const { post_id, comment_id, reason } = req.body;
  if (!reason) return res.status(400).json({ error: '신고 사유를 입력해주세요.' });
  const { error } = await supabase.from('reports').insert({ post_id, comment_id, reporter_uid:req.user.id, reason, resolved:false });
  if (error) return res.status(400).json({ error: '이미 신고한 게시글이에요.' });
  res.json({ ok:true });
});

// 게시글 삭제 (본인)
app.delete('/api/posts/:id', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('uid').eq('id',req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('posts').update({deleted:true,pinned:false}).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid:req.user.id, action:'게시글 삭제', type:'del' });
  res.json({ok:true});
});

// ══ 알림 ══
app.get('/api/notifications', auth, async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').eq('to_uid', req.user.id).order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('id', req.params.id).eq('to_uid', req.user.id);
  res.json({ ok: true });
});

app.put('/api/notifications/read-all', auth, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('to_uid', req.user.id);
  res.json({ ok: true });
});

// ══ 관리자 ══
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('users').select('id,name,role,suspended,warnings,created_at,deleted').order('created_at',{ascending:false});
  res.json(data||[]);
});
app.put('/api/admin/users/:id/suspend', auth, adminOnly, async (req, res) => {
  const { suspend } = req.body;
  const { data: u } = await supabase.from('users').select('name').eq('id',req.params.id).single();
  await supabase.from('users').update({ suspended: suspend }).eq('id',req.params.id);
  if (suspend) await supabase.from('notifications').insert({to_uid:req.params.id,text:'🚫 관리자에 의해 계정이 정지됐어요.',read:false});
  await supabase.from('logs').insert({uid:'admin',action:(u?.name||req.params.id)+' 계정 '+(suspend?'정지':'해제'),type:'ban'});
  res.json({ok:true});
});
app.post('/api/admin/users/:id/warn', auth, adminOnly, async (req, res) => {
  const { data: user } = await supabase.from('users').select('warnings,name').eq('id',req.params.id).single();
  const nw=(user.warnings||0)+1;
  const upd={warnings:nw}; if(nw>=3)upd.suspended=true;
  await supabase.from('users').update(upd).eq('id',req.params.id);
  await supabase.from('notifications').insert({to_uid:req.params.id,text:'⚠️ 관리자로부터 경고를 받았어요. (누적 '+nw+'회)',read:false});
  if(nw>=3)await supabase.from('notifications').insert({to_uid:req.params.id,text:'🚫 경고 3회 누적으로 계정이 정지됐어요.',read:false});
  await supabase.from('logs').insert({uid:'admin',action:user.name+' 경고 부여 ('+nw+'회)',type:'warn'});
  res.json({ok:true,warnings:nw,suspended:nw>=3});
});
app.delete('/api/admin/posts/:id', auth, adminOnly, async (req, res) => {
  const { data: p } = await supabase.from('posts').select('title').eq('id',req.params.id).single();
  await supabase.from('posts').update({deleted:true,pinned:false}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:'admin',action:'게시글 삭제: "'+p?.title+'"',type:'del'});
  res.json({ok:true});
});
app.delete('/api/admin/comments/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('comments').update({deleted:true}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:'admin',action:'댓글 삭제',type:'del'});
  res.json({ok:true});
});
app.put('/api/admin/posts/:id/pin', auth, adminOnly, async (req, res) => {
  const { pinned } = req.body;
  const { data: p } = await supabase.from('posts').select('title').eq('id',req.params.id).single();
  await supabase.from('posts').update({pinned}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:'admin',action:'게시글 '+(pinned?'고정':'고정해제')+': '+p?.title,type:'del'});
  res.json({ok:true});
});
app.get('/api/admin/reports', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('reports').select('*').order('created_at',{ascending:false});
  res.json(data||[]);
});
app.put('/api/admin/reports/:id/resolve', auth, adminOnly, async (req, res) => {
  await supabase.from('reports').update({resolved:true}).eq('id',req.params.id);
  const { data: report } = await supabase.from('reports').select('reporter_uid').eq('id',req.params.id).single();
  if (report) await supabase.from('notifications').insert({to_uid:report.reporter_uid,text:'✅ 회원님이 신고한 내용이 처리완료됐어요. 감사해요.',read:false,is_report_resolved:true});
  await supabase.from('logs').insert({uid:'admin',action:'신고 처리완료',type:'del'});
  res.json({ok:true});
});
app.get('/api/admin/logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('logs').select('*').order('created_at',{ascending:false}).limit(100);
  res.json(data||[]);
});
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const [u,p,s,r] = await Promise.all([
    supabase.from('users').select('id',{count:'exact'}).eq('deleted',false),
    supabase.from('posts').select('id',{count:'exact'}).eq('deleted',false),
    supabase.from('users').select('id',{count:'exact'}).eq('suspended',true).eq('deleted',false),
    supabase.from('reports').select('id',{count:'exact'}).eq('resolved',false),
  ]);
  res.json({users:u.count||0,posts:p.count||0,suspended:s.count||0,reports:r.count||0});
});

// 금지어 관리
app.get('/api/admin/banned-words', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('banned_words').select('*').order('created_at',{ascending:false});
  res.json(data||[]);
});
app.post('/api/admin/banned-words', auth, adminOnly, async (req, res) => {
  const { word } = req.body;
  if (!word||word.trim().length<2) return res.status(400).json({error:'금지어는 2자 이상이어야 해요.'});
  const { error } = await supabase.from('banned_words').insert({word:word.trim().toLowerCase(),added_by:req.user.id});
  if (error) return res.status(400).json({error:'이미 등록된 금지어예요.'});
  await loadBannedWords();
  res.json({ok:true});
});
app.delete('/api/admin/banned-words/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('banned_words').delete().eq('id',req.params.id);
  await loadBannedWords();
  res.json({ok:true});
});

// ══ 에러 핸들러 ══
app.use((req,res) => res.status(404).json({error:'존재하지 않는 API예요.'}));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:'서버 오류가 발생했어요.'}); });



// ══ 다른 사용자 프로필 조회 ══
app.get('/api/users/:uid/profile', auth, async (req, res) => {
  const targetId = req.params.uid;
  const { data: user } = await supabase.from('users').select('id,name,role,avatar,created_at').eq('id', targetId).eq('deleted', false).single();
  if (!user) return res.status(404).json({ error: '존재하지 않는 사용자예요.' });
  // 실명 글만 공개 (익명 글 제외)
  const { data: posts } = await supabase.from('posts').select('id,title,cat,likes,created_at').eq('uid', targetId).eq('deleted', false).eq('anon', false).order('created_at', { ascending: false }).limit(20);
  res.json({ ...user, posts: posts || [] });
});

// ══ 채팅 기록 API ══
app.get('/api/chat/history', auth, async (req, res) => {
  const since = new Date(Date.now() - 24*60*60*1000).toISOString();
  const { data } = await supabase.from('chat_messages')
    .select('*')
    .eq('room', 'general')
    .gte('created_at', since)
    .order('created_at', { ascending: true })
    .limit(200);
  res.json(data || []);
});

// 오래된 채팅 메시지 정리 (1시간마다 24시간 이전 삭제)
setInterval(async () => {
  const cutoff = new Date(Date.now() - 24*60*60*1000).toISOString();
  await supabase.from('chat_messages').delete().lt('created_at', cutoff);
}, 60*60*1000);

const http = require('http');
const { Server } = require('socket.io');

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true,
  },
  pingTimeout: 60000,
  pingInterval: 25000,
});

// ── 채팅방 익명 닉네임 관리 ──
const ANIMALS = ['오리','고양이','여우','토끼','다람쥐','곰','펭귄','코알라','판다','수달','늑대','사자','호랑이','코끼리','기린'];
const roomUsers = {}; // {socketId: {nickname, room}}

io.on('connection', (socket) => {
  console.log('새 연결:', socket.id);

  // 채팅방 입장
  socket.on('join_room', ({ room = 'general', token }) => {
    // JWT 검증
    let user = null;
    try {
      if (token) user = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
    } catch {}

    const nickname = '익명의 ' + ANIMALS[Math.floor(Math.random() * ANIMALS.length)];
    roomUsers[socket.id] = { nickname, room, userId: user?.id };
    socket.join(room);

    // 입장 알림
    socket.to(room).emit('system_message', {
      text: nickname + '님이 입장했어요 👋',
      time: new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }),
    });

    // 현재 접속자 수 전송
    const roomSize = io.sockets.adapter.rooms.get(room)?.size || 0;
    io.to(room).emit('room_users', { count: roomSize });

    // 본인에게 닉네임 전송
    socket.emit('my_nickname', { nickname });
  });

  // 메시지 전송
  socket.on('chat_message', ({ room = 'general', text }) => {
    if (!text || text.trim().length === 0) return;
    if (text.length > 200) return;

    // 금지어 필터
    let filtered = text.trim();
    bannedWords.forEach(w => {
      filtered = filtered.split(w).join('*'.repeat(w.length));
    });

    const userData = roomUsers[socket.id];
    if (!userData) return;

    const now = new Date();
    const msg = {
      id: Date.now(),
      nickname: userData.nickname,
      text: filtered,
      time: now.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }),
      isMe: false,
    };

    // DB에 저장
    supabase.from('chat_messages').insert({ room, nickname: userData.nickname, body: filtered, created_at: now.toISOString() }).then(() => {});

    // 다른 사람들에게 전송
    socket.to(room).emit('chat_message', msg);
    // 본인에게도 전송 (isMe: true)
    socket.emit('chat_message', { ...msg, isMe: true });
  });

  // 연결 해제
  socket.on('disconnect', () => {
    const userData = roomUsers[socket.id];
    if (userData) {
      const { nickname, room } = userData;
      socket.to(room).emit('system_message', {
        text: nickname + '님이 퇴장했어요 👋',
        time: new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }),
      });
      const roomSize = (io.sockets.adapter.rooms.get(room)?.size || 1) - 1;
      io.to(room).emit('room_users', { count: roomSize });
      delete roomUsers[socket.id];
    }
    console.log('연결 해제:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 에브리유니 서버 실행 중 → 포트 ${PORT}`));

// ── 전체 공지 발송 (관리자) ──
app.post('/api/admin/notice', auth, adminOnly, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: '내용을 입력해주세요.' });
  const { data: users } = await supabase.from('users').select('id').eq('deleted', false).eq('suspended', false);
  if (users && users.length) {
    const notifications = users.map(u => ({ to_uid: u.id, text: '📢 공지: ' + sanBody(message), read: false }));
    await supabase.from('notifications').insert(notifications);
  }
  await supabase.from('logs').insert({ uid: 'admin', action: '전체 공지 발송: ' + message, type: 'post' });
  res.json({ ok: true });
});

// ── posts 테이블 tags 컬럼 지원 ──
// database.sql에서 아래 SQL 실행 필요:
// alter table posts add column if not exists tags text[] default '{}';

// ═══════════════════════════════════════════
// Supabase Storage 파일 업로드
// ═══════════════════════════════════════════
app.post('/api/upload', auth, checkSuspended, async (req, res) => {
  const { file, fileName, fileType, bucket } = req.body;
  if (!file || !fileName) return res.status(400).json({ error: '파일 정보가 없어요.' });

  const base64Data = file.replace(/^data:[^;]+;base64,/, '');
  const buffer = Buffer.from(base64Data, 'base64');

  if (buffer.length > 20 * 1024 * 1024) return res.status(400).json({ error: '파일 크기는 20MB 이하여야 해요.' });

  const ext = fileName.split('.').pop().toLowerCase();
  const safeName = Date.now() + '_' + req.user.id + '.' + ext;
  const allowedBuckets = ['everyu', 'images', 'files', 'profiles'];
  const bucketName = allowedBuckets.includes(bucket) ? bucket : 'everyu';
  const path = req.user.id + '/' + safeName;

  const { data, error } = await supabase.storage
    .from(bucketName)
    .upload(path, buffer, {
      contentType: fileType || 'application/octet-stream',
      upsert: false,
    });

  if (error) return res.status(500).json({ error: '파일 업로드에 실패했어요: ' + error.message });
  const { data: urlData } = supabase.storage.from(bucketName).getPublicUrl(path);
  res.json({ url: urlData.publicUrl, path, bucketName, name: fileName, size: buffer.length });
});

// 파일 삭제
app.delete('/api/upload', auth, async (req, res) => {
  const { path, bucket } = req.body;
  const allowedBuckets2 = ['everyu', 'images', 'files', 'profiles'];
  const bucketName2 = allowedBuckets2.includes(bucket) ? bucket : 'everyu';
  await supabase.storage.from(bucketName2).remove([path]);
  res.json({ ok: true });
});

// 프로필 사진 업로드
app.post('/api/profile/avatar', auth, checkSuspended, async (req, res) => {
  const { file, fileName } = req.body;
  if (!file) return res.status(400).json({ error: '이미지가 없어요.' });
  const base64Data = file.replace(/^data:[^;]+;base64,/, '');
  const buffer = Buffer.from(base64Data, 'base64');
  if (buffer.length > 5 * 1024 * 1024) return res.status(400).json({ error: '프로필 사진은 5MB 이하여야 해요.' });
  const ext = (fileName || 'jpg').split('.').pop().toLowerCase();
  const path = 'avatars/' + req.user.id + '.' + ext;
  await supabase.storage.from('everyu').upload(path, buffer, { contentType: 'image/' + ext, upsert: true });
  const { data: urlData } = supabase.storage.from('everyu').getPublicUrl(path);
  await supabase.from('users').update({ avatar: urlData.publicUrl }).eq('id', req.user.id);
  res.json({ url: urlData.publicUrl });
});

// 프로필 정보 조회
app.get('/api/profile', auth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('id,name,bday,role,warnings,avatar,created_at').eq('id', req.user.id).single();
  const { data: myPosts } = await supabase.from('posts').select('id,title,likes,created_at').eq('uid', req.user.id).eq('deleted', false).order('created_at', { ascending: false });
  const totalLikes = (myPosts || []).reduce((a, p) => a + (p.likes || 0), 0);
  res.json({ ...user, postCount: (myPosts || []).length, totalLikes });
});

// 프로필 정보 수정 (이름 변경)
app.put('/api/profile', auth, checkSuspended, async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: '이름은 2자 이상이어야 해요.' });
  if (hasBadWords(name)) return res.status(400).json({ error: '사용할 수 없는 단어가 포함됐어요.' });
  await supabase.from('users').update({ name: san(name.trim()) }).eq('id', req.user.id);
  res.json({ ok: true });
});

// 실시간 알림 폴링 (새 알림만 반환)
app.get('/api/notifications/new', auth, async (req, res) => {
  const since = req.query.since || new Date(0).toISOString();
  const { data } = await supabase.from('notifications').select('*').eq('to_uid', req.user.id).eq('read', false).gt('created_at', since).order('created_at', { ascending: false });
  res.json(data || []);
});

// 회원 통계 (관리자)
app.get('/api/admin/dashboard', auth, adminOnly, async (req, res) => {
  const now = new Date();
  const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();

  const [totalUsers, newUsers, totalPosts, weekPosts, totalReports, resolvedReports] = await Promise.all([
    supabase.from('users').select('id', { count: 'exact' }).eq('deleted', false),
    supabase.from('users').select('id', { count: 'exact' }).eq('deleted', false).gte('created_at', weekAgo),
    supabase.from('posts').select('id', { count: 'exact' }).eq('deleted', false),
    supabase.from('posts').select('id', { count: 'exact' }).eq('deleted', false).gte('created_at', weekAgo),
    supabase.from('reports').select('id', { count: 'exact' }),
    supabase.from('reports').select('id', { count: 'exact' }).eq('resolved', true),
  ]);

  const { data: dailySignups } = await supabase.from('users').select('created_at').gte('created_at', weekAgo).eq('deleted', false);

  res.json({
    totalUsers: totalUsers.count || 0,
    newUsers: newUsers.count || 0,
    totalPosts: totalPosts.count || 0,
    weekPosts: weekPosts.count || 0,
    totalReports: totalReports.count || 0,
    resolvedReports: resolvedReports.count || 0,
    dailySignups: dailySignups || [],
  });
});
