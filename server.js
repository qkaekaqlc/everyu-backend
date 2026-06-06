const express = require('express');
const { Resend } = require('resend');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
require('dotenv').config();
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

// ══ Cloudflare R2 클라이언트 ══
const r2 = new S3Client({
  endpoint: process.env.R2_ENDPOINT,
  region: 'auto',
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY,
    secretAccessKey: process.env.R2_SECRET_KEY,
  },
});
const R2_BUCKET = process.env.R2_BUCKET || 'everyu-files';
const R2_PUBLIC_URL = (process.env.R2_PUBLIC_URL || '').replace(/\/$/, '');

async function getR2Usage() {
  const { data } = await supabase.from('r2_usage').select('total_bytes').eq('id', 1).single();
  return data?.total_bytes || 0;
}
async function updateR2Usage(bytes) {
  const current = await getR2Usage();
  await supabase.from('r2_usage').upsert({ id: 1, total_bytes: current + bytes });
}

const app = express();
app.set('trust proxy', 1); // Render 프록시 설정

// ══ 보안 미들웨어 ══
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://everyu-backend.onrender.com", "wss://everyu-backend.onrender.com", "https://*.supabase.co"],
      mediaSrc: ["'self'", "https:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
}));

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

// IP 차단 미들웨어 (로그인 필요 없는 요청도 차단)
app.use(async (req, res, next) => {
  if (req.path === '/' || req.path === '/health') return next();
  const ip = req.ip || req.connection.remoteAddress;
  const { data } = await supabase.from('banned_ips').select('ip').eq('ip', ip).single();
  if (data) return res.status(403).json({ error: '접근이 차단된 IP예요.' });
  next();
});

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || (process.env.JWT_SECRET || '') + '_refresh_fallback_change_this';

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
function sanBody(t) {
  return String(t||'').trim()
    .replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#x27;')
    .replace(/javascript:/gi,'')
    .replace(/vbscript:/gi,'')
    .replace(/on\w+\s*=/gi,'')
    .replace(/data:/gi,'');
}

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
async function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '관리자만 접근 가능해요.' });
  const { data: dbUser } = await supabase.from('users').select('role,suspended').eq('id', req.user.id).single();
  if (!dbUser || dbUser.role !== 'admin' || dbUser.suspended) return res.status(403).json({ error: '관리자 권한이 없어요.' });
  next();
}

async function managerOnly(req, res, next) {
  const { data: dbUser } = await supabase.from('users').select('role,suspended').eq('id', req.user.id).single();
  if (!dbUser || !['admin','manager'].includes(dbUser.role) || dbUser.suspended) return res.status(403).json({ error: '매니저 이상만 접근 가능해요.' });
  next();
}

// 성별 전용 게시판 접근 체크
const GENDER_BOARDS = { '남자게시판': 'male', '여자게시판': 'female' };
async function checkGenderBoard(req, res, next) {
  const cat = req.body?.cat || req.query?.cat;
  if (!GENDER_BOARDS[cat]) return next();
  const { data: dbUser } = await supabase.from('users').select('gender').eq('id', req.user.id).single();
  if (!dbUser?.gender) return res.status(403).json({ error: '성별을 설정해야 이용할 수 있어요.' });
  if (dbUser.gender !== GENDER_BOARDS[cat]) return res.status(403).json({ error: `${cat}은 ${GENDER_BOARDS[cat]==='male'?'남자':'여자'}만 이용할 수 있어요.` });
  next();
}
async function checkSuspended(req, res, next) {
  const { data } = await supabase.from('users').select('suspended').eq('id', req.user.id).single();
  if (data?.suspended) return res.status(403).json({ error: '정지된 계정이에요.' });
  next();
}

// ══ 회원가입 ══
app.post('/api/register', registerLimiter, async (req, res) => {
  const { id, name, bday, password, securityQuestion, securityAnswer, grade, classroom, email, gender } = req.body;
  if (!id||!name||!password) return res.status(400).json({ error: '필수 항목이 빠졌어요.' });
  if (!/^[a-zA-Z0-9]{4,20}$/.test(id)) return res.status(400).json({ error: '아이디는 영문·숫자 4~20자이어야 해요.' });
  if (password.length < 6 || password.length > 50) return res.status(400).json({ error: '비밀번호는 6~50자이어야 해요.' });
  if (name.length < 2 || name.length > 20) return res.status(400).json({ error: '이름은 2~20자이어야 해요.' });
  if (hasBadWords(id)||hasBadWords(name)) return res.status(400).json({ error: '사용할 수 없는 단어가 포함됐어요.' });
  const { data: exists } = await supabase.from('users').select('id').eq('id', id).single();
  if (exists) return res.status(400).json({ error: '이미 사용 중인 아이디예요.' });
  const hashed = await bcrypt.hash(password, 12);
  const { error } = await supabase.from('users').insert({
    id: san(id), name: san(name), bday, password: hashed, role:'user', suspended:false, warnings:0,
    securityQuestion: securityQuestion||null, securityAnswer: securityAnswer ? await bcrypt.hash(securityAnswer.trim().toLowerCase(), 12) : null,
    grade: grade ? parseInt(grade) : null, classroom: classroom ? parseInt(classroom) : null,
    email: email||null, email_verified: false
  });
  if (error) {
    console.error('회원가입 DB 오류:', error);
    return res.status(500).json({ error: '서버 오류가 발생했어요.' });
  }
  // 이메일 인증 완료된 경우 반영
  const { data: emailVerif } = await supabase.from('email_verifications').select('email,verified').eq('user_id', id).single();
  if (emailVerif?.verified) {
    await supabase.from('users').update({ email: emailVerif.email, email_verified: true }).eq('id', id);
    await supabase.from('email_verifications').delete().eq('user_id', id);
  }
  await supabase.from('logs').insert({ uid: id, action: '회원가입', type: 'login' });
  res.json({ ok: true });
});

// ══ 로그인 ══
app.post('/api/login', loginLimiter, async (req, res) => {
  const { id, password } = req.body;
  if (!id||!password) return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
  const { data: user, error: dbError } = await supabase.from('users').select('*').eq('id', id).single();
  if (!user||user.deleted) { await bcrypt.compare(password,'$2b$12$dummy'); return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' }); }
  if (user.suspended) return res.status(403).json({ error: '정지된 계정입니다. 관리자에게 문의하세요.' });
  if (!user.password) {
    await supabase.from('security_logs').insert({ uid: id, action: '로그인 실패 (카카오 계정)', ip: req.ip||'', created_at: new Date().toISOString() });
    return res.status(401).json({ error: '카카오로 가입된 계정이에요. 카카오로 로그인해주세요.' });
  }
  const ok = await bcrypt.compare(password, user.password);

  if (!ok) {
    await supabase.from('security_logs').insert({ uid: id, action: '로그인 실패 (비밀번호 오류)', ip: req.ip||'', created_at: new Date().toISOString() });
    return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  }
  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
  const loginIp = req.ip || req.connection.remoteAddress;
  await supabase.from('users').update({ last_ip: loginIp, last_login: new Date().toISOString() }).eq('id', id);
  // Refresh Token DB 저장
  await supabase.from('refresh_tokens').insert({ uid: id, token: refreshToken, expires_at: new Date(Date.now()+7*24*60*60*1000).toISOString() });
  // 보안 로그 저장
  const loginIp2 = req.ip || req.connection.remoteAddress;
  await supabase.from('security_logs').insert({ uid: id, action: '로그인 성공', ip: loginIp2, created_at: new Date().toISOString() });
  await supabase.from('logs').insert({ uid: id, action: '로그인', type: 'login' });
  res.json({ token, refreshToken, user: { id: user.id, name: user.name, role: user.role, bday: user.bday, warnings: user.warnings, grade: user.grade, classroom: user.classroom } });
});

// 토큰 갱신
app.post('/api/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: '리프레시 토큰이 없어요.' });
  try {
    const p = jwt.verify(refreshToken, REFRESH_SECRET);
    // DB에서 토큰 유효성 확인
    const { data: storedToken } = await supabase.from('refresh_tokens').select('uid,expires_at').eq('token', refreshToken).single();
    if (!storedToken || new Date(storedToken.expires_at) < new Date()) {
      await supabase.from('refresh_tokens').delete().eq('token', refreshToken);
      return res.status(401).json({ error: '다시 로그인해주세요.' });
    }
    const { data: user } = await supabase.from('users').select('id,role,name,suspended').eq('id', p.id).single();
    if (!user||user.suspended) return res.status(403).json({ error: '사용할 수 없는 계정이에요.' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch { res.status(401).json({ error: '다시 로그인해주세요.' }); }
});

// 비밀번호 찾기
app.post('/api/find-password', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '시도 횟수를 초과했어요.' } }), async (req, res) => {
  const { id, name, bday } = req.body;
  const { data: user } = await supabase.from('users').select('id,name,bday,securityQuestion').eq('id', id).single();
  await new Promise(r => setTimeout(r, 300));
  if (!user||user.name!==name||user.bday!==bday) return res.status(404).json({ error: '일치하는 계정을 찾을 수 없어요.' });
  res.json({ ok: true, securityQuestion: user.securityQuestion || '보안 질문' });
});

app.post('/api/verify-security', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '너무 많이 시도했어요. 1시간 후 다시 시도해주세요.' } }), async (req, res) => {
  const { id, name, bday, securityAnswer } = req.body;
  const { data: user } = await supabase.from('users').select('id,name,bday,securityAnswer').eq('id', id).single();
  await new Promise(r => setTimeout(r, 300));
  if (!user||user.name!==name||user.bday!==bday) return res.status(403).json({ error: '본인 확인 실패' });
  if (!user.securityAnswer) return res.status(403).json({ error: '보안 질문이 설정되지 않았어요.' });
  const answerOk = await bcrypt.compare((securityAnswer||'').trim().toLowerCase(), user.securityAnswer);
  if (!answerOk) return res.status(403).json({ error: '보안 질문 답변이 틀렸어요.' });
  res.json({ ok: true });
});

app.post('/api/reset-password', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '너무 많이 시도했어요. 1시간 후 다시 시도해주세요.' } }), async (req, res) => {
  const { id, name, bday, securityAnswer, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('id', id).single();
  if (!user||user.name!==name||user.bday!==bday) return res.status(403).json({ error: '본인 확인 실패' });
  if (user.securityAnswer) {
    const answerOk = await bcrypt.compare((securityAnswer||'').trim().toLowerCase(), user.securityAnswer);
    if (!answerOk) return res.status(403).json({ error: '보안 질문 답변이 틀렸어요.' });
  }
  if (!newPassword||newPassword.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 해요.' });
  await supabase.from('users').update({ password: await bcrypt.hash(newPassword, 12) }).eq('id', id);
  res.json({ ok: true });
});

app.post('/api/logout', auth, async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) await supabase.from('refresh_tokens').delete().eq('token', refreshToken);
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
  const { password } = req.body;
  const { data: user } = await supabase.from('users').select('password,kakao_id,google_id').eq('id', req.user.id).single();
  const isSocialUser = !!(user?.kakao_id || user?.google_id);
  if (!isSocialUser) {
    if (!password) return res.status(400).json({ error: '비밀번호를 입력해주세요.' });
    if (!user?.password || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: '비밀번호가 틀렸어요.' });
  }
  await supabase.from('users').update({ deleted: true, suspended: true, kakao_id: null, google_id: null }).eq('id', req.user.id);
  await supabase.from('refresh_tokens').delete().eq('uid', req.user.id);
  const provider = user?.kakao_id ? '카카오' : user?.google_id ? '구글' : '일반';
  await supabase.from('logs').insert({ uid: req.user.id, action: `계정 탈퇴 (${provider})`, type: 'login' });
  res.json({ ok: true });
});

// ══ 게시글 ══
app.get('/api/posts', auth, async (req, res) => {
  // 성별 전용 게시판 조회 차단
  const cat = req.query.cat;
  if (cat && GENDER_BOARDS[cat]) {
    const { data: dbUser } = await supabase.from('users').select('gender,role').eq('id', req.user.id).single();
    if (dbUser?.role !== 'admin' && dbUser?.gender !== GENDER_BOARDS[cat]) {
      return res.status(403).json({ error: `${cat}은 ${GENDER_BOARDS[cat]==='male'?'남자':'여자'}만 이용할 수 있어요.` });
    }
  }
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
  const weekAgo = new Date(Date.now() - 7*24*60*60*1000).toISOString();
  const { data } = await supabase.from('posts').select('*').eq('deleted',false).gte('created_at', weekAgo).order('likes',{ascending:false}).limit(20);
  res.json(data||[]);
});

app.get('/api/posts/:id', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('*').eq('id',req.params.id).single();
  if (!post||post.deleted) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id) {
    const today = new Date().toISOString().slice(0,10);
    const viewKey = `${req.user.id}_${req.params.id}_${today}`;
    const { data: alreadyViewed } = await supabase.from('post_views').select('id').eq('view_key', viewKey).single();
    if (!alreadyViewed) {
      await supabase.from('post_views').insert({ view_key: viewKey, post_id: req.params.id, uid: req.user.id });
      await supabase.from('posts').update({ views:(post.views||0)+1 }).eq('id',req.params.id);
    }
  }
  const { data: comments } = await supabase.from('comments').select('*').eq('post_id',req.params.id).eq('deleted',false).order('created_at');
  res.json({...post, comments:comments||[]});
});

app.post('/api/posts', auth, checkSuspended, postLimiter, checkGenderBoard, async (req, res) => {
  const { cat, title, body, anon, imgs, files } = req.body;
  if (!cat||!title||!body) return res.status(400).json({ error: '필수 항목이 빠졌어요.' });
  if (title.length>100) return res.status(400).json({ error: '제목은 100자 이내로 입력해주세요.' });
  if (body.length>10000) return res.status(400).json({ error: '내용은 10,000자 이내로 입력해주세요.' });
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('posts').insert({ uid:req.user.id, author:req.user.name, cat, title:filterBadWords(san(title)), body:filterBadWords(sanBody(body)), anon, imgs:imgs||[], files:files||[], likes:0, dislikes:0, deleted:false, pinned:false, views:0, created_at:now }).select().single();
  if (error) return res.status(500).json({ error: '게시글 등록에 실패했어요.' });
  await supabase.from('logs').insert({ uid:req.user.id, action:'게시글 등록: '+title, type:'post' });
  res.json(data);
});

app.put('/api/posts/:id', auth, checkSuspended, async (req, res) => {
  const { cat, title, body, anon, imgs, files } = req.body;
  const { data: post } = await supabase.from('posts').select('*').eq('id',req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error: '수정 권한이 없어요.' });
  // 수정 이력 저장
  await supabase.from('edit_history').insert({ post_id: parseInt(req.params.id), uid: req.user.id, before_title: post.title, before_body: post.body, edited_at: new Date().toISOString() });
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
  if (p&&p.uid!==uid) await sendNotif(p.uid,'like','회원님의 글 "'+p.title+'"에 좋아요가 달렸어요! ❤️',pid);
  await supabase.from('logs').insert({ uid, action: `게시글 좋아요 (#${pid})`, type: 'like' });
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
  if (post&&post.uid!==req.user.id) await sendNotif(post.uid,'comment','회원님의 글 "'+post.title+'"에 댓글이 달렸어요. 💬',postId);
  if (parentId) { const { data: pc } = await supabase.from('comments').select('uid').eq('id',parseInt(parentId)).single(); if (pc&&pc.uid!==req.user.id) await sendNotif(pc.uid,'reply','회원님의 댓글에 답글이 달렸어요. ↩',postId); }
  // 멘션 알림: @이름 파싱 후 해당 유저에게 알림
  const mentionMatches = (body||'').match(/@([가-힣a-zA-Z0-9_]+)/g);
  if (mentionMatches) {
    const mentionNames = [...new Set(mentionMatches.map(m => m.slice(1)))];
    for (const name of mentionNames) {
      const { data: mu } = await supabase.from('users').select('id').eq('name', name).single();
      if (mu && mu.id !== req.user.id) await sendNotif(mu.id, 'mention', `${req.user.name}님이 댓글에서 회원님을 멘션했어요. 💬`, postId);
    }
  }
  await supabase.from('logs').insert({ uid: req.user.id, action: `댓글 작성 (게시글 #${postId})`, type: 'comment' });
  res.json(data);
});

app.put('/api/comments/:id', auth, checkSuspended, async (req, res) => {
  const { body } = req.body;
  const { data: c } = await supabase.from('comments').select('uid').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '수정 권한이 없어요.' });
  await supabase.from('comments').update({ body:filterBadWords(sanBody(body)), edited:true }).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid: req.user.id, action: `댓글 수정 (#${req.params.id})`, type: 'edit' });
  res.json({ok:true});
});

app.delete('/api/comments/:id/mine', auth, async (req, res) => {
  const { data: c } = await supabase.from('comments').select('uid').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('comments').update({deleted:true}).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid: req.user.id, action: `댓글 삭제 (#${req.params.id})`, type: 'del' });
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

// DM 차단 (반드시 :partnerId 라우트보다 먼저 선언)
app.post('/api/dm/block/:uid', auth, async (req, res) => {
  const { uid } = req.params;
  if (uid === req.user.id) return res.status(400).json({ error: '자기 자신을 차단할 수 없어요.' });
  const { data: existing } = await supabase.from('dm_blocks').select('id').eq('blocker_uid', req.user.id).eq('blocked_uid', uid).single();
  if (existing) {
    await supabase.from('dm_blocks').delete().eq('id', existing.id);
    return res.json({ blocked: false });
  }
  await supabase.from('dm_blocks').insert({ blocker_uid: req.user.id, blocked_uid: uid });
  res.json({ blocked: true });
});

app.get('/api/dm/blocks', auth, async (req, res) => {
  const { data } = await supabase.from('dm_blocks').select('blocked_uid').eq('blocker_uid', req.user.id);
  res.json((data||[]).map(d => d.blocked_uid));
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
  // 차단 여부 확인
  const { data: blockData } = await supabase.from('dm_blocks').select('id').eq('blocker_uid', req.params.partnerId).eq('blocked_uid', req.user.id).single();
  if (blockData) return res.status(403).json({ error: '쪽지를 보낼 수 없는 상대예요.' });
  const { data, error } = await supabase.from('dms').insert({ from_uid:req.user.id, to_uid:req.params.partnerId, body:filterBadWords(sanBody(body)), read:false, from_name:req.user.name||req.user.id }).select().single();
  if (error) return res.status(500).json({ error: '쪽지 전송에 실패했어요: ' + error.message });
  await sendNotif(req.params.partnerId,'dm',req.user.name+'님에게 쪽지가 도착했어요. 📩');
  res.json(data||{ok:true});
});



// ══ NEIS 급식/시간표 ══
const NEIS_KEY = process.env.NEIS_KEY || 'a4189b4517b84ad593b912a5c8362bf5';
const SCHOOL_CODE = '7391126';
const OFFICE_CODE = 'F10';

app.get('/api/meal', auth, async (req, res) => {
  const date = req.query.date || new Date().toISOString().slice(0,10).replace(/-/g,'');
  try {
    const url = `https://open.neis.go.kr/hub/mealServiceDietInfo?KEY=${NEIS_KEY}&Type=json&ATPT_OFCDC_SC_CODE=${OFFICE_CODE}&SD_SCHUL_CODE=${SCHOOL_CODE}&MLSV_YMD=${date}`;
    const resp = await fetch(url);
    const data = await resp.json();
    if (data.mealServiceDietInfo) {
      const rows = data.mealServiceDietInfo[1].row;
      const meals = rows.map(r => ({
        type: r.MMEAL_SC_NM,
        menu: r.DDISH_NM.replace(/<br\/>/g, '\n').replace(/\d+\./g, '').trim(),
        cal: r.CAL_INFO,
        origin: r.ORPLC_INFO
      }));
      res.json({ date, meals });
    } else {
      res.json({ date, meals: [], message: '급식 정보가 없어요.' });
    }
  } catch(e) {
    res.status(500).json({ error: '급식 정보를 불러오지 못했어요.' });
  }
});

app.get('/api/timetable', auth, async (req, res) => {
  const { grade, classroom, date } = req.query;
  if (!grade || !classroom) return res.status(400).json({ error: '학년과 반을 입력해주세요.' });
  const today = date || new Date().toISOString().slice(0,10).replace(/-/g,'');
  // Get week dates (Mon-Fri)
  const d = new Date(today.slice(0,4)+'-'+today.slice(4,6)+'-'+today.slice(6,8));
  const day = d.getDay();
  const monday = new Date(d);
  monday.setDate(d.getDate() - (day===0?6:day-1));
  const friday = new Date(monday);
  friday.setDate(monday.getDate() + 4);
  const toStr = dt => dt.toISOString().slice(0,10).replace(/-/g,'');
  try {
    const url = `https://open.neis.go.kr/hub/misTimetable?KEY=${NEIS_KEY}&Type=json&ATPT_OFCDC_SC_CODE=${OFFICE_CODE}&SD_SCHUL_CODE=${SCHOOL_CODE}&GRADE=${grade}&CLASS_NM=${classroom}&TI_FROM_YMD=${toStr(monday)}&TI_TO_YMD=${toStr(friday)}`;
    const resp = await fetch(url);
    const data = await resp.json();
    if (data.misTimetable) {
      const rows = data.misTimetable[1].row;
      res.json({ grade, classroom, rows });
    } else {
      res.json({ grade, classroom, rows: [], message: '시간표 정보가 없어요.' });
    }
  } catch(e) {
    res.status(500).json({ error: '시간표를 불러오지 못했어요.' });
  }
});

// 프로필 학년/반 업데이트
app.put('/api/profile/gender', auth, async (req, res) => {
  const { gender } = req.body;
  if (!['male','female'].includes(gender)) return res.status(400).json({ error: '올바른 성별을 선택해주세요.' });
  const { data: user } = await supabase.from('users').select('gender').eq('id', req.user.id).single();
  if (user?.gender) return res.status(400).json({ error: '성별은 한 번만 설정할 수 있어요.' });
  await supabase.from('users').update({ gender }).eq('id', req.user.id);
  res.json({ ok: true, gender });
});

app.put('/api/profile/grade', auth, async (req, res) => {
  const { grade, classroom } = req.body;
  await supabase.from('users').update({ grade: parseInt(grade)||null, classroom: parseInt(classroom)||null }).eq('id', req.user.id);
  res.json({ ok: true });
});


// ══ 북마크 ══
app.get('/api/bookmarks', auth, async (req, res) => {
  const { data } = await supabase.from('bookmarks').select('post_id').eq('uid', req.user.id).order('created_at',{ascending:false});
  if (!data||!data.length) return res.json([]);
  const ids = data.map(b => b.post_id);
  const { data: posts } = await supabase.from('posts').select('*').in('id', ids).eq('deleted', false);
  res.json(posts||[]);
});

app.post('/api/bookmarks/:postId', auth, async (req, res) => {
  const postId = parseInt(req.params.postId);
  const { data: existing } = await supabase.from('bookmarks').select('id').eq('uid', req.user.id).eq('post_id', postId).single();
  if (existing) {
    await supabase.from('bookmarks').delete().eq('uid', req.user.id).eq('post_id', postId);
    return res.json({ bookmarked: false });
  }
  await supabase.from('bookmarks').insert({ uid: req.user.id, post_id: postId });
  await supabase.from('logs').insert({ uid: req.user.id, action: `북마크 추가 (#${postId})`, type: 'bookmark' });
  res.json({ bookmarked: true });
});

// ══ 학사일정 (DB 기반) ══
app.get('/api/schedule', auth, async (req, res) => {
  const { year, month } = req.query;
  const now = new Date();
  const y = parseInt(year || now.getFullYear());
  const m = parseInt(month || now.getMonth()+1);
  const from = `${y}-${String(m).padStart(2,'0')}-01`;
  const to = `${y}-${String(m).padStart(2,'0')}-31`;
  const { data } = await supabase.from('school_schedule').select('*').gte('date', from).lte('date', to).order('date');
  res.json(data||[]);
});

app.post('/api/schedule', auth, adminOnly, async (req, res) => {
  const { date, name, type } = req.body;
  if (!date||!name) return res.status(400).json({ error: '날짜와 일정명을 입력해주세요.' });
  const { error } = await supabase.from('school_schedule').insert({ date, name, type: type||'행사' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.put('/api/schedule/:id', auth, adminOnly, async (req, res) => {
  const { date, name, type } = req.body;
  await supabase.from('school_schedule').update({ date, name, type }).eq('id', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/schedule/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('school_schedule').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// ══ 음악공간 ══
app.get('/api/music', auth, async (req, res) => {
  const { data } = await supabase.from('music_posts').select('*').eq('approved', true).order('created_at', {ascending:false});
  res.json(data||[]);
});
app.get('/api/music/pending', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('music_posts').select('*').eq('approved', false).order('created_at', {ascending:false});
  res.json(data||[]);
});
app.post('/api/music', auth, checkSuspended, async (req, res) => {
  const { youtube_url, title, description } = req.body;
  if (!youtube_url) return res.status(400).json({ error: 'URL을 입력해주세요.' });
  const ytRegex = /^https?:\/\/(www\.)?(youtube\.com\/watch\?v=|youtu\.be\/)([\w-]+)/;
  if (!ytRegex.test(youtube_url)) return res.status(400).json({ error: '유튜브 링크만 가능해요.' });
  await supabase.from('music_posts').insert({ uid:req.user.id, author:req.user.name, youtube_url, title:title||'제목 없음', description:description||'', approved:false });
  res.json({ ok:true });
});
app.put('/api/music/:id/approve', auth, adminOnly, async (req, res) => {
  await supabase.from('music_posts').update({ approved:true }).eq('id', req.params.id);
  res.json({ ok:true });
});
app.delete('/api/music/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('music_posts').delete().eq('id', req.params.id);
  res.json({ ok:true });
});
app.post('/api/music/:id/like', auth, async (req, res) => {
  const { data } = await supabase.from('music_posts').select('likes').eq('id', req.params.id).single();
  await supabase.from('music_posts').update({ likes:(data?.likes||0)+1 }).eq('id', req.params.id);
  res.json({ ok:true });
});

// ══ 클럽 (관리자 전용 업로드) ══
app.get('/api/club', auth, async (req, res) => {
  const { data } = await supabase.from('club_posts').select('*').order('created_at', {ascending:false});
  res.json(data||[]);
});
app.post('/api/club', auth, adminOnly, async (req, res) => {
  const { youtube_url, title, description } = req.body;
  if (!youtube_url) return res.status(400).json({ error: 'URL을 입력해주세요.' });
  const ytRegex = /^https?:\/\/(www\.)?(youtube\.com\/watch\?v=|youtu\.be\/)([\w-]+)/;
  if (!ytRegex.test(youtube_url)) return res.status(400).json({ error: '유튜브 링크만 가능해요.' });
  await supabase.from('club_posts').insert({ uid:req.user.id, author:req.user.name, youtube_url, title:title||'제목 없음', description:description||'' });
  res.json({ ok:true });
});
app.delete('/api/club/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('club_posts').delete().eq('id', req.params.id);
  res.json({ ok:true });
});
app.post('/api/club/:id/like', auth, async (req, res) => {
  const { data } = await supabase.from('club_posts').select('likes').eq('id', req.params.id).single();
  await supabase.from('club_posts').update({ likes:(data?.likes||0)+1 }).eq('id', req.params.id);
  res.json({ ok:true });
});

// ══ 끝말잇기 AI ══
app.post('/api/wordchain', auth, async (req, res) => {
  const { word, difficulty } = req.body;
  if (!word) return res.status(400).json({ error: '단어를 입력해주세요.' });
  const lastChar = word[word.length-1];
  const diffMap = { easy:'쉬운 일상 단어', normal:'일반적인 단어', hard:'어렵고 다양한 단어' };
  const hint = diffMap[difficulty]||'일반적인 단어';
  // Simple AI: pick from predefined word lists based on last char
  const wordBank = {
    '가':['가방','가족','가수','가을','가위'],
    '나':['나무','나비','나라','나침반','나물'],
    '다':['다리','다람쥐','다이아몬드','다과'],
    '라':['라면','라디오','라켓'],
    '마':['마을','마음','마라톤','마늘'],
    '바':['바다','바람','바나나','바위'],
    '사':['사과','사람','사랑','사슴','사탕'],
    '아':['아이','아침','아버지','아기'],
    '자':['자동차','자연','자전거','자유'],
    '차':['차이','차량','차도'],
    '카':['카메라','카드'],
    '타':['타조','타워'],
    '파':['파도','파랑','파인애플'],
    '하':['하늘','하트','하마','하루'],
    '고':['고양이','고래','고구마','고속도로'],
    '나':['나무','나비','나라'],
    '도':['도서관','도끼','도움'],
    '로':['로봇','로켓'],
    '모':['모자','모래','모기'],
    '보':['보석','보트','보물'],
    '소':['소나무','소금','소방차'],
    '요':['요리','요술'],
    '조':['조각','조용함','조개'],
    '토':['토끼','토마토'],
    '포':['포도','포크','포옹'],
    '호':['호랑이','호수','호박'],
  };
  const candidates = wordBank[lastChar] || [];
  if (!candidates.length) return res.json({ aiWord: null, message: `"${lastChar}"로 시작하는 단어를 못 찾겠어요. 사용자 승리!`, win: true });
  const aiWord = candidates[Math.floor(Math.random()*candidates.length)];
  res.json({ aiWord, lastChar: aiWord[aiWord.length-1] });
});


// ══ 알림 설정 ══
app.get('/api/notif-settings', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('notif_like,notif_comment,notif_reply,notif_dm').eq('id', req.user.id).single();
  res.json({
    notif_like: data?.notif_like !== false,
    notif_comment: data?.notif_comment !== false,
    notif_reply: data?.notif_reply !== false,
    notif_dm: data?.notif_dm !== false,
  });
});
app.put('/api/notif-settings', auth, async (req, res) => {
  const { notif_like, notif_comment, notif_reply, notif_dm } = req.body;
  await supabase.from('users').update({ notif_like, notif_comment, notif_reply, notif_dm }).eq('id', req.user.id);
  res.json({ ok: true });
});

// 알림 전송 헬퍼 (묶음 처리 + 설정 반영)
async function sendNotif(to_uid, type, text, post_id=null) {
  // 본인 알림 제외
  if (!to_uid) return;
  // 설정 확인
  const { data: user } = await supabase.from('users').select('notif_like,notif_comment,notif_reply,notif_dm').eq('id', to_uid).single();
  if (!user) return;
  if (type === 'like' && user.notif_like === false) return;
  if (type === 'comment' && user.notif_comment === false) return;
  if (type === 'reply' && user.notif_reply === false) return;
  if (type === 'dm' && user.notif_dm === false) return;

  // 묶음 처리: 1시간 이내 같은 type+post_id 알림이 있으면 업데이트
  if (post_id && (type === 'like' || type === 'comment')) {
    const since = new Date(Date.now() - 60*60*1000).toISOString();
    const { data: existing } = await supabase.from('notifications')
      .select('id,text,count')
      .eq('to_uid', to_uid).eq('type', type).eq('post_id', post_id).eq('read', false)
      .gte('created_at', since).order('created_at', {ascending:false}).limit(1);
    if (existing && existing.length) {
      const cnt = (existing[0].count || 1) + 1;
      const baseText = type === 'like' ? '좋아요' : '댓글';
      await supabase.from('notifications').update({
        text: `회원님의 글에 ${baseText}가 ${cnt}개 달렸어요!`,
        count: cnt, read: false, created_at: new Date().toISOString()
      }).eq('id', existing[0].id);
      return;
    }
  }
  await supabase.from('notifications').insert({ to_uid, text, post_id, type, read: false, count: 1 });
}

// ══ 수정 이력 (관리자용) ══
app.get('/api/posts/:id/history', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('edit_history').select('*').eq('post_id', req.params.id).order('edited_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/comments/:id/history', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('edit_history').select('*').eq('comment_id', req.params.id).order('edited_at', { ascending: false });
  res.json(data || []);
});


// ══ 내 댓글 목록 ══
app.get('/api/profile/comments', auth, async (req, res) => {
  const { data } = await supabase.from('comments').select('id,body,post_id,created_at').eq('uid', req.user.id).eq('deleted', false).order('created_at', {ascending:false}).limit(50);
  res.json(data||[]);
});

// ══ 공지사항 고정 ══
app.post('/api/posts/:id/pin', auth, adminOnly, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('pinned').eq('id', req.params.id).single();
  if(!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  await supabase.from('posts').update({ pinned: !post.pinned }).eq('id', req.params.id);
  res.json({ pinned: !post.pinned });
});

// ══ 신고 + 팔로우/차단 ══
// ══ 팔로우/차단 ══
app.post('/api/follow/:uid', auth, async (req, res) => {
  const targetId = req.params.uid;
  if(targetId === req.user.id) return res.status(400).json({ error: '자신을 팔로우할 수 없어요.' });
  const { data: existing } = await supabase.from('follows').select('id').eq('follower_uid', req.user.id).eq('following_uid', targetId).single();
  if(existing) {
    await supabase.from('follows').delete().eq('follower_uid', req.user.id).eq('following_uid', targetId);
    return res.json({ following: false });
  }
  await supabase.from('follows').insert({ follower_uid: req.user.id, following_uid: targetId });
  res.json({ following: true });
});

app.post('/api/block/:uid', auth, async (req, res) => {
  const targetId = req.params.uid;
  if(targetId === req.user.id) return res.status(400).json({ error: '자신을 차단할 수 없어요.' });
  const { data: existing } = await supabase.from('blocks').select('id').eq('blocker_uid', req.user.id).eq('blocked_uid', targetId).single();
  if(existing) {
    await supabase.from('blocks').delete().eq('blocker_uid', req.user.id).eq('blocked_uid', targetId);
    return res.json({ blocked: false });
  }
  await supabase.from('blocks').insert({ blocker_uid: req.user.id, blocked_uid: targetId });
  res.json({ blocked: true });
});

app.get('/api/follow-status/:uid', auth, async (req, res) => {
  const targetId = req.params.uid;
  const [followData, blockData] = await Promise.all([
    supabase.from('follows').select('id').eq('follower_uid', req.user.id).eq('following_uid', targetId).single(),
    supabase.from('blocks').select('id').eq('blocker_uid', req.user.id).eq('blocked_uid', targetId).single()
  ]);
  res.json({ following: !!followData.data, blocked: !!blockData.data });
});

// 신고 7회 자동 숨김 확인 및 적용
app.post('/api/reports', auth, checkSuspended, async (req, res) => {
  const { postId, post_id, commentId, comment_id, violations, severity, detail, reason } = req.body;
  const pid = postId || post_id;
  const cid = commentId || comment_id || null;
  const finalReason = (violations && violations.length) ? violations.join(', ') + (detail ? ' / ' + detail : '') : (reason || detail || '');
  if (!finalReason) return res.status(400).json({ error: '신고 사유를 입력해주세요.' });
  // 중복 신고 방지
  let dupQ = supabase.from('reports').select('id').eq('reporter_uid', req.user.id).eq('resolved', false);
  if (pid) dupQ = dupQ.eq('post_id', pid);
  if (cid) dupQ = dupQ.eq('comment_id', cid);
  const { data: dupReport } = await dupQ.maybeSingle();
  if (dupReport) return res.status(400).json({ error: '이미 신고한 게시물이에요.' });

  const { error } = await supabase.from('reports').insert({
    post_id: pid, comment_id: cid, reporter_uid: req.user.id,
    reason: finalReason, violations: violations || [], severity: severity || 'mid',
    detail: detail || '', resolved: false
  });
  if (error) return res.status(400).json({ error: '신고 처리 중 오류가 발생했어요: ' + error.message });
  // 신고 7회 자동 숨김
  if(pid && !cid) {
    const { count } = await supabase.from('reports').select('id', { count: 'exact' }).eq('post_id', pid).eq('resolved', false);
    if(count >= 7) await supabase.from('posts').update({ deleted: true }).eq('id', pid);
  }
  res.json({ ok: true });
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

// ══ 공지 배너 ══
app.get('/api/notice-banner', async (req, res) => {
  const { data } = await supabase.from('notice_banner').select('*').eq('active', true).order('created_at',{ascending:false}).limit(1).single();
  res.json(data || null);
});
app.post('/api/admin/notice-banner', auth, adminOnly, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: '내용을 입력해주세요.' });
  await supabase.from('notice_banner').update({ active: false }).eq('active', true);
  const { data } = await supabase.from('notice_banner').insert({ text, active: true }).select().single();
  res.json(data);
});
app.delete('/api/admin/notice-banner', auth, adminOnly, async (req, res) => {
  await supabase.from('notice_banner').update({ active: false }).eq('active', true);
  res.json({ ok: true });
});



// ══ 이모지 반응 ══
app.get('/api/posts/:id/reactions', auth, async (req, res) => {
  const pid = req.params.id;
  const { data: all } = await supabase.from('reactions').select('emoji,uid').eq('post_id', pid);
  const counts = {};
  (all||[]).forEach(r => { counts[r.emoji] = (counts[r.emoji]||0)+1; });
  const my = (all||[]).filter(r=>r.uid===req.user.id).map(r=>r.emoji);
  res.json({ counts, my });
});

app.post('/api/posts/:id/reactions', auth, checkSuspended, async (req, res) => {
  const pid = req.params.id, uid = req.user.id, { emoji } = req.body;
  const allowed = ['🔥','😂','😮','😢','🎉','💯'];
  if (!allowed.includes(emoji)) return res.status(400).json({ error: '유효하지 않은 반응이에요.' });
  const { data: ex } = await supabase.from('reactions').select('id,emoji').eq('post_id',pid).eq('uid',uid).eq('emoji',emoji).single();
  if (ex) {
    await supabase.from('reactions').delete().eq('id',ex.id);
    const { count } = await supabase.from('reactions').select('id',{count:'exact'}).eq('post_id',pid).eq('emoji',emoji);
    return res.json({ active: false, count: count||0 });
  }
  // 기존 반응 삭제 (1개만 선택 가능)
  await supabase.from('reactions').delete().eq('post_id',pid).eq('uid',uid);
  await supabase.from('reactions').insert({ post_id: pid, uid, emoji });
  const { count } = await supabase.from('reactions').select('id',{count:'exact'}).eq('post_id',pid).eq('emoji',emoji);
  await supabase.from('logs').insert({ uid, action: `이모지 반응 ${emoji} (게시글 #${pid})`, type: 'like' });
  res.json({ active: true, count: count||0 });
});

// 수정 이력 조회 (본인 + 관리자만)
app.get('/api/posts/:id/history', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('uid').eq('id', req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: '이력을 볼 권한이 없어요.' });
  const { data } = await supabase.from('edit_history').select('*').eq('post_id', req.params.id).order('edited_at',{ascending:false});
  res.json(data||[]);
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
  const { data } = await supabase.from('users').select('id,name,role,suspended,warnings,created_at,deleted,last_ip,last_login,kakao_id').order('created_at',{ascending:false});
  res.json(data||[]);
});
app.put('/api/admin/users/:id/suspend', auth, adminOnly, async (req, res) => {
  const { suspend } = req.body;
  const { data: u } = await supabase.from('users').select('name').eq('id',req.params.id).single();
  await supabase.from('users').update({ suspended: suspend }).eq('id',req.params.id);
  if (suspend) await supabase.from('notifications').insert({to_uid:req.params.id,text:'🚫 관리자에 의해 계정이 정지됐어요.',read:false});
  await supabase.from('logs').insert({uid:req.user.id,action:(u?.name||req.params.id)+' 계정 '+(suspend?'정지':'해제')+' (관리자: '+req.user.id+')',type:'ban'});
  res.json({ok:true});
});
// 관리자 계정 삭제 (개인정보 초기화 + 정지)
app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const uid = req.params.id;
  if (uid === req.user.id) return res.status(400).json({ error: '자기 자신은 삭제할 수 없어요.' });
  const { data: u } = await supabase.from('users').select('name').eq('id', uid).single();
  if (!u) return res.status(404).json({ error: '사용자를 찾을 수 없어요.' });
  // 개인정보 초기화 + 정지 처리
  await supabase.from('users').update({
    name: '정지된 사용자',
    email: null,
    email_verified: false,
    avatar: null,
    kakao_id: null,
    google_id: null,
    naver_id: null,
    password: null,
    deleted: true,
    suspended: true,
    bday: null,
  }).eq('id', uid);
  // refresh_tokens 삭제
  await supabase.from('refresh_tokens').delete().eq('uid', uid);
  await supabase.from('logs').insert({ uid: req.user.id, action: `계정 삭제: ${u.name} (@${uid}) (관리자: ${req.user.id})`, type: 'ban' });
  res.json({ ok: true });
});

// 경고 부여 (관리자 + 매니저 가능)
app.post('/api/admin/users/:id/warn', auth, async (req, res) => {
  // 관리자 또는 매니저만 가능
  const { data: me } = await supabase.from('users').select('role').eq('id', req.user.id).single();
  if (!me || !['admin','manager'].includes(me.role)) return res.status(403).json({ error: '권한이 없어요.' });

  const { data: user } = await supabase.from('users').select('warnings,name').eq('id',req.params.id).single();
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없어요.' });
  if (req.params.id === req.user.id) return res.status(400).json({ error: '자신에게 경고를 줄 수 없어요.' });

  const nw = (user.warnings||0) + 1;
  const isManager = me.role === 'manager';
  const warnedBy = isManager ? '매니저' : '관리자';

  await supabase.from('users').update({ warnings: nw }).eq('id', req.params.id);
  await supabase.from('notifications').insert({ to_uid: req.params.id, text: `⚠️ ${warnedBy}로부터 경고를 받았어요. (누적 ${nw}회)`, read: false });

  // 경고 3회 이상 시 자동 정지 대신 관리자에게 알림
  if (nw >= 3) {
    const { data: admins } = await supabase.from('users').select('id').eq('role', 'admin');
    for (const admin of admins || []) {
      await supabase.from('notifications').insert({
        to_uid: admin.id,
        text: `🚨 ${user.name}(@${req.params.id})님이 경고 ${nw}회를 받았어요. 정지 여부를 확인해주세요.`,
        read: false
      });
    }
  }

  // 경고 로그 저장
  await supabase.from('warn_logs').insert({
    target_uid: req.params.id,
    target_name: user.name,
    warned_by: req.user.id,
    warned_by_role: me.role,
    warnings_total: nw
  });
  await supabase.from('logs').insert({ uid: req.user.id, action: `${user.name} 경고 부여 (${nw}회) (${warnedBy}: ${req.user.id})`, type: 'warn' });
  res.json({ ok: true, warnings: nw });
});

// 매니저 임명/해제
app.post('/api/admin/manager/:id', auth, adminOnly, async (req, res) => {
  const { data: user } = await supabase.from('users').select('id,name,role').eq('id', req.params.id).single();
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없어요.' });
  if (user.role === 'admin') return res.status(400).json({ error: '관리자는 변경할 수 없어요.' });
  const newRole = user.role === 'manager' ? 'user' : 'manager';
  await supabase.from('users').update({ role: newRole }).eq('id', req.params.id);
  await supabase.from('notifications').insert({ to_uid: req.params.id, text: newRole === 'manager' ? '🎖️ 매니저로 임명됐어요!' : '매니저 권한이 해제됐어요.', read: false });
  await supabase.from('logs').insert({ uid: req.user.id, action: `${user.name} 매니저 ${newRole==='manager'?'임명':'해제'} (관리자: ${req.user.id})`, type: 'warn' });
  res.json({ ok: true, role: newRole });
});

// 임시 제한
app.post('/api/admin/restrict/:id', auth, adminOnly, async (req, res) => {
  const { hours = 24 } = req.body;
  const until = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  const { data: user } = await supabase.from('users').select('name').eq('id', req.params.id).single();
  await supabase.from('users').update({ restricted_until: until }).eq('id', req.params.id);
  await supabase.from('notifications').insert({ to_uid: req.params.id, text: `⏰ ${hours}시간 동안 게시글 작성이 제한됐어요.`, read: false });
  await supabase.from('logs').insert({ uid: req.user.id, action: `${user?.name} ${hours}시간 임시제한 (관리자: ${req.user.id})`, type: 'ban' });
  res.json({ ok: true, until });
});

app.delete('/api/admin/restrict/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('users').update({ restricted_until: null }).eq('id', req.params.id);
  res.json({ ok: true });
});
app.delete('/api/admin/posts/:id', auth, adminOnly, async (req, res) => {
  const { data: p } = await supabase.from('posts').select('title').eq('id',req.params.id).single();
  await supabase.from('posts').update({deleted:true,pinned:false}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:req.user.id,action:'게시글 삭제: "'+p?.title+'" (관리자: '+req.user.id+')',type:'del'});
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
  // 신고 처리 누적 시 자동 경고 (같은 유저 게시글 3회 처리 시)
  const { data: fullReport } = await supabase.from('reports').select('post_id').eq('id', req.params.id).single();
  if (fullReport?.post_id) {
    const { data: post } = await supabase.from('posts').select('uid').eq('id', fullReport.post_id).single();
    if (post?.uid) {
      const { count: resolvedCount } = await supabase.from('reports').select('id', {count:'exact'})
        .eq('resolved', true)
        .in('post_id', supabase.from('posts').select('id').eq('uid', post.uid));
      // 3, 5, 7회마다 경고
      if (resolvedCount && [3,5,7].includes(resolvedCount)) {
        const { data: targetUser } = await supabase.from('users').select('warnings,name').eq('id', post.uid).single();
        const nw = (targetUser?.warnings||0)+1;
        await supabase.from('users').update({warnings:nw}).eq('id', post.uid);
        await supabase.from('notifications').insert({to_uid:post.uid,text:`⚠️ 신고 누적으로 경고가 부여됐어요. (누적 ${nw}회)`,read:false});
        // 자동 정지 대신 관리자 알림
        const { data: admins } = await supabase.from('users').select('id').eq('role','admin');
        for (const admin of admins||[]) {
          await supabase.from('notifications').insert({to_uid:admin.id,text:`🚨 ${targetUser?.name}님이 신고 누적 경고 ${nw}회를 받았어요. 정지 여부를 확인해주세요.`,read:false});
        }
      }
    }
  }
  await supabase.from('logs').insert({uid:req.user.id,action:'신고 처리완료 (관리자: '+req.user.id+')',type:'del'});
  res.json({ok:true});
});
// 경고 로그 조회
// 보안 로그 조회
app.get('/api/admin/security-logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('security_logs').select('*').order('created_at', { ascending: false }).limit(200);
  res.json(data || []);
});

app.get('/api/admin/warn-logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('warn_logs').select('*').order('created_at', { ascending: false }).limit(100);
  res.json(data || []);
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
server.listen(PORT, () => {
  console.log(`🚀 에브리유니 서버 실행 중 → 포트 ${PORT}`);
  // 90일 이상 로그 자동 삭제 (서버 시작 시 + 매일)
  async function cleanOldLogs() {
    const cutoff = new Date(Date.now() - 90*24*60*60*1000).toISOString();
    await supabase.from('logs').delete().lt('created_at', cutoff);
    await supabase.from('security_logs').delete().lt('created_at', cutoff);
    await supabase.from('warn_logs').delete().lt('created_at', cutoff);
    await supabase.from('refresh_tokens').delete().lt('expires_at', new Date().toISOString());
    console.log('🧹 오래된 로그 정리 완료');
  }
  cleanOldLogs();
  setInterval(cleanOldLogs, 24*60*60*1000); // 매일 실행
});

// ── 전체 공지 발송 (관리자) ──
app.post('/api/admin/notice', auth, adminOnly, rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: '공지는 1시간에 10회까지만 보낼 수 있어요.' } }), async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: '내용을 입력해주세요.' });
  const { data: users } = await supabase.from('users').select('id').eq('deleted', false).eq('suspended', false);
  if (users && users.length) {
    const notifications = users.map(u => ({ to_uid: u.id, text: '📢 공지: ' + sanBody(message), read: false }));
    await supabase.from('notifications').insert(notifications);
  }
  await supabase.from('logs').insert({ uid: req.user.id, action: '전체 공지 발송: ' + message + ' (관리자: ' + req.user.id + ')', type: 'post' });
  res.json({ ok: true });
});

// ── posts 테이블 tags 컬럼 지원 ──
// database.sql에서 아래 SQL 실행 필요:
// alter table posts add column if not exists tags text[] default '{}';

// ═══════════════════════════════════════════
// Supabase Storage 파일 업로드
// ═══════════════════════════════════════════
app.post('/api/upload', auth, checkSuspended, async (req, res) => {
  const { file, fileName } = req.body;
  if (!file || !fileName) return res.status(400).json({ error: '파일 정보가 없어요.' });

  const base64Data = file.replace(/^data:[^;]+;base64,/, '');
  const buffer = Buffer.from(base64Data, 'base64');

  const isPrivileged = req.user.role === 'admin' || req.user.role === 'manager';
  const maxSize = isPrivileged ? 100 * 1024 * 1024 : 30 * 1024 * 1024;
  if (buffer.length > maxSize) return res.status(400).json({ error: `파일 크기는 ${isPrivileged ? '100MB' : '30MB'} 이하여야 해요.` });

  const used = await getR2Usage();
  if (used + buffer.length > 9.5 * 1024 * 1024 * 1024) {
    return res.status(400).json({ error: '저장공간이 부족해요. 관리자에게 문의하세요.' });
  }

  const ext = fileName.split('.').pop().toLowerCase();
  const ALLOWED_EXTS = ['jpg','jpeg','png','gif','webp','pdf','docx','xlsx','pptx','txt'];
  const BLOCKED_EXTS = ['html','htm','js','ts','php','py','exe','bat','sh','cmd','apk','msi','svg','zip'];
  if (BLOCKED_EXTS.includes(ext)) return res.status(400).json({ error: `${ext} 파일은 업로드할 수 없어요.` });
  if (!ALLOWED_EXTS.includes(ext)) return res.status(400).json({ error: '허용되지 않는 파일 형식이에요.' });

  const EXT_CONTENT_TYPE = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', pdf: 'application/pdf',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    txt: 'text/plain',
  };
  const safeContentType = EXT_CONTENT_TYPE[ext] || 'application/octet-stream';
  const safeName = Date.now() + '_' + req.user.id + '.' + ext;
  const r2Key = 'uploads/' + req.user.id + '/' + safeName;

  try {
    await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: r2Key, Body: buffer, ContentType: safeContentType }));
  } catch(e) {
    return res.status(500).json({ error: 'R2 업로드 실패: ' + e.message });
  }

  await updateR2Usage(buffer.length);
  await supabase.from('logs').insert({ uid: req.user.id, action: `파일 업로드: ${fileName} (${Math.round(buffer.length/1024)}KB)`, type: 'upload' });
  const url = R2_PUBLIC_URL + '/' + r2Key;
  res.json({ url, path: r2Key, name: fileName, size: buffer.length });
});

// 파일 삭제
app.delete('/api/upload', auth, async (req, res) => {
  const { path } = req.body;
  if (!path) return res.status(400).json({ error: '경로가 없어요.' });
  try {
    await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: path }));
  } catch(e) { return res.status(500).json({ error: 'R2 삭제 실패: ' + e.message }); }
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
  const ALLOWED_IMG_EXTS = ['jpg','jpeg','png','gif','webp'];
  if (!ALLOWED_IMG_EXTS.includes(ext)) return res.status(400).json({ error: '이미지 파일만 업로드할 수 있어요.' });
  const r2AvatarKey = 'avatars/' + req.user.id + '.' + ext;
  try {
    await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: r2AvatarKey, Body: buffer, ContentType: 'image/' + (ext === 'jpg' ? 'jpeg' : ext) }));
  } catch(e) { return res.status(500).json({ error: '프로필 사진 업로드 실패: ' + e.message }); }
  const avatarUrl = R2_PUBLIC_URL + '/' + r2AvatarKey;
  await supabase.from('users').update({ avatar: avatarUrl }).eq('id', req.user.id);
  res.json({ url: avatarUrl });
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


const resend = new Resend(process.env.RESEND_API_KEY);

// ══ 이메일 인증 ══
app.post('/api/auth/send-verify', async (req, res) => {
  const { email, userId } = req.body;
  if (!email || !userId) return res.status(400).json({ error: '이메일과 아이디를 입력해주세요.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: '올바른 이메일 주소를 입력해주세요.' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  // 임시 테이블에 저장 (회원가입 전에도 동작)
  await supabase.from('email_verifications').delete().eq('user_id', userId);
  await supabase.from('email_verifications').insert({ user_id: userId, email, code, expires_at: expires });
  try {
    await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: email,
      subject: '에브리유니 이메일 인증',
      html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px;">
        <h2 style="color:#2563eb;">에브리유니 이메일 인증</h2>
        <p>아래 인증 코드를 입력해주세요.</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;padding:20px;background:#f3f4f6;border-radius:8px;margin:16px 0;">${code}</div>
        <p style="color:#6b7280;font-size:13px;">이 코드는 10분 후 만료됩니다.</p>
      </div>`
    });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: '이메일 발송에 실패했어요: ' + e.message });
  }
});

app.post('/api/auth/verify-email', async (req, res) => {
  const { userId, code } = req.body;
  const { data: verif } = await supabase.from('email_verifications').select('*').eq('user_id', userId).single();
  if (!verif) return res.status(404).json({ error: '인증 요청을 찾을 수 없어요. 코드를 다시 발송해주세요.' });
  if (verif.code !== code) return res.status(400).json({ error: '인증 코드가 틀렸어요.' });
  if (new Date() > new Date(verif.expires_at)) return res.status(400).json({ error: '인증 코드가 만료됐어요. 다시 발송해주세요.' });
  // 실제 유저가 있으면 DB 업데이트, 없으면 임시 완료 상태만 저장
  const { data: user } = await supabase.from('users').select('id').eq('id', userId).single();
  if (user) await supabase.from('users').update({ email: verif.email, email_verified: true }).eq('id', userId);
  await supabase.from('email_verifications').update({ verified: true }).eq('user_id', userId);
  res.json({ ok: true, email: verif.email });
});

// ══ 출석체크 ══

// 출석 칭호 계산 함수
function getAttendanceTitle(total) {
  if (total >= 365) return { title: '출석왕', icon: '🏆', days: 365 };
  if (total >= 100) return { title: '개근상', icon: '👑', days: 100 };
  if (total >= 30)  return { title: '성실러', icon: '⭐', days: 30 };
  if (total >= 7)   return { title: '새싹', icon: '🌱', days: 7 };
  return null;
}
app.post('/api/attendance', auth, checkSuspended, async (req, res) => {
  const today = new Date().toLocaleDateString('ko-KR', {timeZone:'Asia/Seoul'}).replace(/\. /g,'-').replace(/\.$/, '');
  const { data: existing } = await supabase.from('attendance').select('id').eq('uid', req.user.id).eq('date', today).single();
  if (existing) return res.status(400).json({ error: '오늘은 이미 출석했어요! 🎉' });
  await supabase.from('attendance').insert({ uid: req.user.id, date: today });
  const { count } = await supabase.from('attendance').select('id', { count: 'exact' }).eq('uid', req.user.id);
  const total = count || 1;
  // 연속 출석 계산
  const { data: recent } = await supabase.from('attendance').select('date').eq('uid', req.user.id).order('date', {ascending:false}).limit(100);
  let streak = 1;
  if (recent && recent.length > 1) {
    const dates = recent.map(r => r.date);
    for (let i = 1; i < dates.length; i++) {
      const prev = new Date(dates[i-1]), curr = new Date(dates[i]);
      const diff = Math.round((prev - curr) / (1000*60*60*24));
      if (diff === 1) streak++;
      else break;
    }
  }
  const titleInfo = getAttendanceTitle(total);
  // 칭호 달성 알림
  if (titleInfo && [7,30,100,365].includes(total)) {
    await supabase.from('notifications').insert({to_uid: req.user.id, text: `${titleInfo.icon} ${total}일 출석 달성! "${titleInfo.title}" 칭호를 획득했어요!`, read: false});
  }
  res.json({ ok: true, total, streak, title: titleInfo });
});

app.get('/api/attendance', auth, async (req, res) => {
  const { count } = await supabase.from('attendance').select('id', { count: 'exact' }).eq('uid', req.user.id);
  const today = new Date().toLocaleDateString('ko-KR', {timeZone:'Asia/Seoul'}).replace(/\. /g,'-').replace(/\.$/, '');
  const { data: todayData } = await supabase.from('attendance').select('id').eq('uid', req.user.id).eq('date', today).single();
  // 연속 출석 계산
  const { data: recent } = await supabase.from('attendance').select('date').eq('uid', req.user.id).order('date', {ascending:false}).limit(100);
  let streak = 0;
  if (recent && recent.length) {
    const dates = recent.map(r => r.date);
    if (dates[0] === today) {
      streak = 1;
      for (let i = 1; i < dates.length; i++) {
        const prev = new Date(dates[i-1]), curr = new Date(dates[i]);
        const diff = Math.round((prev - curr) / (1000*60*60*24));
        if (diff === 1) streak++;
        else break;
      }
    }
  }
  const total = count || 0;
  res.json({ total, checkedToday: !!todayData, streak, title: getAttendanceTitle(total) });
});

// ══ 서버 기반 랭킹 ══
app.post('/api/rankings', auth, async (req, res) => {
  const { game, score } = req.body;
  if (!game || score === undefined) return res.status(400).json({ error: '게임과 점수를 입력해주세요.' });
  const lowerIsBetter = game.includes('minesweeper') || game === 'reaction';
  const { data: existing } = await supabase.from('game_rankings').select('score').eq('uid', req.user.id).eq('game', game).order('score', { ascending: lowerIsBetter }).limit(1).single();
  if (existing) {
    const isBetter = lowerIsBetter ? score < existing.score : score > existing.score;
    if (!isBetter) return res.json({ ok: true, updated: false });
    await supabase.from('game_rankings').delete().eq('uid', req.user.id).eq('game', game);
  }
  // 임시로 실명으로 저장 (닉네임 확정 전)
  await supabase.from('game_rankings').insert({ uid: req.user.id, name: req.user.name, game, score, pending: true });
  // 현재 순위 계산
  const { data: allScores } = await supabase.from('game_rankings').select('score').eq('game', game).eq('pending', false).order('score', { ascending: lowerIsBetter });
  const rank = lowerIsBetter
    ? (allScores||[]).filter(r => r.score < score).length + 1
    : (allScores||[]).filter(r => r.score > score).length + 1;
  res.json({ ok: true, updated: true, rank });
});

// 닉네임 확정 등록
app.post('/api/rankings/name', auth, async (req, res) => {
  const { game, score, name } = req.body;
  if(!game || !name) return res.status(400).json({ error: '정보가 부족해요.' });
  await supabase.from('game_rankings').update({ name: name.slice(0,10), pending: false }).eq('uid', req.user.id).eq('game', game).eq('score', score);
  res.json({ ok: true });
});

app.get('/api/rankings/:game', auth, async (req, res) => {
  const lowerIsBetter = req.params.game.includes('minesweeper') || req.params.game === 'reaction';
  let query = supabase.from('game_rankings').select('name,score,created_at').eq('game', req.params.game);
  if(req.query.exclude_pending === 'true') query = query.neq('pending', true);
  const { data } = await query.order('score', { ascending: lowerIsBetter }).limit(10);
  res.json(data || []);
});

// ══ IP 차단 ══
app.get('/api/admin/banned-ips', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('banned_ips').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/admin/banned-ips', auth, adminOnly, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP를 입력해주세요.' });
  await supabase.from('banned_ips').upsert({ ip, reason: reason || '', created_at: new Date().toISOString() });
  res.json({ ok: true });
});

app.delete('/api/admin/banned-ips/:ip', auth, adminOnly, async (req, res) => {
  await supabase.from('banned_ips').delete().eq('ip', req.params.ip);
  res.json({ ok: true });
});

// IP 차단 미들웨어



// ══ 클럽 영상 댓글 ══
app.get('/api/club/:id/comments', auth, async (req, res) => {
  const { data } = await supabase.from('club_comments').select('*').eq('video_id', req.params.id).eq('deleted', false).order('created_at');
  res.json(data||[]);
});

app.post('/api/club/:id/comments', auth, checkSuspended, async (req, res) => {
  const { body } = req.body;
  if(!body?.trim()) return res.status(400).json({ error: '댓글을 입력해주세요.' });
  const { data, error } = await supabase.from('club_comments').insert({ video_id: parseInt(req.params.id), uid: req.user.id, author: req.user.name, body: filterBadWords(sanBody(body)), deleted: false }).select().single();
  if(error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/club/:id/comments/:commentId', auth, adminOnly, async (req, res) => {
  await supabase.from('club_comments').update({ deleted: true }).eq('id', req.params.commentId);
  res.json({ ok: true });
});

// ══ IP 차단 테이블 ══

// ══ 카카오 로그인 ══
const KAKAO_REST_KEY = process.env.KAKAO_REST_KEY;
const KAKAO_REDIRECT_URI = process.env.KAKAO_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/kakao/callback';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://everyu-frontend.vercel.app';

// 카카오 로그인 시작
app.get('/api/auth/kakao', (req, res) => {
  const kakaoAuthUrl = `https://kauth.kakao.com/oauth/authorize?client_id=${KAKAO_REST_KEY}&redirect_uri=${encodeURIComponent(KAKAO_REDIRECT_URI)}&response_type=code`;
  res.redirect(kakaoAuthUrl);
});

// 카카오 콜백
app.get('/api/auth/kakao/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}?kakao_error=cancelled`);

  try {
    // 1. 인가코드 → access_token 교환
    const tokenRes = await fetch('https://kauth.kakao.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: KAKAO_REST_KEY,
        redirect_uri: KAKAO_REDIRECT_URI,
        code,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('토큰 발급 실패');

    // 2. access_token → 카카오 사용자 정보
    const userRes = await fetch('https://kapi.kakao.com/v2/user/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const kakaoUser = await userRes.json();
    const kakaoId = String(kakaoUser.id);
    const kakaoNickname = kakaoUser.kakao_account?.profile?.nickname || '카카오유저';
    const kakaoEmail = kakaoUser.kakao_account?.email || null;

    // 3. DB에서 kakao_id로 기존 유저 조회
    let { data: user } = await supabase.from('users').select('*').eq('kakao_id', kakaoId).single();

    if (!user) {
      // 4. 신규 유저 자동 가입
      const newId = 'kakao_' + kakaoId;
      const safeName = kakaoNickname.slice(0, 20);
      const { data: newUser, error: insertErr } = await supabase.from('users').insert({
        id: newId,
        name: safeName,
        kakao_id: kakaoId,
        email: kakaoEmail,
        email_verified: !!kakaoEmail,
        password: null,
        role: 'user',
        suspended: false,
        warnings: 0,
      }).select().single();
      if (insertErr) throw new Error('회원가입 실패: ' + insertErr.message);
      user = newUser;
      await supabase.from('logs').insert({ uid: newId, action: '카카오 회원가입', type: 'login' });
    } else if (kakaoEmail && !user.email) {
      // 기존 유저인데 이메일 없으면 업데이트
      await supabase.from('users').update({ email: kakaoEmail, email_verified: true }).eq('id', user.id);
    }

    if (user.suspended) return res.redirect(`${FRONTEND_URL}?kakao_error=suspended`);

    // 5. JWT 발급
    const jwtToken = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
    // refresh_tokens DB 저장
    await supabase.from('refresh_tokens').insert({ uid: user.id, token: refreshToken, expires_at: new Date(Date.now()+7*24*60*60*1000).toISOString() });
    await supabase.from('logs').insert({ uid: user.id, action: '카카오 로그인', type: 'login' });

    // 6. 프론트로 redirect (토큰을 URL 파라미터로 전달)
    const isNewKakaoUser = !user.grade || !user.classroom;
    const userData = encodeURIComponent(JSON.stringify({ id: user.id, name: user.name, role: user.role, bday: user.bday, warnings: user.warnings, grade: user.grade, classroom: user.classroom, needsProfile: isNewKakaoUser }));
    res.redirect(`${FRONTEND_URL}?kakao_token=${jwtToken}&kakao_refresh=${refreshToken}&kakao_user=${userData}`);

  } catch (e) {
    console.error('카카오 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?kakao_error=server_error`);
  }
});

// ══ 구글 로그인 ══
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/google/callback';

app.get('/api/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account',
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}?google_error=cancelled`);
  try {
    // 1. 인가코드 → access_token 교환
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('토큰 발급 실패');

    // 2. 사용자 정보 조회
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const googleUser = await userRes.json();
    const googleId = String(googleUser.id);
    const googleName = googleUser.name || '구글유저';
    const googleEmail = googleUser.email || null;
    const googleAvatar = googleUser.picture || null;

    // 3. DB에서 google_id로 기존 유저 조회
    let { data: user } = await supabase.from('users').select('*').eq('google_id', googleId).single();

    if (!user) {
      // 4. 신규 유저 자동 가입
      const newId = 'google_' + googleId;
      const safeName = googleName.slice(0, 20);
      const { data: newUser, error: insertErr } = await supabase.from('users').insert({
        id: newId,
        name: safeName,
        google_id: googleId,
        email: googleEmail,
        email_verified: !!googleEmail,
        avatar: googleAvatar,
        password: null,
        role: 'user',
        suspended: false,
        warnings: 0,
      }).select().single();
      if (insertErr) throw new Error('회원가입 실패: ' + insertErr.message);
      user = newUser;
      await supabase.from('logs').insert({ uid: newId, action: '구글 회원가입', type: 'login' });
    }

    if (user.suspended) return res.redirect(`${FRONTEND_URL}?google_error=suspended`);

    // 5. JWT 발급
    const jwtToken = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
    await supabase.from('refresh_tokens').insert({ uid: user.id, token: refreshToken, expires_at: new Date(Date.now()+7*24*60*60*1000).toISOString() });
    await supabase.from('logs').insert({ uid: user.id, action: '구글 로그인', type: 'login' });

    // 6. 프론트로 redirect
    const isNewUser = !user.grade || !user.classroom;
    const userData = encodeURIComponent(JSON.stringify({ id: user.id, name: user.name, role: user.role, bday: user.bday, warnings: user.warnings, grade: user.grade, classroom: user.classroom, needsProfile: isNewUser, avatar: user.avatar, google_id: googleId }));
    res.redirect(`${FRONTEND_URL}?google_token=${jwtToken}&google_refresh=${refreshToken}&google_user=${userData}`);

  } catch (e) {
    console.error('구글 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?google_error=server_error`);
  }
});

// ══ 네이버 로그인 ══
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;
const NAVER_REDIRECT_URI = process.env.NAVER_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/naver/callback';

app.get('/api/auth/naver', (req, res) => {
  const state = Math.random().toString(36).substring(2);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: NAVER_CLIENT_ID,
    redirect_uri: NAVER_REDIRECT_URI,
    state,
  });
  res.redirect('https://nid.naver.com/oauth2.0/authorize?' + params.toString());
});

app.get('/api/auth/naver/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}?naver_error=cancelled`);
  try {
    // 1. 인가코드 → access_token 교환
    const tokenRes = await fetch('https://nid.naver.com/oauth2.0/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: NAVER_CLIENT_ID,
        client_secret: NAVER_CLIENT_SECRET,
        redirect_uri: NAVER_REDIRECT_URI,
        code,
        state: req.query.state || '',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('토큰 발급 실패');

    // 2. 사용자 정보 조회
    const userRes = await fetch('https://openapi.naver.com/v1/nid/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const naverData = await userRes.json();
    const naverUser = naverData.response;
    const naverId = String(naverUser.id);
    const naverName = (naverUser.nickname || naverUser.name || '네이버유저').slice(0, 20);
    const naverEmail = naverUser.email || null;
    const naverAvatar = naverUser.profile_image || null;
    const naverGender = naverUser.gender === 'M' ? 'male' : naverUser.gender === 'F' ? 'female' : null;

    // 3. DB에서 naver_id로 기존 유저 조회
    let { data: user } = await supabase.from('users').select('*').eq('naver_id', naverId).single();

    if (!user) {
      // 4. 신규 유저 자동 가입
      const newId = 'naver_' + naverId;
      const { data: newUser, error: insertErr } = await supabase.from('users').insert({
        id: newId,
        name: naverName,
        naver_id: naverId,
        email: naverEmail,
        email_verified: !!naverEmail,
        avatar: naverAvatar,
        gender: naverGender,
        password: null,
        role: 'user',
        suspended: false,
        warnings: 0,
      }).select().single();
      if (insertErr) throw new Error('회원가입 실패: ' + insertErr.message);
      user = newUser;
      await supabase.from('logs').insert({ uid: newId, action: '네이버 회원가입', type: 'login' });
    } else {
      // 기존 유저 - 이메일/아바타 업데이트
      const updates = {};
      if (naverEmail && !user.email) { updates.email = naverEmail; updates.email_verified = true; }
      if (naverAvatar && !user.avatar) updates.avatar = naverAvatar;
      if (Object.keys(updates).length) await supabase.from('users').update(updates).eq('id', user.id);
    }

    if (user.suspended) return res.redirect(`${FRONTEND_URL}?naver_error=suspended`);

    // 5. JWT 발급
    const jwtToken = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
    await supabase.from('refresh_tokens').insert({ uid: user.id, token: refreshToken, expires_at: new Date(Date.now()+7*24*60*60*1000).toISOString() });
    await supabase.from('logs').insert({ uid: user.id, action: '네이버 로그인', type: 'login' });

    // 6. 프론트로 redirect
    const isNewUser = !user.grade || !user.classroom;
    const userData = encodeURIComponent(JSON.stringify({ id: user.id, name: user.name, role: user.role, bday: user.bday, warnings: user.warnings, grade: user.grade, classroom: user.classroom, needsProfile: isNewUser, avatar: user.avatar }));
    res.redirect(`${FRONTEND_URL}?naver_token=${jwtToken}&naver_refresh=${refreshToken}&naver_user=${userData}`);

  } catch(e) {
    console.error('네이버 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?naver_error=server_error`);
  }
});

// ══ 에러 핸들러 (반드시 모든 라우트 뒤에 위치해야 함) ══
app.use((req,res) => res.status(404).json({error:'존재하지 않는 API예요.'}));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:'서버 오류가 발생했어요.'}); });
