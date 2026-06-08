require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { S3Client } = require('@aws-sdk/client-s3');
const webpush = require('web-push');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SECRET = process.env.JWT_SECRET || 'everyu-secret-2024';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'everyu-refresh-2024';
const NEIS_KEY = process.env.NEIS_KEY || 'a4189b4517b84ad593b912a5c8362bf5';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://everyu-frontend.vercel.app';

// R2
const r2 = new S3Client({
  endpoint: process.env.R2_ENDPOINT,
  region: 'auto',
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY, secretAccessKey: process.env.R2_SECRET_KEY },
});
const R2_BUCKET = process.env.R2_BUCKET || 'everyu-files';
const R2_PUBLIC_URL = (process.env.R2_PUBLIC_URL || '').replace(/\/$/, '');

// Web Push
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(process.env.VAPID_EMAIL || 'mailto:admin@everyu.app', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
}

// IP 차단 캐시
let bannedIpCache = new Set();
let bannedIpCacheTime = 0;
async function getBannedIps() {
  if (Date.now() - bannedIpCacheTime > 5 * 60 * 1000) {
    const { data } = await supabase.from('banned_ips').select('ip');
    bannedIpCache = new Set((data||[]).map(d => d.ip));
    bannedIpCacheTime = Date.now();
  }
  return bannedIpCache;
}

// R2 사용량
async function getR2Usage() {
  const { data } = await supabase.from('r2_usage').select('total_bytes').eq('id', 1).single();
  return data?.total_bytes || 0;
}
async function updateR2Usage(bytes) {
  const current = await getR2Usage();
  await supabase.from('r2_usage').upsert({ id: 1, total_bytes: current + bytes });
}

// 금지어
const BANNED_WORDS = ['개새끼','씨발','시발','병신','지랄','꺼져','닥쳐','죽어','미친놈','미친년','fuck','shit','bitch','ass','damn'];
function filterBadWords(text) {
  if (!text) return text;
  let result = text;
  BANNED_WORDS.forEach(w => { result = result.replace(new RegExp(w, 'gi'), '*'.repeat(w.length)); });
  return result;
}
function sanBody(text) {
  if (!text) return '';
  return text.replace(/</g,'&lt;').replace(/>/g,'&gt;').slice(0, 5000);
}

// 위경도 → 기상청 격자 변환
function latLonToGrid(lat, lon) {
  const RE=6371.00877,GRID=5.0,SLAT1=30.0,SLAT2=60.0,OLON=126.0,OLAT=38.0,XO=43,YO=136;
  const DEGRAD=Math.PI/180.0,re=RE/GRID;
  const slat1=SLAT1*DEGRAD,slat2=SLAT2*DEGRAD,olon=OLON*DEGRAD,olat=OLAT*DEGRAD;
  let sn=Math.tan(Math.PI*0.25+slat2*0.5)/Math.tan(Math.PI*0.25+slat1*0.5);
  sn=Math.log(Math.cos(slat1)/Math.cos(slat2))/Math.log(sn);
  let sf=Math.tan(Math.PI*0.25+slat1*0.5);
  sf=Math.pow(sf,sn)*Math.cos(slat1)/sn;
  let ro=Math.tan(Math.PI*0.25+olat*0.5);
  ro=re*sf/Math.pow(ro,sn);
  let ra=Math.tan(Math.PI*0.25+lat*DEGRAD*0.5);
  ra=re*sf/Math.pow(ra,sn);
  let theta=lon*DEGRAD-olon;
  if(theta>Math.PI)theta-=2.0*Math.PI;
  if(theta<-Math.PI)theta+=2.0*Math.PI;
  theta*=sn;
  return{nx:Math.round(ra*Math.sin(theta)+XO),ny:Math.round(ro-ra*Math.cos(theta)+YO)};
}

// 알림 발송
async function sendNotif(to_uid, type, text, post_id=null) {
  if (!to_uid) return;
  const { data: user } = await supabase.from('users').select('notif_like,notif_comment,notif_reply,notif_dm').eq('id', to_uid).single();
  if (type==='like'&&user&&!user.notif_like) return;
  if ((type==='comment'||type==='mention')&&user&&!user.notif_comment) return;
  if (type==='reply'&&user&&!user.notif_reply) return;
  if (type==='dm'&&user&&!user.notif_dm) return;
  const { data: existing } = await supabase.from('notifications').select('id,count').eq('to_uid',to_uid).eq('type',type).eq('post_id',post_id).eq('read',false).gte('created_at',new Date(Date.now()-3600000).toISOString()).limit(1);
  if (existing && existing.length) {
    const cnt=(existing[0].count||1)+1;
    const baseText=type==='like'?'좋아요':'댓글';
    const bundledText=`회원님의 글에 ${baseText}가 ${cnt}개 달렸어요!`;
    await supabase.from('notifications').update({text:bundledText,count:cnt,read:false,created_at:new Date().toISOString()}).eq('id',existing[0].id);
    const pushUrl=post_id?`/?post=${post_id}`:'/';
    await sendPush(to_uid,'에브리유니 🎓',bundledText,pushUrl);
    return;
  }
  await supabase.from('notifications').insert({to_uid,text,post_id,type,read:false,count:1});
  const pushUrl=post_id?`/?post=${post_id}`:'/';
  await sendPush(to_uid,'에브리유니 🎓',text,pushUrl);
}

async function sendPush(uid,title,body,url='/') {
  if (!process.env.VAPID_PUBLIC_KEY) return;
  try {
    const {data}=await supabase.from('push_subscriptions').select('subscription').eq('uid',uid).single();
    if(!data)return;
    const subscription=JSON.parse(data.subscription);
    await webpush.sendNotification(subscription,JSON.stringify({title,body,url,tag:uid}));
  } catch(e) { if(e.statusCode===410)await supabase.from('push_subscriptions').delete().eq('uid',uid); }
}

// Rate Limiters
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: '너무 많이 시도했어요. 15분 후 다시 시도해주세요.' } });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '가입 시도가 너무 많아요.' } });
const postLimiter = rateLimit({ windowMs: 60*1000, max: 10, message: { error: '너무 빠르게 게시글을 작성하고 있어요.' } });
const commentLimiter = rateLimit({ windowMs: 60*1000, max: 20, message: { error: '너무 빠르게 댓글을 달고 있어요.' } });
const dmLimiter = rateLimit({ windowMs: 60*1000, max: 20, message: { error: '너무 빠르게 쪽지를 보내고 있어요.' } });

// 미들웨어
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요해요.' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: '토큰이 만료됐어요. 다시 로그인해주세요.' }); }
}

async function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '관리자만 접근 가능해요.' });
  const { data: dbUser } = await supabase.from('users').select('role,suspended').eq('id', req.user.id).single();
  if (!dbUser || dbUser.role !== 'admin' || dbUser.suspended) return res.status(403).json({ error: '관리자 권한이 없어요.' });
  next();
}

async function checkSuspended(req, res, next) {
  const { data: dbUser } = await supabase.from('users').select('role,suspended').eq('id', req.user.id).single();
  if (dbUser?.suspended && dbUser?.role !== 'admin') return res.status(403).json({ error: '정지된 계정이에요.' });
  next();
}

async function checkGenderBoard(req, res, next) {
  const cat = req.body?.cat;
  if (!['남자게시판','여자게시판'].includes(cat)) return next();
  const { data } = await supabase.from('users').select('gender').eq('id', req.user.id).single();
  if (!data?.gender) return res.status(403).json({ error: '성별을 먼저 설정해주세요.' });
  if (cat==='남자게시판'&&data.gender!=='male') return res.status(403).json({ error: '남자 전용 게시판이에요.' });
  if (cat==='여자게시판'&&data.gender!=='female') return res.status(403).json({ error: '여자 전용 게시판이에요.' });
  next();
}

module.exports = { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit };
