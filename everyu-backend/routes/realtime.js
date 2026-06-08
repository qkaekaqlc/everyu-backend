const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const { Server } = require('socket.io');

// ═══════════════════════════════════════════
// Supabase Storage 파일 업로드
// ═══════════════════════════════════════════
router.post('/api/upload', auth, checkSuspended, async (req, res) => {
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
  // Magic bytes 검증 (실제 파일 헤더 확인)
  const MAGIC_BYTES = {
    jpg: [[0xFF,0xD8,0xFF]],
    jpeg: [[0xFF,0xD8,0xFF]],
    png: [[0x89,0x50,0x4E,0x47]],
    gif: [[0x47,0x49,0x46,0x38]],
    webp: [[0x52,0x49,0x46,0x46]],
    pdf: [[0x25,0x50,0x44,0x46]],
  };
  const magic = MAGIC_BYTES[ext];
  if (magic) {
    const valid = magic.some(sig => sig.every((b,i) => buffer[i] === b));
    if (!valid) return res.status(400).json({ error: '파일 형식이 올바르지 않아요.' });
  }

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
router.delete('/api/upload', auth, async (req, res) => {
  const { path } = req.body;
  if (!path) return res.status(400).json({ error: '경로가 없어요.' });
  // 본인 소유 파일인지 확인 (경로에 userId 포함)
  const isAdmin = req.user.role === 'admin' || req.user.role === 'manager';
  if (!isAdmin && !path.includes('/' + req.user.id + '/')) {
    return res.status(403).json({ error: '본인 파일만 삭제할 수 있어요.' });
  }
  try {
    await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: path }));
  } catch(e) { return res.status(500).json({ error: 'R2 삭제 실패: ' + e.message }); }
  res.json({ ok: true });
});

// 프로필 사진 업로드
router.post('/api/profile/avatar', auth, checkSuspended, async (req, res) => {
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
router.get('/api/profile', auth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('id,name,bday,role,warnings,avatar,created_at').eq('id', req.user.id).single();
  const { data: myPosts } = await supabase.from('posts').select('id,title,likes,created_at').eq('uid', req.user.id).eq('deleted', false).order('created_at', { ascending: false });
  const totalLikes = (myPosts || []).reduce((a, p) => a + (p.likes || 0), 0);
  res.json({ ...user, postCount: (myPosts || []).length, totalLikes });
});

// 프로필 정보 수정 (이름 변경)
router.put('/api/profile', auth, checkSuspended, async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: '이름은 2자 이상이어야 해요.' });
  if (hasBadWords(name)) return res.status(400).json({ error: '사용할 수 없는 단어가 포함됐어요.' });
  await supabase.from('users').update({ name: san(name.trim()) }).eq('id', req.user.id);
  res.json({ ok: true });
});

// 실시간 알림 폴링 (새 알림만 반환)
router.get('/api/notifications/new', auth, async (req, res) => {
  const since = req.query.since || new Date(0).toISOString();
  const { data } = await supabase.from('notifications').select('*').eq('to_uid', req.user.id).eq('read', false).gt('created_at', since).order('created_at', { ascending: false });
  res.json(data || []);
});

// 회원 통계 (관리자)
router.get('/api/admin/dashboard', auth, adminOnly, async (req, res) => {
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

module.exports = router;
