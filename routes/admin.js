const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ══ 관리자 ══
router.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('users').select('id,name,role,suspended,warnings,created_at,deleted,last_ip,last_login,kakao_id,google_id,naver_id,email').order('created_at',{ascending:false});
  res.json(data||[]);
});
router.put('/api/admin/users/:id/suspend', auth, adminOnly, async (req, res) => {
  const { suspend } = req.body;
  const { data: u } = await supabase.from('users').select('name').eq('id',req.params.id).single();
  await supabase.from('users').update({ suspended: suspend }).eq('id',req.params.id);
  if (suspend) await supabase.from('notifications').insert({to_uid:req.params.id,text:'🚫 관리자에 의해 계정이 정지됐어요.',read:false});
  await supabase.from('logs').insert({uid:req.user.id,action:(u?.name||req.params.id)+' 계정 '+(suspend?'정지':'해제')+' (관리자: '+req.user.id+')',type:'ban'});
  res.json({ok:true});
});
// 관리자 계정 삭제 (개인정보 초기화 + 정지)
router.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const uid = req.params.id;
  if (uid === req.user.id) return res.status(400).json({ error: '자기 자신은 삭제할 수 없어요.' });
  const { data: u } = await supabase.from('users').select('name,email,kakao_id,google_id,naver_id').eq('id', uid).single();
  if (!u) return res.status(404).json({ error: '사용자를 찾을 수 없어요.' });
  // 이메일 블랙리스트 등록
  if (u.email) await supabase.from('banned_emails').upsert({ email: u.email, uid, reason: `관리자 삭제 (${req.user.id})` });
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
  await supabase.from('refresh_tokens').delete().eq('uid', uid);
  await supabase.from('logs').insert({ uid: req.user.id, action: `계정 삭제: ${u.name} (@${uid}) (관리자: ${req.user.id})`, type: 'ban' });
  res.json({ ok: true });
});

// 관리자 계정 복구
router.put('/api/admin/users/:id/restore', auth, adminOnly, async (req, res) => {
  const uid = req.params.id;
  await supabase.from('users').update({ deleted: false, suspended: false }).eq('id', uid);
  await supabase.from('logs').insert({ uid: req.user.id, action: `계정 복구: @${uid} (관리자: ${req.user.id})`, type: 'ban' });
  res.json({ ok: true });
});

// 경고 부여 (관리자 + 매니저 가능)
router.post('/api/admin/users/:id/warn', auth, async (req, res) => {
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
router.post('/api/admin/manager/:id', auth, adminOnly, async (req, res) => {
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
router.post('/api/admin/restrict/:id', auth, adminOnly, async (req, res) => {
  const { hours = 24 } = req.body;
  const until = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  const { data: user } = await supabase.from('users').select('name').eq('id', req.params.id).single();
  await supabase.from('users').update({ restricted_until: until }).eq('id', req.params.id);
  await supabase.from('notifications').insert({ to_uid: req.params.id, text: `⏰ ${hours}시간 동안 게시글 작성이 제한됐어요.`, read: false });
  await supabase.from('logs').insert({ uid: req.user.id, action: `${user?.name} ${hours}시간 임시제한 (관리자: ${req.user.id})`, type: 'ban' });
  res.json({ ok: true, until });
});

router.delete('/api/admin/restrict/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('users').update({ restricted_until: null }).eq('id', req.params.id);
  res.json({ ok: true });
});
router.delete('/api/admin/posts/:id', auth, adminOnly, async (req, res) => {
  const { data: p } = await supabase.from('posts').select('title').eq('id',req.params.id).single();
  await supabase.from('posts').update({deleted:true,pinned:false}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:req.user.id,action:'게시글 삭제: "'+p?.title+'" (관리자: '+req.user.id+')',type:'del'});
  res.json({ok:true});
});
router.delete('/api/admin/comments/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('comments').update({deleted:true}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:'admin',action:'댓글 삭제',type:'del'});
  res.json({ok:true});
});
router.put('/api/admin/posts/:id/pin', auth, adminOnly, async (req, res) => {
  const { pinned } = req.body;
  const { data: p } = await supabase.from('posts').select('title').eq('id',req.params.id).single();
  await supabase.from('posts').update({pinned}).eq('id',req.params.id);
  await supabase.from('logs').insert({uid:'admin',action:'게시글 '+(pinned?'고정':'고정해제')+': '+p?.title,type:'del'});
  res.json({ok:true});
});
router.get('/api/admin/reports', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('reports').select('*').order('created_at',{ascending:false});
  res.json(data||[]);
});
router.put('/api/admin/reports/:id/resolve', auth, adminOnly, async (req, res) => {
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
router.get('/api/admin/security-logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('security_logs').select('*').order('created_at', { ascending: false }).limit(200);
  res.json(data || []);
});

router.get('/api/admin/warn-logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('warn_logs').select('*').order('created_at', { ascending: false }).limit(100);
  res.json(data || []);
});

router.get('/api/admin/logs', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('logs').select('*').order('created_at',{ascending:false}).limit(100);
  res.json(data||[]);
});
router.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const [u,p,s,r] = await Promise.all([
    supabase.from('users').select('id',{count:'exact'}).eq('deleted',false),
    supabase.from('posts').select('id',{count:'exact'}).eq('deleted',false),
    supabase.from('users').select('id',{count:'exact'}).eq('suspended',true).eq('deleted',false),
    supabase.from('reports').select('id',{count:'exact'}).eq('resolved',false),
  ]);
  res.json({users:u.count||0,posts:p.count||0,suspended:s.count||0,reports:r.count||0});
});

// 금지어 관리
router.get('/api/admin/banned-words', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('banned_words').select('*').order('created_at',{ascending:false});
  res.json(data||[]);
});
router.post('/api/admin/banned-words', auth, adminOnly, async (req, res) => {
  const { word } = req.body;
  if (!word||word.trim().length<2) return res.status(400).json({error:'금지어는 2자 이상이어야 해요.'});
  const { error } = await supabase.from('banned_words').insert({word:word.trim().toLowerCase(),added_by:req.user.id});
  if (error) return res.status(400).json({error:'이미 등록된 금지어예요.'});
  await loadBannedWords();
  res.json({ok:true});
});
router.delete('/api/admin/banned-words/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('banned_words').delete().eq('id',req.params.id);
  await loadBannedWords();
  res.json({ok:true});
});





// ══ 다른 사용자 프로필 조회 ══
router.get('/api/users/:uid/profile', auth, async (req, res) => {
  const targetId = req.params.uid;
  const { data: user } = await supabase.from('users').select('id,name,role,avatar,created_at').eq('id', targetId).eq('deleted', false).single();
  if (!user) return res.status(404).json({ error: '존재하지 않는 사용자예요.' });
  // 실명 글만 공개 (익명 글 제외)
  const { data: posts } = await supabase.from('posts').select('id,title,cat,likes,created_at').eq('uid', targetId).eq('deleted', false).eq('anon', false).order('created_at', { ascending: false }).limit(20);
  res.json({ ...user, posts: posts || [] });
});

// ══ 채팅 기록 API ══
router.get('/api/chat/history', auth, async (req, res) => {
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



// ── 전체 공지 발송 (관리자) ──
router.post('/api/admin/notice', auth, adminOnly, rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: '공지는 1시간에 10회까지만 보낼 수 있어요.' } }), async (req, res) => {
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

module.exports = router;
