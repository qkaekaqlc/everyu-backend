const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const { Resend } = require('resend');

// ══ 회원가입 ══
router.post('/api/register', registerLimiter, async (req, res) => {
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
router.post('/api/login', loginLimiter, async (req, res) => {
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
router.post('/api/refresh-token', async (req, res) => {
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
    const { data: user } = await supabase.from('users').select('id,role,name,nickname,suspended').eq('id', p.id).single();
    if (!user||user.suspended) return res.status(403).json({ error: '사용할 수 없는 계정이에요.' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name, nickname: user.nickname||null }, SECRET, { expiresIn: '1h' });
    // Refresh Token Rotation - 기존 삭제 후 새 토큰 발급
    const newRefreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
    await supabase.from('refresh_tokens').delete().eq('token', refreshToken);
    await supabase.from('refresh_tokens').insert({ uid: user.id, token: newRefreshToken, expires_at: new Date(Date.now()+7*24*60*60*1000).toISOString() });
    res.json({ token, refreshToken: newRefreshToken });
  } catch { res.status(401).json({ error: '다시 로그인해주세요.' }); }
});

// ══ 비밀번호 재설정 이메일 링크 ══
router.post('/api/password-reset/request', rateLimit({ windowMs: 60*60*1000, max: 3, message: { error: '1시간에 3회까지만 요청할 수 있어요.' } }), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '이메일을 입력해주세요.' });
  const { data: user } = await supabase.from('users').select('id,name,email').eq('email', email).eq('deleted', false).single();
  // 보안상 유저 존재 여부 노출 안 함
  if (!user) return res.json({ ok: true });
  const resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Date.now().toString(36);
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30분
  await supabase.from('password_resets').upsert({ uid: user.id, token: resetToken, expires_at: expires }, { onConflict: 'uid' });
  const resetUrl = `${FRONTEND_URL}?reset_token=${resetToken}`;
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: 'everyu@resend.dev',
    to: email,
    subject: '[에브리유니] 비밀번호 재설정',
    html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;">
      <h2>🎓 에브리유니 비밀번호 재설정</h2>
      <p>안녕하세요 ${user.name}님,</p>
      <p>아래 버튼을 클릭해서 비밀번호를 재설정해주세요.</p>
      <a href="${resetUrl}" style="display:inline-block;background:#e87c3a;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0;">비밀번호 재설정</a>
      <p style="color:#888;font-size:12px;">이 링크는 30분 후 만료됩니다. 본인이 요청하지 않았다면 무시해주세요.</p>
    </div>`
  });
  res.json({ ok: true });
});

router.post('/api/password-reset/confirm', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: '정보가 부족해요.' });
  if (newPassword.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 해요.' });
  const { data: reset } = await supabase.from('password_resets').select('uid,expires_at').eq('token', token).single();
  if (!reset || new Date(reset.expires_at) < new Date()) {
    await supabase.from('password_resets').delete().eq('token', token);
    return res.status(400).json({ error: '만료되거나 유효하지 않은 링크예요.' });
  }
  const hashed = await bcrypt.hash(newPassword, 12);
  await supabase.from('users').update({ password: hashed }).eq('id', reset.uid);
  await supabase.from('password_resets').delete().eq('uid', reset.uid);
  await supabase.from('refresh_tokens').delete().eq('uid', reset.uid); // 기존 세션 전부 무효화
  await supabase.from('logs').insert({ uid: reset.uid, action: '이메일로 비밀번호 재설정', type: 'login' });
  res.json({ ok: true });
});

// 비밀번호 찾기
router.post('/api/find-password', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '시도 횟수를 초과했어요.' } }), async (req, res) => {
  const { id, name, bday } = req.body;
  const { data: user } = await supabase.from('users').select('id,name,bday,securityQuestion').eq('id', id).single();
  await new Promise(r => setTimeout(r, 300));
  if (!user||user.name!==name||user.bday!==bday) return res.status(404).json({ error: '일치하는 계정을 찾을 수 없어요.' });
  res.json({ ok: true, securityQuestion: user.securityQuestion || '보안 질문' });
});

router.post('/api/verify-security', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '너무 많이 시도했어요. 1시간 후 다시 시도해주세요.' } }), async (req, res) => {
  const { id, name, bday, securityAnswer } = req.body;
  const { data: user } = await supabase.from('users').select('id,name,bday,securityAnswer').eq('id', id).single();
  await new Promise(r => setTimeout(r, 300));
  if (!user||user.name!==name||user.bday!==bday) return res.status(403).json({ error: '본인 확인 실패' });
  if (!user.securityAnswer) return res.status(403).json({ error: '보안 질문이 설정되지 않았어요.' });
  const answerOk = await bcrypt.compare((securityAnswer||'').trim().toLowerCase(), user.securityAnswer);
  if (!answerOk) return res.status(403).json({ error: '보안 질문 답변이 틀렸어요.' });
  res.json({ ok: true });
});

router.post('/api/reset-password', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: '너무 많이 시도했어요. 1시간 후 다시 시도해주세요.' } }), async (req, res) => {
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

router.post('/api/logout', auth, async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) await supabase.from('refresh_tokens').delete().eq('token', refreshToken);
  res.json({ ok: true });
});

router.post('/api/change-password', auth, checkSuspended, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('password').eq('id', req.user.id).single();
  if (!await bcrypt.compare(currentPassword, user.password)) return res.status(401).json({ error: '현재 비밀번호가 틀렸어요.' });
  if (newPassword.length < 6) return res.status(400).json({ error: '새 비밀번호는 6자 이상이어야 해요.' });
  await supabase.from('users').update({ password: await bcrypt.hash(newPassword, 12) }).eq('id', req.user.id);
  res.json({ ok: true });
});

router.delete('/api/account', auth, async (req, res) => {
  const { password } = req.body;
  const { data: user } = await supabase.from('users').select('password,kakao_id,google_id').eq('id', req.user.id).single();
  const isSocialUser = !!(user?.kakao_id || user?.google_id);
  if (!isSocialUser) {
    if (!password) return res.status(400).json({ error: '비밀번호를 입력해주세요.' });
    if (!user?.password || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: '비밀번호가 틀렸어요.' });
  }
  // 탈퇴 처리 - 6개월 후 개인정보 파기 예약
  const deleteAt = new Date(Date.now() + 6*30*24*60*60*1000).toISOString(); // 6개월 후
  await supabase.from('users').update({
    deleted: true, suspended: true,
    delete_at: deleteAt, // 실제 파기 예약일
    kakao_id: null, google_id: null, naver_id: null, // 소셜 연동 즉시 해제
  }).eq('id', req.user.id);
  await supabase.from('refresh_tokens').delete().eq('uid', req.user.id);
  await supabase.from('push_subscriptions').delete().eq('uid', req.user.id);
  const provider = user?.kakao_id ? '카카오' : user?.google_id ? '구글' : user?.naver_id ? '네이버' : '일반';
  await supabase.from('logs').insert({ uid: req.user.id, action: `계정 탈퇴 (${provider})`, type: 'login' });
  res.json({ ok: true });
});

module.exports = router;
