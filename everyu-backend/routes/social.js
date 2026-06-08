const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

// ══ 이메일 인증 ══
router.post('/api/auth/send-verify', async (req, res) => {
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

router.post('/api/auth/verify-email', async (req, res) => {
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
router.post('/api/attendance', auth, checkSuspended, async (req, res) => {
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

router.get('/api/attendance', auth, async (req, res) => {
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
router.post('/api/rankings', auth, async (req, res) => {
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
router.post('/api/rankings/name', auth, async (req, res) => {
  const { game, score, name } = req.body;
  if(!game || !name) return res.status(400).json({ error: '정보가 부족해요.' });
  await supabase.from('game_rankings').update({ name: name.slice(0,10), pending: false }).eq('uid', req.user.id).eq('game', game).eq('score', score);
  res.json({ ok: true });
});

router.get('/api/rankings/:game', auth, async (req, res) => {
  const lowerIsBetter = req.params.game.includes('minesweeper') || req.params.game === 'reaction';
  let query = supabase.from('game_rankings').select('name,score,created_at').eq('game', req.params.game);
  if(req.query.exclude_pending === 'true') query = query.neq('pending', true);
  const { data } = await query.order('score', { ascending: lowerIsBetter }).limit(10);
  res.json(data || []);
});

// ══ IP 차단 ══
router.get('/api/admin/banned-ips', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('banned_ips').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

router.post('/api/admin/banned-ips', auth, adminOnly, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP를 입력해주세요.' });
  await supabase.from('banned_ips').upsert({ ip, reason: reason || '', created_at: new Date().toISOString() });
  bannedIpCacheTime = 0; // 캐시 초기화
  res.json({ ok: true });
});

router.delete('/api/admin/banned-ips/:ip', auth, adminOnly, async (req, res) => {
  await supabase.from('banned_ips').delete().eq('ip', req.params.ip);
  bannedIpCacheTime = 0; // 캐시 초기화
  res.json({ ok: true });
});

// IP 차단 미들웨어



// ══ 클럽 영상 댓글 ══
router.get('/api/club/:id/comments', auth, async (req, res) => {
  const { data } = await supabase.from('club_comments').select('*').eq('video_id', req.params.id).eq('deleted', false).order('created_at');
  res.json(data||[]);
});

router.post('/api/club/:id/comments', auth, checkSuspended, async (req, res) => {
  const { body } = req.body;
  if(!body?.trim()) return res.status(400).json({ error: '댓글을 입력해주세요.' });
  const { data, error } = await supabase.from('club_comments').insert({ video_id: parseInt(req.params.id), uid: req.user.id, author: req.user.name, body: filterBadWords(sanBody(body)), deleted: false }).select().single();
  if(error) return res.status(500).json({ error: error.message });
  res.json(data);
});

router.delete('/api/club/:id/comments/:commentId', auth, adminOnly, async (req, res) => {
  await supabase.from('club_comments').update({ deleted: true }).eq('id', req.params.commentId);
  res.json({ ok: true });
});

// ══ IP 차단 테이블 ══

// ══ 카카오 로그인 ══
const KAKAO_REST_KEY = process.env.KAKAO_REST_KEY;
const KAKAO_REDIRECT_URI = process.env.KAKAO_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/kakao/callback';

// 카카오 로그인 시작
const kakaoStates = new Map();
router.get('/api/auth/kakao', (req, res) => {
  const state = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  kakaoStates.set(state, Date.now());
  setTimeout(() => kakaoStates.delete(state), 600000);
  const kakaoAuthUrl = `https://kauth.kakao.com/oauth/authorize?client_id=${KAKAO_REST_KEY}&redirect_uri=${encodeURIComponent(KAKAO_REDIRECT_URI)}&response_type=code&state=${state}`;
  res.redirect(kakaoAuthUrl);
});

// 카카오 콜백
router.get('/api/auth/kakao/callback', async (req, res) => {
  const { code, error, state } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}?kakao_error=cancelled`);
  if (!state || !kakaoStates.has(state)) return res.redirect(`${FRONTEND_URL}?kakao_error=invalid_state`);
  kakaoStates.delete(state);

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

    // 이메일 블랙리스트 체크
    if (kakaoEmail) {
      const { data: banned } = await supabase.from('banned_emails').select('id').eq('email', kakaoEmail).single();
      if (banned) return res.redirect(`${FRONTEND_URL}?kakao_error=suspended`);
    }

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
    const kakaoCode = createSocialCode({ token: jwtToken, refreshToken, user: JSON.parse(decodeURIComponent(userData)), provider: 'kakao' });
    res.redirect(`${FRONTEND_URL}?social_code=${kakaoCode}`);

  } catch (e) {
    console.error('카카오 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?kakao_error=server_error`);
  }
});

// ══ 구글 로그인 ══
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/google/callback';

const googleStates = new Map();
router.get('/api/auth/google', (req, res) => {
  const state = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  googleStates.set(state, Date.now());
  setTimeout(() => googleStates.delete(state), 600000);
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account',
    state,
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

router.get('/api/auth/google/callback', async (req, res) => {
  const { code, error, state } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}?google_error=cancelled`);
  if (!state || !googleStates.has(state)) return res.redirect(`${FRONTEND_URL}?google_error=invalid_state`);
  googleStates.delete(state);
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

    // 이메일 블랙리스트 체크
    if (googleEmail) {
      const { data: banned } = await supabase.from('banned_emails').select('id').eq('email', googleEmail).single();
      if (banned) return res.redirect(`${FRONTEND_URL}?google_error=suspended`);
    }

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
    const googleCode = createSocialCode({ token: jwtToken, refreshToken, user: JSON.parse(decodeURIComponent(userData)), provider: 'google' });
    res.redirect(`${FRONTEND_URL}?social_code=${googleCode}`);

  } catch (e) {
    console.error('구글 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?google_error=server_error`);
  }
});

// ══ 네이버 로그인 ══
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;
const NAVER_REDIRECT_URI = process.env.NAVER_REDIRECT_URI || 'https://everyu-backend.onrender.com/api/auth/naver/callback';

router.get('/api/auth/naver', (req, res) => {
  const state = Math.random().toString(36).substring(2);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: NAVER_CLIENT_ID,
    redirect_uri: NAVER_REDIRECT_URI,
    state,
  });
  res.redirect('https://nid.naver.com/oauth2.0/authorize?' + params.toString());
});

router.get('/api/auth/naver/callback', async (req, res) => {
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

    // 이메일 블랙리스트 체크
    if (naverEmail) {
      const { data: banned } = await supabase.from('banned_emails').select('id').eq('email', naverEmail).single();
      if (banned) return res.redirect(`${FRONTEND_URL}?naver_error=suspended`);
    }

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
    const naverCode = createSocialCode({ token: jwtToken, refreshToken, user: JSON.parse(decodeURIComponent(userData)), provider: 'naver' });
    res.redirect(`${FRONTEND_URL}?social_code=${naverCode}`);

  } catch(e) {
    console.error('네이버 로그인 오류:', e.message);
    res.redirect(`${FRONTEND_URL}?naver_error=server_error`);
  }
});

// ══ 오늘의 퀴즈 ══
const DIFFICULTY_SCORES = { easy: 1, medium: 2, hard: 3 };

router.get('/api/quiz/today', auth, async (req, res) => {
  const today = new Date().toISOString().slice(0,10);
  // 오늘 이미 풀었는지 확인
  const { data: solved } = await supabase.from('quiz_results').select('*').eq('uid', req.user.id).eq('date', today).single();
  if (solved) {
    const { data: quiz } = await supabase.from('quizzes').select('*').eq('id', solved.quiz_id).single();
    return res.json({ solved: true, quiz, result: solved });
  }
  const { difficulty = 'medium' } = req.query;
  const { data: quizzes } = await supabase.from('quizzes').select('*').eq('difficulty', difficulty).eq('active', true);
  if (!quizzes || !quizzes.length) return res.status(404).json({ error: '해당 난이도 문제가 없어요.' });
  const seed = today.split('-').reduce((a,b) => a + parseInt(b), 0);
  const quiz = quizzes[seed % quizzes.length];
  res.json({ solved: false, quiz, difficulty });
});

router.post('/api/quiz/today', auth, async (req, res) => {
  const today = new Date().toISOString().slice(0,10);
  const { quiz_id, answer, difficulty } = req.body;
  const { data: existing } = await supabase.from('quiz_results').select('id').eq('uid', req.user.id).eq('date', today).single();
  if (existing) return res.status(400).json({ error: '오늘은 이미 풀었어요!' });
  const { data: quiz } = await supabase.from('quizzes').select('*').eq('id', quiz_id).single();
  if (!quiz) return res.status(404).json({ error: '문제를 찾을 수 없어요.' });
  const correct = quiz.answer === parseInt(answer);
  const score = correct ? (DIFFICULTY_SCORES[difficulty] || 1) : 0;
  await supabase.from('quiz_results').insert({ uid: req.user.id, date: today, quiz_id, answer: parseInt(answer), correct, difficulty, score });
  if (correct) {
    const nickname = req.user.nickname || req.user.name;
    const { data: es } = await supabase.from('quiz_scores').select('*').eq('uid', req.user.id).single();
    if (es) {
      await supabase.from('quiz_scores').update({ nickname, total_score: es.total_score + score, solved_count: es.solved_count + 1, updated_at: new Date().toISOString() }).eq('uid', req.user.id);
    } else {
      await supabase.from('quiz_scores').insert({ uid: req.user.id, nickname, total_score: score, solved_count: 1 });
    }
  }
  res.json({ correct, correctAnswer: quiz.answer, explanation: quiz.explanation || '', score, difficulty });
});

router.get('/api/quiz/ranking', auth, async (req, res) => {
  const { data } = await supabase.from('quiz_scores').select('uid,nickname,total_score,solved_count').order('total_score', { ascending: false }).limit(20);
  res.json(data || []);
});

// 관리자 퀴즈 관리
router.get('/api/admin/quizzes', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('quizzes').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});

router.post('/api/admin/quizzes', auth, adminOnly, async (req, res) => {
  const { subject, grade, question, options, answer, explanation, difficulty } = req.body;
  if (!question || !options || answer === undefined) return res.status(400).json({ error: '필수 항목이 없어요.' });
  const { data, error } = await supabase.from('quizzes').insert({ subject, grade: grade||null, question, options, answer: parseInt(answer), explanation, difficulty: difficulty||'medium', active: true }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

router.put('/api/admin/quizzes/:id', auth, adminOnly, async (req, res) => {
  const { active, difficulty, question, options, answer, explanation, subject, grade } = req.body;
  const updates = {};
  if (active !== undefined) updates.active = active;
  if (difficulty) updates.difficulty = difficulty;
  if (question) updates.question = question;
  if (options) updates.options = options;
  if (answer !== undefined) updates.answer = parseInt(answer);
  if (explanation !== undefined) updates.explanation = explanation;
  if (subject) updates.subject = subject;
  if (grade !== undefined) updates.grade = grade;
  await supabase.from('quizzes').update(updates).eq('id', req.params.id);
  res.json({ ok: true });
});

router.delete('/api/admin/quizzes/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('quizzes').delete().eq('id', req.params.id);
  res.json({ ok: true });
});


module.exports = router;
