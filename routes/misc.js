const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();

// ══ 북마크 ══
router.get('/api/bookmarks', auth, async (req, res) => {
  const { data } = await supabase.from('bookmarks').select('post_id').eq('uid', req.user.id).order('created_at',{ascending:false});
  if (!data||!data.length) return res.json([]);
  const ids = data.map(b => b.post_id);
  const { data: posts } = await supabase.from('posts').select('*').in('id', ids).eq('deleted', false);
  res.json(posts||[]);
});

router.post('/api/bookmarks/:postId', auth, async (req, res) => {
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
router.get('/api/schedule', auth, async (req, res) => {
  const { year, month } = req.query;
  const now = new Date();
  const y = parseInt(year || now.getFullYear());
  const m = parseInt(month || now.getMonth()+1);
  const from = `${y}-${String(m).padStart(2,'0')}-01`;
  const to = `${y}-${String(m).padStart(2,'0')}-31`;
  const { data } = await supabase.from('school_schedule').select('*').gte('date', from).lte('date', to).order('date');
  res.json(data||[]);
});

router.post('/api/schedule', auth, adminOnly, async (req, res) => {
  const { date, name, type } = req.body;
  if (!date||!name) return res.status(400).json({ error: '날짜와 일정명을 입력해주세요.' });
  const { error } = await supabase.from('school_schedule').insert({ date, name, type: type||'행사' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

router.put('/api/schedule/:id', auth, adminOnly, async (req, res) => {
  const { date, name, type } = req.body;
  await supabase.from('school_schedule').update({ date, name, type }).eq('id', req.params.id);
  res.json({ ok: true });
});

router.delete('/api/schedule/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('school_schedule').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// ══ 음악공간 ══
router.get('/api/music', auth, async (req, res) => {
  const { data } = await supabase.from('music_posts').select('*').eq('approved', true).order('created_at', {ascending:false});
  res.json(data||[]);
});
router.get('/api/music/pending', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('music_posts').select('*').eq('approved', false).order('created_at', {ascending:false});
  res.json(data||[]);
});
router.post('/api/music', auth, checkSuspended, async (req, res) => {
  const { youtube_url, title, description } = req.body;
  if (!youtube_url) return res.status(400).json({ error: 'URL을 입력해주세요.' });
  const ytRegex = /^https?:\/\/(www\.)?(youtube\.com\/watch\?v=|youtu\.be\/)([\w-]+)/;
  if (!ytRegex.test(youtube_url)) return res.status(400).json({ error: '유튜브 링크만 가능해요.' });
  await supabase.from('music_posts').insert({ uid:req.user.id, author:req.user.name, youtube_url, title:title||'제목 없음', description:description||'', approved:false });
  res.json({ ok:true });
});
router.put('/api/music/:id/approve', auth, adminOnly, async (req, res) => {
  await supabase.from('music_posts').update({ approved:true }).eq('id', req.params.id);
  res.json({ ok:true });
});
router.delete('/api/music/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('music_posts').delete().eq('id', req.params.id);
  res.json({ ok:true });
});
router.post('/api/music/:id/like', auth, async (req, res) => {
  const { data: exLike } = await supabase.from('music_likes').select('id').eq('post_id', req.params.id).eq('uid', req.user.id).single();
  if (exLike) {
    await supabase.from('music_likes').delete().eq('id', exLike.id);
    const { data: cur } = await supabase.from('music_posts').select('likes').eq('id', req.params.id).single();
    await supabase.from('music_posts').update({ likes: Math.max(0,(cur?.likes||0)-1) }).eq('id', req.params.id);
    return res.json({ liked: false });
  }
  await supabase.from('music_likes').insert({ post_id: req.params.id, uid: req.user.id });
  const { data } = await supabase.from('music_posts').select('likes').eq('id', req.params.id).single();
  await supabase.from('music_posts').update({ likes:(data?.likes||0)+1 }).eq('id', req.params.id);
  res.json({ ok:true });
});

// ══ 클럽 (관리자 전용 업로드) ══
router.get('/api/club', auth, async (req, res) => {
  const { data } = await supabase.from('club_posts').select('*').order('created_at', {ascending:false});
  res.json(data||[]);
});
router.post('/api/club', auth, adminOnly, async (req, res) => {
  const { youtube_url, title, description } = req.body;
  if (!youtube_url) return res.status(400).json({ error: 'URL을 입력해주세요.' });
  const ytRegex = /^https?:\/\/(www\.)?(youtube\.com\/watch\?v=|youtu\.be\/)([\w-]+)/;
  if (!ytRegex.test(youtube_url)) return res.status(400).json({ error: '유튜브 링크만 가능해요.' });
  await supabase.from('club_posts').insert({ uid:req.user.id, author:req.user.name, youtube_url, title:title||'제목 없음', description:description||'' });
  res.json({ ok:true });
});
router.delete('/api/club/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('club_posts').delete().eq('id', req.params.id);
  res.json({ ok:true });
});
router.post('/api/club/:id/like', auth, async (req, res) => {
  const { data: exLike } = await supabase.from('club_likes').select('id').eq('post_id', req.params.id).eq('uid', req.user.id).single();
  if (exLike) {
    await supabase.from('club_likes').delete().eq('id', exLike.id);
    const { data: cur } = await supabase.from('club_posts').select('likes').eq('id', req.params.id).single();
    await supabase.from('club_posts').update({ likes: Math.max(0,(cur?.likes||0)-1) }).eq('id', req.params.id);
    return res.json({ liked: false });
  }
  await supabase.from('club_likes').insert({ post_id: req.params.id, uid: req.user.id });
  const { data } = await supabase.from('club_posts').select('likes').eq('id', req.params.id).single();
  await supabase.from('club_posts').update({ likes:(data?.likes||0)+1 }).eq('id', req.params.id);
  res.json({ ok:true });
});

// ══ 끝말잇기 AI ══
router.post('/api/wordchain', auth, async (req, res) => {
  const { lastChar, usedWords = [] } = req.body;
  if (!lastChar) return res.status(400).json({ error: '마지막 글자가 없어요.' });
  const WORD_BANK_EX = {
    '가':['가방','가족','가수','가을','가위','가구','가능','가득','가로','가르침','가마','가면','가뭄','가사','가속','가슴','가시','가야금','가운데'],
    '나':['나무','나비','나라','나침반','나물','나이','나팔','나들이','나막신','나뭇잎','나선'],
    '다':['다리','다람쥐','다이아몬드','다과','다수','다짐','다툼','다행','달걀','달력','달리기','달빛','달팽이'],
    '라':['라면','라디오','라켓','라이터','라일락','라임'],
    '마':['마을','마음','마라톤','마늘','마당','마루','마무리','마법','마찰','마트'],
    '바':['바다','바람','바나나','바위','바구니','바늘','바닥','바둑','박수','반달','반지'],
    '사':['사과','사람','사랑','사슴','사탕','사막','사방','사슬','사이','사진','산','산책','삼각형','새벽'],
    '아':['아이','아침','아버지','아기','아파트','아름다움','악기','악어','안개','안녕'],
    '자':['자동차','자연','자전거','자유','자석','자랑','자리','자매','자습','작품','잠수함','잠자리'],
    '차':['차이','차량','차도','차갑다','차분','찰흙','참새','창문','창작'],
    '카':['카메라','카드','카페','카레','카네이션','카멜레온'],
    '타':['타조','타워','타임','타자','타악기','탁구','탈출','탐험','태양','태풍'],
    '파':['파도','파랑','파인애플','파악','파충류','파티','판다','팔찌','팽이','펭귄'],
    '하':['하늘','하트','하마','하루','하수도','하품','학교','학생','한강','한복','항구','해바라기'],
    '고':['고양이','고래','고구마','고속도로','고드름','고민','고사리','고슴도치','공룡','공부'],
    '도':['도서관','도끼','도움','도마뱀','도시','도전','돌고래','동물','동생','두더지'],
    '로':['로봇','로켓','로션'],
    '모':['모자','모래','모기','모험','모형','목도리','목소리','무지개','무한'],
    '보':['보석','보트','보물','보름달','복숭아','볼펜','봉황','부엉이','북극곰'],
    '소':['소나무','소금','소방차','소라','소설','솔방울','송아지','수박','수영','수학'],
    '요':['요리','요술','요가','요정','용기','우산','우주','우체국','운동'],
    '조':['조각','조개','조용함','조랑말','종이','주먹','주전자','중력','쥐','지구'],
    '토':['토끼','토마토','토성','토양','통나무','튤립'],
    '포':['포도','포크','포옹','표범','표지판','풀잠자리','풍선'],
    '호':['호랑이','호수','호박','호기심','홍합','화분','화살','화산','황금','황소'],
    '기':['기차','기린','기억','기후','기록','기적','기타','기둥'],
    '물':['물고기','물감','물병','물개','물결','물레방아'],
    '강':['강아지','강물','강변','강풍'],
    '구':['구름','구리','구석','구슬'],
    '눈':['눈사람','눈송이','눈물','눈빛'],
    '달':['달팽이','달걀','달력','달빛'],
    '새':['새벽','새싹','새장'],
    '양':['양말','양배추','양치기','양파'],
    '코':['코끼리','코뿔소','코알라','코스모스'],
    '지':['지구','지도','지렁이','지식','지하철','지평선'],
    '땅':['땅콩','땅굴'],
  };
  const candidates = (WORD_BANK_EX[lastChar] || []).filter(w => !usedWords.includes(w));
  if (!candidates.length) return res.json({ aiWord: null, message: `"${lastChar}"로 시작하는 단어를 못 찾겠어요. 사용자 승리! 🏆`, win: true });
  const aiWord = candidates[Math.floor(Math.random()*candidates.length)];
  res.json({ aiWord, lastChar: [...aiWord].at(-1) });
});


// ══ 알림 설정 ══
router.get('/api/notif-settings', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('notif_like,notif_comment,notif_reply,notif_dm').eq('id', req.user.id).single();
  res.json({
    notif_like: data?.notif_like !== false,
    notif_comment: data?.notif_comment !== false,
    notif_reply: data?.notif_reply !== false,
    notif_dm: data?.notif_dm !== false,
  });
});
router.put('/api/notif-settings', auth, async (req, res) => {
  const { notif_like, notif_comment, notif_reply, notif_dm } = req.body;
  await supabase.from('users').update({ notif_like, notif_comment, notif_reply, notif_dm }).eq('id', req.user.id);
  res.json({ ok: true });
});

// 알림 전송 헬퍼 (묶음 처리 + 설정 반영)


// ══ 푸시 구독 ══
router.post('/api/push/subscribe', auth, async (req, res) => {
  const { subscription } = req.body;
  if (!subscription) return res.status(400).json({ error: '구독 정보가 없어요.' });
  await supabase.from('push_subscriptions').upsert({
    uid: req.user.id,
    subscription: JSON.stringify(subscription),
    updated_at: new Date().toISOString(),
  }, { onConflict: 'uid' });
  res.json({ ok: true });
});

router.delete('/api/push/unsubscribe', auth, async (req, res) => {
  await supabase.from('push_subscriptions').delete().eq('uid', req.user.id);
  res.json({ ok: true });
});

// ══ 태그 검색 ══
router.get('/api/posts/by-tag', auth, async (req, res) => {
  const { tag } = req.query;
  if (!tag) return res.status(400).json({ error: '태그를 입력해주세요.' });
  const { data } = await supabase.from('posts').select('*').contains('tags', [tag]).eq('deleted', false).order('created_at', { ascending: false }).limit(30);
  res.json(data || []);
});

// ══ 수정 이력 (관리자용) ══
router.get('/api/posts/:id/history', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('edit_history').select('*').eq('post_id', req.params.id).order('edited_at', { ascending: false });
  res.json(data || []);
});

router.get('/api/comments/:id/history', auth, adminOnly, async (req, res) => {
  const { data } = await supabase.from('edit_history').select('*').eq('comment_id', req.params.id).order('edited_at', { ascending: false });
  res.json(data || []);
});


// ══ 내 댓글 목록 ══
router.get('/api/profile/comments', auth, async (req, res) => {
  const { data } = await supabase.from('comments').select('id,body,post_id,created_at').eq('uid', req.user.id).eq('deleted', false).order('created_at', {ascending:false}).limit(50);
  res.json(data||[]);
});

// ══ 공지사항 고정 ══
router.post('/api/posts/:id/pin', auth, adminOnly, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('pinned').eq('id', req.params.id).single();
  if(!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  await supabase.from('posts').update({ pinned: !post.pinned }).eq('id', req.params.id);
  res.json({ pinned: !post.pinned });
});

// ══ 신고 + 팔로우/차단 ══
// ══ 팔로우/차단 ══
router.post('/api/follow/:uid', auth, async (req, res) => {
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

router.post('/api/block/:uid', auth, async (req, res) => {
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

router.get('/api/follow-status/:uid', auth, async (req, res) => {
  const targetId = req.params.uid;
  const [followData, blockData] = await Promise.all([
    supabase.from('follows').select('id').eq('follower_uid', req.user.id).eq('following_uid', targetId).single(),
    supabase.from('blocks').select('id').eq('blocker_uid', req.user.id).eq('blocked_uid', targetId).single()
  ]);
  res.json({ following: !!followData.data, blocked: !!blockData.data });
});

// 신고 7회 자동 숨김 확인 및 적용
router.post('/api/reports', auth, checkSuspended, async (req, res) => {
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
router.delete('/api/posts/:id', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('uid').eq('id',req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('posts').update({deleted:true,pinned:false}).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid:req.user.id, action:'게시글 삭제', type:'del' });
  res.json({ok:true});
});

// ══ 공지 배너 ══
router.get('/api/notice-banner', async (req, res) => {
  const { data } = await supabase.from('notice_banner').select('*').eq('active', true).order('created_at',{ascending:false}).limit(1).single();
  res.json(data || null);
});
router.post('/api/admin/notice-banner', auth, adminOnly, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: '내용을 입력해주세요.' });
  await supabase.from('notice_banner').update({ active: false }).eq('active', true);
  const { data } = await supabase.from('notice_banner').insert({ text, active: true }).select().single();
  res.json(data);
});
router.delete('/api/admin/notice-banner', auth, adminOnly, async (req, res) => {
  await supabase.from('notice_banner').update({ active: false }).eq('active', true);
  res.json({ ok: true });
});



// ══ 이모지 반응 ══
router.get('/api/posts/:id/reactions', auth, async (req, res) => {
  const pid = req.params.id;
  const { data: all } = await supabase.from('reactions').select('emoji,uid').eq('post_id', pid);
  const counts = {};
  (all||[]).forEach(r => { counts[r.emoji] = (counts[r.emoji]||0)+1; });
  const my = (all||[]).filter(r=>r.uid===req.user.id).map(r=>r.emoji);
  res.json({ counts, my });
});

router.post('/api/posts/:id/reactions', auth, checkSuspended, async (req, res) => {
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
router.get('/api/posts/:id/history', auth, async (req, res) => {
  const { data: post } = await supabase.from('posts').select('uid').eq('id', req.params.id).single();
  if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없어요.' });
  if (post.uid !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: '이력을 볼 권한이 없어요.' });
  const { data } = await supabase.from('edit_history').select('*').eq('post_id', req.params.id).order('edited_at',{ascending:false});
  res.json(data||[]);
});

// ══ 알림 ══
router.get('/api/notifications', auth, async (req, res) => {
  const { data } = await supabase.from('notifications').select('*').eq('to_uid', req.user.id).order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

router.put('/api/notifications/:id/read', auth, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('id', req.params.id).eq('to_uid', req.user.id);
  res.json({ ok: true });
});

router.put('/api/notifications/read-all', auth, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('to_uid', req.user.id);
  res.json({ ok: true });
});

module.exports = router;
