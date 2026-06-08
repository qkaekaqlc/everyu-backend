const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();

// ══ 게시글 ══
router.get('/api/posts', auth, async (req, res) => {
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

router.get('/api/posts/hot', auth, async (req, res) => {
  const weekAgo = new Date(Date.now() - 7*24*60*60*1000).toISOString();
  const { data } = await supabase.from('posts').select('*').eq('deleted',false).gte('created_at', weekAgo).order('likes',{ascending:false}).limit(20);
  res.json(data||[]);
});

router.get('/api/posts/:id', auth, async (req, res) => {
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

router.post('/api/posts', auth, checkSuspended, postLimiter, checkGenderBoard, async (req, res) => {
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

router.put('/api/posts/:id', auth, checkSuspended, async (req, res) => {
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
router.post('/api/posts/:id/like', auth, checkSuspended, async (req, res) => {
  const pid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('likes').select('id').eq('post_id',pid).eq('uid',uid).single();
  if (ex) { await supabase.from('likes').delete().eq('post_id',pid).eq('uid',uid); const {data:cur}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); await supabase.from('posts').update({likes:Math.max(0,(cur?.likes||0)-1)}).eq('id',pid); const {data:pp}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); return res.json({liked:false, likes:pp?.likes||0, dislikes:pp?.dislikes||0}); }
  await supabase.from('dislikes').delete().eq('post_id',pid).eq('uid',uid);
  await supabase.from('likes').insert({post_id:pid,uid});
  await Promise.all([supabase.rpc('increment_likes',{post_id:parseInt(pid)}), supabase.rpc('decrement_dislikes',{post_id:parseInt(pid)})]);
  const { data: p } = await supabase.from('posts').select('uid,title,likes,dislikes').eq('id',pid).single();
  if (p&&p.uid!==uid) await sendNotif(p.uid,'like','회원님의 글 "'+p.title+'"에 좋아요가 달렸어요! ❤️',pid);
  await supabase.from('logs').insert({ uid, action: `게시글 좋아요 (#${pid})`, type: 'like' });
  res.json({liked:true, likes:p?.likes||0, dislikes:p?.dislikes||0});
});

router.post('/api/posts/:id/dislike', auth, checkSuspended, async (req, res) => {
  const pid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('dislikes').select('id').eq('post_id',pid).eq('uid',uid).single();
  if (ex) { await supabase.from('dislikes').delete().eq('post_id',pid).eq('uid',uid); const {data:cur2}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); await supabase.from('posts').update({dislikes:Math.max(0,(cur2?.dislikes||0)-1)}).eq('id',pid); const {data:pp}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single(); return res.json({disliked:false, likes:pp?.likes||0, dislikes:pp?.dislikes||0}); }
  await supabase.from('likes').delete().eq('post_id',pid).eq('uid',uid);
  await supabase.from('dislikes').insert({post_id:pid,uid});
  await Promise.all([supabase.rpc('increment_dislikes',{post_id:parseInt(pid)}), supabase.rpc('decrement_likes',{post_id:parseInt(pid)})]);
  const {data:p2}=await supabase.from('posts').select('likes,dislikes').eq('id',pid).single();
  res.json({disliked:true, likes:p2?.likes||0, dislikes:p2?.dislikes||0});
});

// ══ 댓글 ══
router.post('/api/posts/:id/comments', auth, checkSuspended, commentLimiter, async (req, res) => {
  const { body, parentId } = req.body;
  if (!body||body.trim().length===0) return res.status(400).json({ error: '댓글 내용을 입력해주세요.' });
  if (body.length>500) return res.status(400).json({ error: '댓글은 500자 이내로 작성해주세요.' });
  const postId = parseInt(req.params.id);
  if (isNaN(postId)) return res.status(400).json({ error: '잘못된 게시글 ID예요.' });
  // 익명 번호 일관성
  const { data: prevComments } = await supabase.from('comments').select('uid,anon_num').eq('post_id', postId).not('anon_num', 'is', null);
  const existingAnon = (prevComments||[]).find(c => c.uid === req.user.id);
  const anonNum = existingAnon ? existingAnon.anon_num : ([...new Set((prevComments||[]).map(c=>c.anon_num).filter(Boolean))].length + 1);
  const { data, error } = await supabase.from('comments').insert({ post_id:postId, uid:req.user.id, author:req.user.nickname||req.user.name, body:filterBadWords(sanBody(body)), anon:true, anon_num:anonNum, parent_id:parentId?parseInt(parentId):null, likes:0, dislikes:0 }).select().single();
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

router.put('/api/comments/:id', auth, checkSuspended, async (req, res) => {
  const { body } = req.body;
  const { data: c } = await supabase.from('comments').select('uid,body').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '수정 권한이 없어요.' });
  // 수정 이력 저장
  await supabase.from('edit_history').insert({ comment_id: parseInt(req.params.id), uid: req.user.id, before_body: c.body, edited_at: new Date().toISOString() });
  await supabase.from('comments').update({ body:filterBadWords(sanBody(body)), edited:true }).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid: req.user.id, action: `댓글 수정 (#${req.params.id})`, type: 'edit' });
  res.json({ok:true});
});

router.delete('/api/comments/:id/mine', auth, async (req, res) => {
  const { data: c } = await supabase.from('comments').select('uid').eq('id',req.params.id).single();
  if (!c) return res.status(404).json({ error: '댓글을 찾을 수 없어요.' });
  if (c.uid!==req.user.id) return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('comments').update({deleted:true}).eq('id',req.params.id);
  await supabase.from('logs').insert({ uid: req.user.id, action: `댓글 삭제 (#${req.params.id})`, type: 'del' });
  res.json({ok:true});
});

router.post('/api/comments/:id/like', auth, checkSuspended, async (req, res) => {
  const cid=req.params.id, uid=req.user.id;
  const { data: ex } = await supabase.from('comment_likes').select('id').eq('comment_id',cid).eq('uid',uid).single();
  if (ex) { await supabase.from('comment_likes').delete().eq('comment_id',cid).eq('uid',uid); await supabase.rpc('decrement_comment_likes',{comment_id:parseInt(cid)}); return res.json({liked:false}); }
  await supabase.from('comment_dislikes').delete().eq('comment_id',cid).eq('uid',uid);
  await supabase.from('comment_likes').insert({comment_id:cid,uid});
  await supabase.rpc('increment_comment_likes',{comment_id:parseInt(cid)});
  await supabase.rpc('decrement_comment_dislikes',{comment_id:parseInt(cid)});
  res.json({liked:true});
});

router.post('/api/comments/:id/dislike', auth, checkSuspended, async (req, res) => {
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
router.get('/api/search', auth, async (req, res) => {
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

module.exports = router;
