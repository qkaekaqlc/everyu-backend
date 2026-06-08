const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

// ══ DM ══
router.get('/api/dm', auth, async (req, res) => {
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
router.post('/api/dm/block/:uid', auth, async (req, res) => {
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

router.get('/api/dm/blocks', auth, async (req, res) => {
  const { data } = await supabase.from('dm_blocks').select('blocked_uid').eq('blocker_uid', req.user.id);
  res.json((data||[]).map(d => d.blocked_uid));
});

router.get('/api/dm/:partnerId', auth, async (req, res) => {
  const me=req.user.id, p=req.params.partnerId;
  const { data } = await supabase.from('dms').select('*').or(`and(from_uid.eq.${me},to_uid.eq.${p}),and(from_uid.eq.${p},to_uid.eq.${me})`).order('created_at');
  await supabase.from('dms').update({read:true}).eq('to_uid',me).eq('from_uid',p);
  res.json(data||[]);
});

router.post('/api/dm/:partnerId', auth, checkSuspended, dmLimiter, async (req, res) => {
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
const DEFAULT_SCHOOL_CODE = '7391126';
const DEFAULT_OFFICE_CODE = 'F10';

// 학교 검색 API
router.get('/api/schools/search', async (req, res) => {
  const { q } = req.query;
  if (!q || q.trim().length < 2) return res.status(400).json({ error: '2자 이상 입력해주세요.' });
  try {
    const url = `https://open.neis.go.kr/hub/schoolInfo?KEY=${NEIS_KEY}&Type=json&SCHUL_NM=${encodeURIComponent(q)}&SCHUL_KND_SC_NM=중학교`;
    const resp = await fetch(url);
    const data = await resp.json();
    const rows = data?.schoolInfo?.[1]?.row || [];
    res.json(rows.map(r => {
      // 위경도가 있으면 격자 좌표 자동 계산
      let nx = null, ny = null;
      if (r.LTTUDE && r.LGTUDE) {
        const grid = latLonToGrid(parseFloat(r.LTTUDE), parseFloat(r.LGTUDE));
        nx = grid.nx; ny = grid.ny;
      }
      return {
        name: r.SCHUL_NM,
        officeCode: r.ATPT_OFCDC_SC_CODE,
        schoolCode: r.SD_SCHUL_CODE,
        address: r.ORG_RDNMA,
        lat: r.LTTUDE ? parseFloat(r.LTTUDE) : null,
        lon: r.LGTUDE ? parseFloat(r.LGTUDE) : null,
        nx, ny,
      };
    }));
  } catch(e) {
    res.status(500).json({ error: '학교 검색에 실패했어요.' });
  }
});

// 학교 목록 (DB)
router.get('/api/schools', async (req, res) => {
  const { data } = await supabase.from('schools').select('*').order('name');
  res.json(data || []);
});

// 학교 등록 (관리자)
router.post('/api/schools', auth, adminOnly, async (req, res) => {
  const { name, office_code, school_code, address, lat, lon, nx, ny, bus_stops } = req.body;
  if (!name || !office_code || !school_code) return res.status(400).json({ error: '필수 항목이 없어요.' });
  // nx, ny 자동 계산 (위경도 있으면)
  let calcNx = nx || null, calcNy = ny || null;
  if (!calcNx && lat && lon) {
    const grid = latLonToGrid(parseFloat(lat), parseFloat(lon));
    calcNx = grid.nx; calcNy = grid.ny;
  }
  // 중복 체크
  const { data: exists } = await supabase.from('schools').select('id').eq('school_code', school_code).single();
  if (exists) return res.status(400).json({ error: '이미 등록된 학교예요.' });
  const { data, error } = await supabase.from('schools').insert({ name, office_code, school_code, address, lat: lat||null, lon: lon||null, nx: calcNx, ny: calcNy, bus_stops: bus_stops || [] }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// 학교 수정 (관리자)
router.put('/api/schools/:id', auth, adminOnly, async (req, res) => {
  const updates = req.body;
  await supabase.from('schools').update(updates).eq('id', req.params.id);
  res.json({ ok: true });
});

// 학교 삭제 (관리자)
router.delete('/api/schools/:id', auth, adminOnly, async (req, res) => {
  await supabase.from('schools').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

// 위경도 → 기상청 격자 변환 함수

// ══ 전국 중학교 일괄 동기화 (관리자) ══
router.post('/api/admin/schools/sync', auth, adminOnly, async (req, res) => {
  try {
    let page = 1, total = 0, added = 0, skipped = 0;
    const pageSize = 1000;
    while (true) {
      const url = `https://open.neis.go.kr/hub/schoolInfo?KEY=${NEIS_KEY}&Type=json&SCHUL_KND_SC_NM=중학교&pSize=${pageSize}&pIndex=${page}`;
      const resp = await fetch(url);
      const data = await resp.json();
      const rows = data?.schoolInfo?.[1]?.row || [];
      if (!rows.length) break;
      total += rows.length;
      // 배치로 upsert
      for (const r of rows) {
        let nx = null, ny = null;
        if (r.LTTUDE && r.LGTUDE) {
          const grid = latLonToGrid(parseFloat(r.LTTUDE), parseFloat(r.LGTUDE));
          nx = grid.nx; ny = grid.ny;
        }
        const { error } = await supabase.from('schools').upsert({
          name: r.SCHUL_NM,
          office_code: r.ATPT_OFCDC_SC_CODE,
          school_code: r.SD_SCHUL_CODE,
          address: r.ORG_RDNMA || null,
          lat: r.LTTUDE ? parseFloat(r.LTTUDE) : null,
          lon: r.LGTUDE ? parseFloat(r.LGTUDE) : null,
          nx, ny,
          bus_stops: [],
        }, { onConflict: 'school_code', ignoreDuplicates: false });
        if (error) skipped++;
        else added++;
      }
      if (rows.length < pageSize) break;
      page++;
    }
    res.json({ ok: true, total, added, skipped, message: `전국 중학교 ${added}개 동기화 완료!` });
  } catch(e) {
    res.status(500).json({ error: '동기화 실패: ' + e.message });
  }
});

// 학교 자동 등록 + 유저 학교 설정 (학생이 선택하면 자동으로 DB에 등록)
router.post('/api/schools/auto-register', auth, async (req, res) => {
  const { name, office_code, school_code, address, lat, lon, nx, ny } = req.body;
  if (!name || !office_code || !school_code) return res.status(400).json({ error: '학교 정보가 없어요.' });
  // 이미 있으면 기존 것 반환
  const { data: exists } = await supabase.from('schools').select('*').eq('school_code', school_code).single();
  if (exists) return res.json(exists);
  // 없으면 자동 등록 (버스정류장 없이)
  let calcNx = nx || null, calcNy = ny || null;
  if (!calcNx && lat && lon) {
    const grid = latLonToGrid(parseFloat(lat), parseFloat(lon));
    calcNx = grid.nx; calcNy = grid.ny;
  }
  const { data, error } = await supabase.from('schools').insert({ name, office_code, school_code, address, lat: lat||null, lon: lon||null, nx: calcNx, ny: calcNy, bus_stops: [] }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// 유저 학교 설정
router.put('/api/profile/school', auth, async (req, res) => {
  const { school_id } = req.body;
  if (!school_id) return res.status(400).json({ error: '학교를 선택해주세요.' });
  const { data: school } = await supabase.from('schools').select('*').eq('id', school_id).single();
  if (!school) return res.status(404).json({ error: '학교를 찾을 수 없어요.' });
  await supabase.from('users').update({ school_id }).eq('id', req.user.id);
  res.json({ ok: true, school });
});

router.get('/api/meal', auth, async (req, res) => {
  const date = req.query.date || new Date().toISOString().slice(0,10).replace(/-/g,'');
  try {
    const { data: user } = await supabase.from('users').select('school_id').eq('id', req.user.id).single();
    let officeCode = DEFAULT_OFFICE_CODE, schoolCode = DEFAULT_SCHOOL_CODE;
    if (user?.school_id) {
      const { data: school } = await supabase.from('schools').select('office_code,school_code').eq('id', user.school_id).single();
      if (school) { officeCode = school.office_code; schoolCode = school.school_code; }
    }
    const url = `https://open.neis.go.kr/hub/mealServiceDietInfo?KEY=${NEIS_KEY}&Type=json&ATPT_OFCDC_SC_CODE=${officeCode}&SD_SCHUL_CODE=${schoolCode}&MLSV_YMD=${date}`;
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

router.get('/api/timetable', auth, async (req, res) => {
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
    // 유저 학교 정보 가져오기
    const { data: userInfo } = await supabase.from('users').select('school_id').eq('id', req.user.id).single();
    let ttOfficeCode = DEFAULT_OFFICE_CODE, ttSchoolCode = DEFAULT_SCHOOL_CODE;
    if (userInfo?.school_id) {
      const { data: school } = await supabase.from('schools').select('office_code,school_code').eq('id', userInfo.school_id).single();
      if (school) { ttOfficeCode = school.office_code; ttSchoolCode = school.school_code; }
    }
    const url = `https://open.neis.go.kr/hub/misTimetable?KEY=${NEIS_KEY}&Type=json&ATPT_OFCDC_SC_CODE=${ttOfficeCode}&SD_SCHUL_CODE=${ttSchoolCode}&GRADE=${grade}&CLASS_NM=${classroom}&TI_FROM_YMD=${toStr(monday)}&TI_TO_YMD=${toStr(friday)}`;
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
router.put('/api/profile/gender', auth, async (req, res) => {
  const { gender } = req.body;
  if (!['male','female'].includes(gender)) return res.status(400).json({ error: '올바른 성별을 선택해주세요.' });
  const { data: user } = await supabase.from('users').select('gender').eq('id', req.user.id).single();
  if (user?.gender) return res.status(400).json({ error: '성별은 한 번만 설정할 수 있어요.' });
  await supabase.from('users').update({ gender }).eq('id', req.user.id);
  res.json({ ok: true, gender });
});

router.put('/api/profile/grade', auth, async (req, res) => {
  const { grade, classroom } = req.body;
  await supabase.from('users').update({ grade: parseInt(grade)||null, classroom: parseInt(classroom)||null }).eq('id', req.user.id);
  res.json({ ok: true });
});

// 닉네임 중복 체크 (비로그인용)
router.get('/api/nickname/check-public', async (req, res) => {
  const { nickname } = req.query;
  if (!nickname || nickname.trim().length < 2) return res.status(400).json({ error: '닉네임은 2자 이상이어야 해요.' });
  const { data } = await supabase.from('users').select('id').eq('nickname', nickname.trim()).single();
  res.json({ available: !data });
});

// 닉네임 중복 체크 (로그인용)
router.get('/api/nickname/check', auth, async (req, res) => {
  const { nickname } = req.query;
  if (!nickname || nickname.trim().length < 2) return res.status(400).json({ error: '닉네임은 2자 이상이어야 해요.' });
  if (nickname.trim().length > 15) return res.status(400).json({ error: '닉네임은 15자 이하여야 해요.' });
  const { data } = await supabase.from('users').select('id').eq('nickname', nickname.trim()).neq('id', req.user.id).single();
  res.json({ available: !data });
});

// 닉네임 변경 (30일 1회 제한)
router.put('/api/profile/nickname', auth, async (req, res) => {
  const { nickname } = req.body;
  if (!nickname || nickname.trim().length < 2) return res.status(400).json({ error: '닉네임은 2자 이상이어야 해요.' });
  if (nickname.trim().length > 15) return res.status(400).json({ error: '닉네임은 15자 이하여야 해요.' });
  if (/[!@#$%^&*()+=\[\]{}|;':",.<>?\/`~]/.test(nickname)) return res.status(400).json({ error: '닉네임에 특수문자는 사용할 수 없어요.' });
  const { data: me } = await supabase.from('users').select('nickname,nickname_changed_at').eq('id', req.user.id).single();
  if (me?.nickname && me?.nickname_changed_at) {
    const daysSince = (Date.now() - new Date(me.nickname_changed_at).getTime()) / (1000*60*60*24);
    if (daysSince < 30) return res.status(400).json({ error: `닉네임은 30일에 1번만 변경할 수 있어요. (${Math.ceil(30-daysSince)}일 후 변경 가능)` });
  }
  const { data: existing } = await supabase.from('users').select('id').eq('nickname', nickname.trim()).neq('id', req.user.id).single();
  if (existing) return res.status(400).json({ error: '이미 사용 중인 닉네임이에요.' });
  await supabase.from('users').update({ nickname: nickname.trim(), nickname_changed_at: new Date().toISOString() }).eq('id', req.user.id);
  const newToken = jwt.sign({ id: req.user.id, role: req.user.role, name: req.user.name, nickname: nickname.trim() }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ ok: true, nickname: nickname.trim(), token: newToken });
});


module.exports = router;
