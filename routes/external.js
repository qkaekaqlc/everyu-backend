const { supabase, SECRET, REFRESH_SECRET, NEIS_KEY, FRONTEND_URL, r2, R2_BUCKET, R2_PUBLIC_URL, webpush, getBannedIps, updateR2Usage, filterBadWords, sanBody, latLonToGrid, sendNotif, sendPush, loginLimiter, registerLimiter, postLimiter, commentLimiter, dmLimiter, auth, adminOnly, checkSuspended, checkGenderBoard, rateLimit } = require('../shared');
const express = require('express');
const router = express.Router();
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const socialLoginCodes = new Map(); // 임시 코드 저장 (메모리)

function createSocialCode(data) {
  const code = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  socialLoginCodes.set(code, { data, expires: Date.now() + 60000 }); // 1분 유효
  // 5분마다 만료된 코드 정리
  setTimeout(() => socialLoginCodes.delete(code), 60000);
  return code;
}

router.get('/api/auth/social-code', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: '코드가 없어요.' });
  const entry = socialLoginCodes.get(code);
  if (!entry || Date.now() > entry.expires) {
    socialLoginCodes.delete(code);
    return res.status(400).json({ error: '만료되거나 유효하지 않은 코드예요.' });
  }
  socialLoginCodes.delete(code); // 1회용
  res.json(entry.data);
});

// ══ 출석 캘린더 ══
router.get('/api/attendance/history', auth, async (req, res) => {
  const { year, month } = req.query;
  let query = supabase.from('attendance').select('date').eq('uid', req.user.id).order('date', {ascending:true});
  if (year && month) {
    const from = `${year}-${String(month).padStart(2,'0')}-01`;
    const to = `${year}-${String(month).padStart(2,'0')}-31`;
    query = query.gte('date', from).lte('date', to);
  }
  const { data } = await query;
  res.json((data||[]).map(d => d.date));
});

// ══ 자료실 ══
const STUDY_SUBJECTS = ['전체', '국어', '수학', '영어', '과학', '사회', '역사', '도덕', '기술가정', '음악', '미술', '체육', '기타'];

router.get('/api/study', auth, async (req, res) => {
  const { grade, subject } = req.query;
  if (!grade) return res.status(400).json({ error: '학년을 선택해주세요.' });
  let query = supabase.from('study_posts').select('*').eq('grade', parseInt(grade)).eq('deleted', false).order('created_at', { ascending: false });
  if (subject && subject !== '전체') query = query.eq('subject', subject);
  const { data } = await query;
  res.json(data || []);
});

router.post('/api/study', auth, checkSuspended, async (req, res) => {
  const { grade, subject, title, description, file_url, file_name, file_size } = req.body;
  if (!grade || !subject || !title) return res.status(400).json({ error: '학년, 과목, 제목은 필수예요.' });
  if (![1,2,3].includes(parseInt(grade))) return res.status(400).json({ error: '학년은 1~3이어야 해요.' });
  if (!STUDY_SUBJECTS.includes(subject)) return res.status(400).json({ error: '올바른 과목을 선택해주세요.' });
  if (!req.user.nickname) return res.status(400).json({ error: '닉네임을 먼저 설정해주세요.' });
  const { data, error } = await supabase.from('study_posts').insert({
    uid: req.user.id,
    author: req.user.nickname || req.user.name,
    grade: parseInt(grade),
    subject,
    title: title.trim(),
    description: description?.trim() || null,
    file_url: file_url || null,
    file_name: file_name || null,
    file_size: file_size || null,
    download_count: 0,
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await supabase.from('logs').insert({ uid: req.user.id, action: `자료 업로드: ${title} (${grade}학년)`, type: 'upload' });
  res.json(data);
});

router.post('/api/study/:id/download', auth, async (req, res) => {
  const { data } = await supabase.from('study_posts').select('*').eq('id', req.params.id).eq('deleted', false).single();
  if (!data) return res.status(404).json({ error: '자료를 찾을 수 없어요.' });
  await supabase.from('study_posts').update({ download_count: (data.download_count || 0) + 1 }).eq('id', req.params.id);
  res.json({ ok: true, file_url: data.file_url, file_name: data.file_name });
});

router.delete('/api/study/:id', auth, async (req, res) => {
  const { data } = await supabase.from('study_posts').select('uid').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: '자료를 찾을 수 없어요.' });
  const isAdmin = req.user.role === 'admin' || req.user.role === 'manager';
  if (data.uid !== req.user.id && !isAdmin) return res.status(403).json({ error: '삭제 권한이 없어요.' });
  await supabase.from('study_posts').update({ deleted: true }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══ 날씨 API (기상청 단기예보) ══
const WEATHER_NX = 59;  // 광주 동구 학동
const WEATHER_NY = 74;

router.get('/api/weather', auth, async (req, res) => {
  try {
    // 유저 학교 위치 기준 날씨
    const { data: user } = await supabase.from('users').select('school_id').eq('id', req.user.id).single();
    let nx = WEATHER_NX, ny = WEATHER_NY;
    if (user?.school_id) {
      const { data: school } = await supabase.from('schools').select('nx,ny').eq('id', user.school_id).single();
      if (school?.nx) { nx = school.nx; ny = school.ny; }
    }
    const now = new Date(new Date().toLocaleString('en-US', {timeZone:'Asia/Seoul'}));
    const pad = n => String(n).padStart(2,'0');
    const date = `${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}`;
    const hours = [2,5,8,11,14,17,20,23];
    const curHour = now.getHours();
    let baseHour = hours.filter(h => h <= curHour).pop() || 23;
    let baseDate = date;
    if (baseHour === 23 && curHour < 2) {
      const yesterday = new Date(now); yesterday.setDate(yesterday.getDate()-1);
      baseDate = `${yesterday.getFullYear()}${pad(yesterday.getMonth()+1)}${pad(yesterday.getDate())}`;
    }
    const baseTime = `${pad(baseHour)}00`;
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    const url = `https://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getVilageFcst?serviceKey=${key}&numOfRows=100&pageNo=1&dataType=JSON&base_date=${baseDate}&base_time=${baseTime}&nx=${nx}&ny=${ny}`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data?.response?.body?.items?.item || [];
    // 현재 시간 기준 날씨 파싱
    const targetTime = `${pad(curHour)}00`;
    const getVal = (cat) => items.find(i => i.category === cat && i.fcstTime === targetTime)?.fcstValue;
    const skyCode = getVal('SKY');
    const ptyCode = getVal('PTY');
    const skyMap = { '1':'맑음', '3':'구름많음', '4':'흐림' };
    const ptyMap = { '1':'비', '2':'비/눈', '3':'눈', '4':'소나기' };
    const skyText = ptyCode && ptyCode !== '0' ? ptyMap[ptyCode] : (skyMap[skyCode] || '맑음');
    const skyEmoji = ptyCode && ptyCode !== '0' ? (ptyCode==='3'?'🌨️':'🌧️') : (skyCode==='1'?'☀️':skyCode==='3'?'⛅':'☁️');
    res.json({
      temp: getVal('TMP') || '-',
      sky: skyText,
      skyEmoji,
      pop: getVal('POP') || '0',  // 강수확률
      humidity: getVal('REH') || '-',
      wind: getVal('WSD') || '-',
      pty: ptyCode || '0',
    });
  } catch(e) {
    res.status(500).json({ error: '날씨 정보를 불러오지 못했어요.' });
  }
});

// ══ 미세먼지 API (에어코리아) ══
router.get('/api/airquality', auth, async (req, res) => {
  try {
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    const url = `https://apis.data.go.kr/B552584/ArpltnInforInqireSvc/getCtprvnRltmMesureDnsty?serviceKey=${key}&returnType=json&numOfRows=100&pageNo=1&sidoName=광주&ver=1.0`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data?.response?.body?.items || [];
    // 광주 동구 측정소 찾기
    const station = items.find(i => i.stationName?.includes('동구') || i.stationName?.includes('학동')) || items[0];
    if (!station) return res.json({ pm10: '-', pm25: '-', grade: '정보없음' });
    const pm10 = parseInt(station.pm10Value) || 0;
    const pm25 = parseInt(station.pm25Value) || 0;
    const getGrade = (val, type) => {
      if (type === 'pm10') {
        if (val <= 30) return { text: '좋음', emoji: '😊', color: '#3b82f6' };
        if (val <= 80) return { text: '보통', emoji: '🙂', color: '#22c55e' };
        if (val <= 150) return { text: '나쁨', emoji: '😷', color: '#f59e0b' };
        return { text: '매우나쁨', emoji: '🤢', color: '#ef4444' };
      } else {
        if (val <= 15) return { text: '좋음', emoji: '😊', color: '#3b82f6' };
        if (val <= 35) return { text: '보통', emoji: '🙂', color: '#22c55e' };
        if (val <= 75) return { text: '나쁨', emoji: '😷', color: '#f59e0b' };
        return { text: '매우나쁨', emoji: '🤢', color: '#ef4444' };
      }
    };
    res.json({
      pm10, pm25,
      pm10Grade: getGrade(pm10, 'pm10'),
      pm25Grade: getGrade(pm25, 'pm25'),
      stationName: station.stationName,
      dataTime: station.dataTime,
    });
  } catch(e) {
    res.status(500).json({ error: '미세먼지 정보를 불러오지 못했어요.' });
  }
});

// ══ 버스 API (광주 BIS) ══
const GJ_BUS_STOPS = [
  { id: '1160', name: '운림중(정방향)' },
  { id: '1161', name: '운림중(역방향)' },
];

// 버스 도착 정보
router.get('/api/bus/arrive', auth, async (req, res) => {
  try {
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    // 유저 학교 버스 정류장
    let busStops = GJ_BUS_STOPS;
    const { data: user } = await supabase.from('users').select('school_id').eq('id', req.user.id).single();
    if (user?.school_id) {
      const { data: school } = await supabase.from('schools').select('bus_stops').eq('id', user.school_id).single();
      if (school?.bus_stops?.length) busStops = school.bus_stops;
    }
    const results = await Promise.all(busStops.map(async stop => {
      const url = `https://apis.data.go.kr/6290000/gj_bis/arriveInfo?serviceKey=${key}&stationId=${stop.id}&numOfRows=20&pageNo=1&returnType=json`;
      const resp = await fetch(url);
      const data = await resp.json();
      const buses = data?.response?.body?.items?.item || [];
      const busList = Array.isArray(buses) ? buses : [buses];
      return {
        stopId: stop.id,
        stopName: stop.name,
        buses: busList.map(b => ({
          routeNo: b.routeNo || b.lineNo || '-',
          arrTime: b.arrivalTime || b.arrmsg1 || '-',
          arrSec: parseInt(b.arrivalSec || 0),
          destination: b.endStationName || b.endStnNm || '-',
          lowBus: b.lowplate === '1' || b.lowBus === '1',
        })).filter(b => b.routeNo !== '-'),
      };
    }));
    res.json(results);
  } catch(e) {
    res.status(500).json({ error: '버스 정보를 불러오지 못했어요.' });
  }
});

// 버스 노선 정보
router.get('/api/bus/line/:routeNo', auth, async (req, res) => {
  try {
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    const url = `https://apis.data.go.kr/6290000/gj_bis/lineInfo?serviceKey=${key}&lineNo=${encodeURIComponent(req.params.routeNo)}&numOfRows=5&pageNo=1&returnType=json`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data?.response?.body?.items?.item || [];
    res.json(Array.isArray(items) ? items : [items]);
  } catch(e) {
    res.status(500).json({ error: '노선 정보를 불러오지 못했어요.' });
  }
});

// 버스 실시간 위치
router.get('/api/bus/location/:routeNo', auth, async (req, res) => {
  try {
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    const url = `https://apis.data.go.kr/6290000/gj_bis/busLocationInfo?serviceKey=${key}&lineNo=${encodeURIComponent(req.params.routeNo)}&numOfRows=20&pageNo=1&returnType=json`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data?.response?.body?.items?.item || [];
    res.json(Array.isArray(items) ? items : [items]);
  } catch(e) {
    res.status(500).json({ error: '버스 위치 정보를 불러오지 못했어요.' });
  }
});

// 정류장 검색
router.get('/api/bus/station', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) return res.status(400).json({ error: '검색어를 입력해주세요.' });
    const key = encodeURIComponent(process.env.PUBLIC_DATA_API_KEY);
    const url = `https://apis.data.go.kr/6290000/gj_bis/lineStationInfo?serviceKey=${key}&stationName=${encodeURIComponent(q)}&numOfRows=10&pageNo=1&returnType=json`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data?.response?.body?.items?.item || [];
    res.json(Array.isArray(items) ? items : [items]);
  } catch(e) {
    res.status(500).json({ error: '정류장 검색에 실패했어요.' });
  }
});

// ══ 이용약관 / 개인정보처리방침 / 저작권 정책 API ══
const TERMS_DATA = {
  version: '2.0',
  effective_date: '2026-03-01',
  terms: {
    service: `에브리유니 서비스 이용약관

제1조 (목적)
본 약관은 에브리유니가 제공하는 학교 커뮤니티 서비스의 이용 조건 및 절차, 이용자와 운영자의 권리·의무 및 책임사항을 규정함을 목적으로 합니다.

제2조 (서비스 이용 자격)
① 본 서비스는 운림중학교 재학생 및 관계자를 대상으로 합니다.
② 만 14세 미만의 이용자가 본 약관에 동의하는 경우, 법정대리인(부모 등)의 동의를 받은 것으로 간주합니다.
③ 타인의 정보를 도용하여 가입하는 행위는 엄격히 금지됩니다.

제3조 (이용자의 금지행위)
① 욕설, 비방, 모욕적 언어 사용
② 타인의 개인정보 무단 게시
③ 허위사실 유포 및 명예훼손
④ 성적으로 부적절한 콘텐츠 게시
⑤ 광고, 스팸, 홍보성 게시물 무단 게재
⑥ 다른 이용자에 대한 사이버 따돌림, 괴롭힘
⑦ 저작권이 있는 콘텐츠의 무단 게시
⑧ 타인의 계정을 도용하거나 사칭하는 행위

제4조 (운영자의 권한 및 면책)
① 운영자는 약관 위반 게시물을 사전 통보 없이 삭제할 수 있습니다.
② 본 서비스는 학교의 공식 서비스가 아닌 학생 개인이 운영하는 커뮤니티입니다.

제5조 (제재 및 처벌)
① 1차 위반: 경고 1회
② 2~3차 위반: 게시물 삭제 및 경고 누적
③ 경고 3회 이상: 계정 일시 정지
④ 중대한 위반: 즉시 영구 계정 정지

제9조 (약관의 변경)
본 약관은 필요 시 변경될 수 있으며, 변경 시 서비스 내 공지합니다.`,

    privacy: `개인정보 처리방침

1. 수집하는 개인정보
- 필수: 아이디, 이름, 생년월일, 비밀번호
- 선택: 이메일, 학년/반, 성별, 프로필 사진
- 소셜 로그인 시: 카카오/구글/네이버 계정 정보 (닉네임, 이메일, 프로필 사진)

2. 개인정보 수집 목적
- 서비스 제공 및 본인 확인
- 비밀번호 찾기 및 계정 보안
- 급식·시간표 등 맞춤 정보 제공

3. 보유 및 이용 기간
- 회원 탈퇴 후 6개월 보관 후 완전 파기
- 관련 법령에 따라 일정 기간 보관이 필요한 경우 해당 기간 보관

4. 개인정보의 제3자 제공
법령에 의한 경우를 제외하고 제3자에게 제공하지 않습니다.

5. 개인정보 보호 조치
- 비밀번호는 bcrypt로 암호화 저장
- HTTPS 암호화 통신
- DB 접근 권한 최소화

6. 이용자의 권리
언제든지 개인정보 열람, 수정, 삭제를 요청할 수 있습니다.

7. 개인정보 처리방침 변경
변경 시 서비스 내 공지사항을 통해 안내합니다.`,

    copyright: `게시물 저작권 정책

1. 이용자 게시물 저작권
이용자가 에브리유니에 게시한 콘텐츠(글, 사진, 영상 등)의 저작권은 해당 이용자에게 귀속됩니다.

2. 서비스 운영 목적 사용
운영자는 서비스 운영, 홍보, 개선 목적으로 이용자 게시물을 사용할 수 있습니다. 단, 이 경우 이용자의 명예를 훼손하거나 개인정보를 침해하지 않습니다.

3. 타인 저작물 게시 금지
① 타인의 저작물(글, 사진, 영상, 음악 등)을 출처 표시 없이 무단으로 게시하는 것은 금지됩니다.
② 위반 시 저작권법에 따라 민·형사상 책임을 질 수 있습니다.
③ 저작권 침해 게시물은 신고 후 즉시 삭제될 수 있습니다.

4. 저작권 침해 신고
저작권 침해가 의심되는 게시물은 관리자에게 신고해주세요.

5. 면책
에브리유니는 이용자가 게시한 콘텐츠로 인한 저작권 분쟁에 대해 책임을 지지 않습니다.`
  }
};

router.get('/api/terms', (req, res) => {
  const { type } = req.query;
  if (type && TERMS_DATA.terms[type]) {
    return res.json({ version: TERMS_DATA.version, effective_date: TERMS_DATA.effective_date, content: TERMS_DATA.terms[type], type });
  }
  res.json({ version: TERMS_DATA.version, effective_date: TERMS_DATA.effective_date, types: Object.keys(TERMS_DATA.terms) });
});

// ══ 멘션용 닉네임 검색 ══
router.get('/api/users/search-nickname', auth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  const { data } = await supabase.from('users')
    .select('id,nickname,avatar')
    .ilike('nickname', `${q}%`)
    .eq('deleted', false)
    .not('nickname', 'is', null)
    .neq('id', req.user.id)
    .limit(8);
  res.json((data||[]).map(u => ({ id: u.id, nickname: u.nickname, avatar: u.avatar })));
});

// ══ 에러 핸들러 (반드시 모든 라우트 뒤에 위치해야 함) ══
app.use((req,res) => res.status(404).json({error:'존재하지 않는 API예요.'}));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:'서버 오류가 발생했어요.'}); });

module.exports = router;
