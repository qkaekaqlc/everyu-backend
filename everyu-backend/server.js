require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');
const { Server } = require('socket.io');
const { supabase, SECRET, getBannedIps, webpush, auth, rateLimit } = require('./shared');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const jwt = require('jsonwebtoken');

const app = express();
app.set('trust proxy', 1);

// ══ 보안 미들웨어 ══
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https:"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "https:"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'https://everyu-frontend.vercel.app',
    'http://localhost:3000', 'http://localhost:5500',
  ],
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// Rate Limiter (전체)
const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 500, message: { error: '너무 많은 요청이에요.' } });
app.use(globalLimiter);
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true, limit: '30mb' }));

// ══ IP 차단 미들웨어 ══
app.use(async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const bannedSet = await getBannedIps();
  if (bannedSet.has(ip)) return res.status(403).json({ error: '접근이 차단된 IP예요.' });
  next();
});

// ══ 헬스체크 ══
app.get('/', (req, res) => res.json({ status: 'ok', service: '에브리유니 서버' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ══ 라우트 등록 ══
app.use('/api', require('./routes/auth'));
app.use('/api', require('./routes/posts'));
app.use('/api', require('./routes/dm'));
app.use('/api', require('./routes/misc'));
app.use('/api', require('./routes/admin'));
app.use('/api', require('./routes/social'));
app.use('/api', require('./routes/external'));

// ══ Socket.io (실시간 채팅) ══
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [process.env.FRONTEND_URL || 'https://everyu-frontend.vercel.app', 'http://localhost:3000', 'http://localhost:5500'],
    methods: ['GET','POST'],
  }
});

const ANIMALS = ['호랑이','사자','코끼리','기린','펭귄','토끼','여우','늑대','곰','독수리','돌고래','판다','코알라','치타','얼룩말'];
const roomUsers = {};

io.on('connection', async (socket) => {
  const token = socket.handshake.auth?.token;
  let user = null;
  if (token) {
    try { user = jwt.verify(token, SECRET); } catch {}
  }
  const { room } = socket.handshake.query;
  if (!room) return;
  socket.join(room);
  const nickname = '익명의 ' + ANIMALS[Math.floor(Math.random() * ANIMALS.length)];
  roomUsers[socket.id] = { nickname, room, userId: user?.id };
  io.to(room).emit('system', { text: nickname + '님이 입장했어요 👋', type: 'join' });
  socket.emit('my_nickname', { nickname });

  socket.on('chat', async (msg) => {
    const userData = roomUsers[socket.id];
    if (!userData) return;
    const now = new Date();
    const msgData = { nickname: userData.nickname, body: msg.body, time: now.toISOString(), userId: userData.userId };
    io.to(userData.room).emit('chat', msgData);
    if (userData.userId) {
      supabase.from('chat_messages').insert({ room: userData.room, nickname: userData.nickname, body: msg.body, created_at: now.toISOString() }).then(() => {});
    }
  });

  socket.on('disconnect', () => {
    const userData = roomUsers[socket.id];
    if (userData) {
      io.to(userData.room).emit('system', { text: userData.nickname + '님이 퇴장했어요 👋', type: 'leave' });
      delete roomUsers[socket.id];
    }
  });
});

// ══ 에러 핸들러 ══
app.use((req, res) => res.status(404).json({ error: '존재하지 않는 API예요.' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: '서버 오류가 발생했어요.' }); });

// ══ 서버 시작 ══
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 에브리유니 서버 실행 중 → 포트 ${PORT}`);
  async function cleanOldLogs() {
    const cutoff = new Date(Date.now() - 90*24*60*60*1000).toISOString();
    await supabase.from('logs').delete().lt('created_at', cutoff);
    await supabase.from('security_logs').delete().lt('created_at', cutoff);
    await supabase.from('warn_logs').delete().lt('created_at', cutoff);
    await supabase.from('refresh_tokens').delete().lt('expires_at', new Date().toISOString());
    // pending 게임 랭킹 정리
    const pendingCutoff = new Date(Date.now() - 7*24*60*60*1000).toISOString();
    await supabase.from('game_rankings').delete().eq('pending', true).lt('created_at', pendingCutoff);
    // 6개월 지난 탈퇴 계정 개인정보 파기
    const now = new Date().toISOString();
    const { data: expiredUsers } = await supabase.from('users').select('id').eq('deleted', true).not('delete_at', 'is', null).lt('delete_at', now);
    if (expiredUsers?.length) {
      for (const u of expiredUsers) {
        await supabase.from('users').update({ name:'탈퇴한 사용자', email:null, email_verified:false, avatar:null, bday:null, password:null, security_question:null, security_answer:null, nickname:null, grade:null, classroom:null, delete_at:null }).eq('id', u.id);
      }
      console.log(`🧹 탈퇴 계정 개인정보 파기: ${expiredUsers.length}건`);
    }
    console.log('🧹 오래된 로그 정리 완료');
  }
  cleanOldLogs();
  setInterval(cleanOldLogs, 24*60*60*1000);
});
