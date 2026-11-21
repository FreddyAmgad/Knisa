const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'sundayschool.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ---------- DATABASE ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','admin')),
  points INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS quizzes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  passage_ref TEXT,
  passage_text TEXT NOT NULL,
  bonus_points INTEGER NOT NULL DEFAULT 5,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS questions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  options TEXT NOT NULL,            -- JSON array of strings
  correct_index INTEGER NOT NULL,   -- model answer
  points INTEGER NOT NULL DEFAULT 10,
  position INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  score INTEGER NOT NULL,
  bonus INTEGER NOT NULL DEFAULT 0,
  finish_rank INTEGER NOT NULL,
  submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, quiz_id)          -- one attempt per student per quiz
);
CREATE TABLE IF NOT EXISTS answers(
  attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  chosen_index INTEGER NOT NULL,
  is_correct INTEGER NOT NULL,
  PRIMARY KEY(attempt_id, question_id)
);
`);

// ---------- THE ONE ADMIN ACCOUNT (created from env vars, never via signup) ----------
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const u = process.env.ADMIN_USER || 'admin';
  const p = process.env.ADMIN_PASS || 'admin123';
  db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'admin')")
    .run('مدرس الفصل', u, bcrypt.hashSync(p, 10));
  console.log(`Admin created -> username: ${u}  (CHANGE THE PASSWORD via ADMIN_PASS env var before first run!)`);
}

// ---------- APP ----------
const app = express();
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const cookie = (req, k) => (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(x => x[0] === k)?.[1];
function auth(req, res, next) {
  const t = cookie(req, 'sid');
  const u = t && db.prepare('SELECT u.id,u.name,u.username,u.role,u.points FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t);
  if (!u) return res.status(401).json({ error: 'سجّل الدخول أولاً' });
  req.user = u; next();
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'للمدرس فقط' });
const login = (res, id) => {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id) VALUES(?,?)').run(t, id);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}`);
};

app.post('/api/signup', (req, res) => {
  const name = String(req.body.name || '').trim(), username = String(req.body.username || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (name.length < 2 || username.length < 3 || password.length < 4) return res.status(400).json({ error: 'تأكد من الاسم (٢+) واسم المستخدم (٣+) وكلمة السر (٤+)' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'اسم المستخدم مأخوذ، جرب غيره' });
  const r = db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'student')").run(name, username, bcrypt.hashSync(password, 10));
  login(res, r.lastInsertRowid); res.json({ ok: true });
});
app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(req.body.username || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash)) return res.status(401).json({ error: 'اسم المستخدم أو كلمة السر غلط' });
  login(res, u.id); res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token=?').run(cookie(req, 'sid') || '');
  res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(req.user));

// ---- student side ----
app.get('/api/quizzes', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT q.id,q.title,q.passage_ref,q.bonus_points,q.active,q.created_at,
      (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS n_questions,
      (SELECT COALESCE(SUM(points),0) FROM questions WHERE quiz_id=q.id) AS max_score,
      (SELECT COUNT(*) FROM attempts WHERE quiz_id=q.id) AS n_attempts,
      a.score AS my_score, a.bonus AS my_bonus, a.finish_rank AS my_rank
    FROM quizzes q LEFT JOIN attempts a ON a.quiz_id=q.id AND a.user_id=?
    ${req.user.role === 'admin' ? '' : 'WHERE q.active=1'} ORDER BY q.id DESC`).all(req.user.id);
  res.json(rows);
});
app.get('/api/quizzes/:id', auth, (req, res) => {
  const q = db.prepare('SELECT * FROM quizzes WHERE id=?').get(req.params.id);
  if (!q || (!q.active && req.user.role !== 'admin')) return res.status(404).json({ error: 'الدرس غير موجود' });
  const att = db.prepare('SELECT * FROM attempts WHERE quiz_id=? AND user_id=?').get(q.id, req.user.id);
  const qs = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id').all(q.id);
  const mine = att ? Object.fromEntries(db.prepare('SELECT question_id,chosen_index FROM answers WHERE attempt_id=?').all(att.id).map(a => [a.question_id, a.chosen_index])) : {};
  res.json({
    id: q.id, title: q.title, passage_ref: q.passage_ref, passage_text: q.passage_text, bonus_points: q.bonus_points,
    attempt: att ? { score: att.score, bonus: att.bonus, rank: att.finish_rank } : null,
    questions: qs.map(x => ({
      id: x.id, text: x.text, options: JSON.parse(x.options), points: x.points,
      ...(att ? { correct_index: x.correct_index, chosen_index: mine[x.id] } : {})   // model answers only revealed AFTER submitting
    }))
  });
});
app.post('/api/quizzes/:id/submit', auth, (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'المدرس لا يحل الأسئلة' });
  const run = db.transaction(() => {
    const q = db.prepare('SELECT * FROM quizzes WHERE id=? AND active=1').get(req.params.id);
    if (!q) throw { code: 404, error: 'الدرس غير موجود' };
    if (db.prepare('SELECT 1 FROM attempts WHERE quiz_id=? AND user_id=?').get(q.id, req.user.id)) throw { code: 409, error: 'لقد حللت هذا الاختبار من قبل' };
    const qs = db.prepare('SELECT * FROM questions WHERE quiz_id=?').all(q.id);
    const given = req.body.answers || {};
    if (qs.some(x => !Number.isInteger(given[x.id]))) throw { code: 400, error: 'جاوب على كل الأسئلة' };
    let score = 0, max = 0;
    const graded = qs.map(x => {
      const ok = given[x.id] === x.correct_index; max += x.points; if (ok) score += x.points;
      return { id: x.id, chosen: given[x.id], ok: ok ? 1 : 0, correct: x.correct_index };
    });
    const finish_rank = db.prepare('SELECT COUNT(*) c FROM attempts WHERE quiz_id=?').get(q.id).c + 1;
    const bonus = finish_rank <= 5 ? q.bonus_points : 0;          // first 5 finishers get the bonus
    const a = db.prepare('INSERT INTO attempts(user_id,quiz_id,score,bonus,finish_rank) VALUES(?,?,?,?,?)').run(req.user.id, q.id, score, bonus, finish_rank);
    const ins = db.prepare('INSERT INTO answers VALUES(?,?,?,?)');
    graded.forEach(g => ins.run(a.lastInsertRowid, g.id, g.chosen, g.ok));
    db.prepare('UPDATE users SET points=points+? WHERE id=?').run(score + bonus, req.user.id);
    return { score, max, bonus, rank: finish_rank };
  });
  try { res.json(run()); } catch (e) { if (e.code) return res.status(e.code).json({ error: e.error }); console.error(e); res.status(500).json({ error: 'خطأ في الخادم' }); }
});
app.get('/api/leaderboard', auth, (req, res) => {
  res.json(db.prepare(`SELECT u.id,u.name,u.points,(SELECT COUNT(*) FROM attempts WHERE user_id=u.id) AS quizzes_done
    FROM users u WHERE u.role='student' ORDER BY u.points DESC, u.name LIMIT 100`).all());
});

// ---- admin side ----
app.post('/api/admin/quizzes', auth, adminOnly, (req, res) => {
  const b = req.body, qs = Array.isArray(b.questions) ? b.questions : [];
  if (!String(b.title || '').trim() || !String(b.passage_text || '').trim()) return res.status(400).json({ error: 'اكتب عنوان الدرس ونص الآيات' });
  if (!qs.length) return res.status(400).json({ error: 'أضف سؤالاً واحداً على الأقل' });
  for (const [i, x] of qs.entries()) {
    const o = Array.isArray(x.options) ? x.options.map(s => String(s).trim()).filter(Boolean) : [];
    if (!String(x.text || '').trim() || o.length < 2 || !Number.isInteger(x.correct_index) || x.correct_index < 0 || x.correct_index >= o.length)
      return res.status(400).json({ error: `السؤال ${i + 1}: اكتب السؤال وخيارين على الأقل وحدد الإجابة الصحيحة` });
  }
  const id = db.transaction(() => {
    const r = db.prepare('INSERT INTO quizzes(title,passage_ref,passage_text,bonus_points) VALUES(?,?,?,?)')
      .run(b.title.trim(), String(b.passage_ref || '').trim(), b.passage_text.trim(), Math.max(0, parseInt(b.bonus_points) || 0));
    const ins = db.prepare('INSERT INTO questions(quiz_id,text,options,correct_index,points,position) VALUES(?,?,?,?,?,?)');
    qs.forEach((x, i) => ins.run(r.lastInsertRowid, x.text.trim(), JSON.stringify(x.options.map(s => String(s).trim()).filter(Boolean)), x.correct_index, Math.max(1, parseInt(x.points) || 10), i));
    return r.lastInsertRowid;
  })();
  res.json({ id });
});
app.patch('/api/admin/quizzes/:id', auth, adminOnly, (req, res) => {
  db.prepare('UPDATE quizzes SET active=? WHERE id=?').run(req.body.active ? 1 : 0, req.params.id); res.json({ ok: true });
});
app.delete('/api/admin/quizzes/:id', auth, adminOnly, (req, res) => {
  db.transaction(() => {   // take back the points earned from this quiz
    db.prepare(`UPDATE users SET points=points-(SELECT COALESCE(SUM(score+bonus),0) FROM attempts WHERE user_id=users.id AND quiz_id=?)
      WHERE id IN (SELECT user_id FROM attempts WHERE quiz_id=?)`).run(req.params.id, req.params.id);
    db.prepare('DELETE FROM quizzes WHERE id=?').run(req.params.id);
  })();
  res.json({ ok: true });
});
app.get('/api/admin/quizzes/:id/results', auth, adminOnly, (req, res) => {
  res.json(db.prepare(`SELECT u.name,a.score,a.bonus,a.finish_rank,a.submitted_at FROM attempts a JOIN users u ON u.id=a.user_id
    WHERE a.quiz_id=? ORDER BY a.finish_rank`).all(req.params.id));
});

app.listen(PORT, () => console.log(`Sunday School app running on http://localhost:${PORT}`));
