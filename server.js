const express = require('express');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;

if (!process.env.TURSO_DATABASE_URL) {
  console.warn('Warning: TURSO_DATABASE_URL is not set.');
}

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ---------- DATABASE ----------
async function initDb() {
  await db.batch(
    [
      `CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','admin')),
        points INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS quizzes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        passage_ref TEXT,
        passage_text TEXT NOT NULL,
        bonus_points INTEGER NOT NULL DEFAULT 5,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS questions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        options TEXT NOT NULL,
        correct_index INTEGER NOT NULL,
        points INTEGER NOT NULL DEFAULT 10,
        position INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
        score INTEGER NOT NULL,
        bonus INTEGER NOT NULL DEFAULT 0,
        finish_rank INTEGER NOT NULL,
        submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, quiz_id)
      )`,
      `CREATE TABLE IF NOT EXISTS answers(
        attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
        chosen_index INTEGER NOT NULL,
        is_correct INTEGER NOT NULL,
        PRIMARY KEY(attempt_id, question_id)
      )`,
    ],
    'write'
  );

  // ---------- THE ONE ADMIN ACCOUNT (created from env vars, never via signup) ----------
  const adminCheck = await db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
  if (!adminCheck.rows.length) {
    const u = process.env.ADMIN_USER || 'admin';
    const p = process.env.ADMIN_PASS || 'admin123';
    await db.execute({
      sql: "INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'admin')",
      args: ['مدرس الفصل', u, bcrypt.hashSync(p, 10)],
    });
    console.log(`Admin created -> username: ${u}  (CHANGE THE PASSWORD via ADMIN_PASS env var before first run!)`);
  }
}

// ---------- APP ----------
const app = express();
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const cookie = (req, k) =>
  (req.headers.cookie || '')
    .split(';')
    .map((s) => s.trim().split('='))
    .find((x) => x[0] === k)?.[1];

async function auth(req, res, next) {
  try {
    const t = cookie(req, 'sid');
    if (!t) return res.status(401).json({ error: 'سجّل الدخول أولاً' });

    const r = await db.execute({
      sql: 'SELECT u.id,u.name,u.username,u.role,u.points FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?',
      args: [t],
    });
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: 'سجّل الدخول أولاً' });

    req.user = u;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
}

const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'للمدرس فقط' });

async function login(res, id) {
  const t = crypto.randomBytes(32).toString('hex');
  await db.execute({
    sql: 'INSERT INTO sessions(token,user_id) VALUES(?,?)',
    args: [t, id],
  });
  res.setHeader(
    'Set-Cookie',
    `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}`
  );
}

app.post('/api/signup', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2 || username.length < 3 || password.length < 4) {
      return res.status(400).json({ error: 'تأكد من الاسم (٢+) واسم المستخدم (٣+) وكلمة السر (٤+)' });
    }

    const exists = await db.execute({
      sql: 'SELECT 1 FROM users WHERE username=? LIMIT 1',
      args: [username],
    });
    if (exists.rows.length) {
      return res.status(409).json({ error: 'اسم المستخدم مأخوذ، جرب غيره' });
    }

    const r = await db.execute({
      sql: "INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'student')",
      args: [name, username, bcrypt.hashSync(password, 10)],
    });

    await login(res, Number(r.lastInsertRowid));
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const r = await db.execute({
      sql: 'SELECT * FROM users WHERE username=? LIMIT 1',
      args: [username],
    });
    const u = r.rows[0];
    if (!u || !bcrypt.compareSync(password, u.password_hash)) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة السر غلط' });
    }

    await login(res, Number(u.id));
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const sid = cookie(req, 'sid') || '';
    if (sid) {
      await db.execute({
        sql: 'DELETE FROM sessions WHERE token=?',
        args: [sid],
      });
    }
    res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/');
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/me', auth, (req, res) => res.json(req.user));

// ---- student side ----
app.get('/api/quizzes', auth, async (req, res) => {
  try {
    const r = await db.execute({
      sql: `
        SELECT q.id,q.title,q.passage_ref,q.bonus_points,q.active,q.created_at,
          (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS n_questions,
          (SELECT COALESCE(SUM(points),0) FROM questions WHERE quiz_id=q.id) AS max_score,
          (SELECT COUNT(*) FROM attempts WHERE quiz_id=q.id) AS n_attempts,
          a.score AS my_score, a.bonus AS my_bonus, a.finish_rank AS my_rank
        FROM quizzes q LEFT JOIN attempts a ON a.quiz_id=q.id AND a.user_id=?
        ${req.user.role === 'admin' ? '' : 'WHERE q.active=1'} ORDER BY q.id DESC`,
      args: [req.user.id],
    });
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/quizzes/:id', auth, async (req, res) => {
  try {
    const qRes = await db.execute({
      sql: 'SELECT * FROM quizzes WHERE id=? LIMIT 1',
      args: [req.params.id],
    });
    const q = qRes.rows[0];
    if (!q || (!q.active && req.user.role !== 'admin')) {
      return res.status(404).json({ error: 'الدرس غير موجود' });
    }

    const attRes = await db.execute({
      sql: 'SELECT * FROM attempts WHERE quiz_id=? AND user_id=? LIMIT 1',
      args: [q.id, req.user.id],
    });
    const att = attRes.rows[0];

    const qsRes = await db.execute({
      sql: 'SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id',
      args: [q.id],
    });
    const qs = qsRes.rows;

    let mine = {};
    if (att) {
      const ansRes = await db.execute({
        sql: 'SELECT question_id,chosen_index FROM answers WHERE attempt_id=?',
        args: [att.id],
      });
      mine = Object.fromEntries(ansRes.rows.map((a) => [a.question_id, a.chosen_index]));
    }

    res.json({
      id: q.id,
      title: q.title,
      passage_ref: q.passage_ref,
      passage_text: q.passage_text,
      bonus_points: q.bonus_points,
      attempt: att ? { score: att.score, bonus: att.bonus, rank: att.finish_rank } : null,
      questions: qs.map((x) => ({
        id: x.id,
        text: x.text,
        options: JSON.parse(x.options),
        points: x.points,
        ...(att ? { correct_index: x.correct_index, chosen_index: mine[x.id] } : {}),
      })),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.post('/api/quizzes/:id/submit', auth, async (req, res) => {
  if (req.user.role === 'admin') {
    return res.status(403).json({ error: 'المدرس لا يحل الأسئلة' });
  }

  let tx;
  try {
    tx = await db.transaction('write');

    const qRes = await tx.execute({
      sql: 'SELECT * FROM quizzes WHERE id=? AND active=1 LIMIT 1',
      args: [req.params.id],
    });
    const q = qRes.rows[0];
    if (!q) {
      await tx.rollback();
      return res.status(404).json({ error: 'الدرس غير موجود' });
    }

    const dupRes = await tx.execute({
      sql: 'SELECT 1 FROM attempts WHERE quiz_id=? AND user_id=? LIMIT 1',
      args: [q.id, req.user.id],
    });
    if (dupRes.rows.length) {
      await tx.rollback();
      return res.status(409).json({ error: 'لقد حللت هذا الاختبار من قبل' });
    }

    const qsRes = await tx.execute({
      sql: 'SELECT * FROM questions WHERE quiz_id=?',
      args: [q.id],
    });
    const qs = qsRes.rows;

    const given = req.body.answers || {};
    if (qs.some((x) => !Number.isInteger(given[x.id]))) {
      await tx.rollback();
      return res.status(400).json({ error: 'جاوب على كل الأسئلة' });
    }

    let score = 0;
    let max = 0;
    const graded = qs.map((x) => {
      const ok = given[x.id] === x.correct_index;
      max += x.points;
      if (ok) score += x.points;
      return { id: x.id, chosen: given[x.id], ok: ok ? 1 : 0, correct: x.correct_index };
    });

    const cntRes = await tx.execute({
      sql: 'SELECT COUNT(*) AS c FROM attempts WHERE quiz_id=?',
      args: [q.id],
    });
    const finish_rank = Number(cntRes.rows[0].c) + 1;
    const bonus = finish_rank <= 5 ? q.bonus_points : 0;

    const attIns = await tx.execute({
      sql: 'INSERT INTO attempts(user_id,quiz_id,score,bonus,finish_rank) VALUES(?,?,?,?,?)',
      args: [req.user.id, q.id, score, bonus, finish_rank],
    });
    const attemptId = Number(attIns.lastInsertRowid);

    for (const g of graded) {
      await tx.execute({
        sql: 'INSERT INTO answers(attempt_id,question_id,chosen_index,is_correct) VALUES(?,?,?,?)',
        args: [attemptId, g.id, g.chosen, g.ok],
      });
    }

    await tx.execute({
      sql: 'UPDATE users SET points=points+? WHERE id=?',
      args: [score + bonus, req.user.id],
    });

    await tx.commit();
    res.json({ score, max, bonus, rank: finish_rank });
  } catch (e) {
    if (tx && !tx.closed) {
      try { await tx.rollback(); } catch (_) {}
    }
    if (e?.code === 'SQLITE_CONSTRAINT' || String(e?.message || '').includes('UNIQUE')) {
      return res.status(409).json({ error: 'لقد حللت هذا الاختبار من قبل' });
    }
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/leaderboard', auth, async (req, res) => {
  try {
    const r = await db.execute(`
      SELECT u.id,u.name,u.points,(SELECT COUNT(*) FROM attempts WHERE user_id=u.id) AS quizzes_done
      FROM users u WHERE u.role='student' ORDER BY u.points DESC, u.name LIMIT 100
    `);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// ---- admin side ----
app.post('/api/admin/quizzes', auth, adminOnly, async (req, res) => {
  const b = req.body || {};
  const qs = Array.isArray(b.questions) ? b.questions : [];
  if (!String(b.title || '').trim() || !String(b.passage_text || '').trim()) {
    return res.status(400).json({ error: 'اكتب عنوان الدرس ونص الآيات' });
  }
  if (!qs.length) {
    return res.status(400).json({ error: 'أضف سؤالاً واحداً على الأقل' });
  }
  for (const [i, x] of qs.entries()) {
    const o = Array.isArray(x.options) ? x.options.map((s) => String(s).trim()).filter(Boolean) : [];
    if (
      !String(x.text || '').trim() ||
      o.length < 2 ||
      !Number.isInteger(x.correct_index) ||
      x.correct_index < 0 ||
      x.correct_index >= o.length
    ) {
      return res.status(400).json({
        error: `السؤال ${i + 1}: اكتب السؤال وخيارين على الأقل وحدد الإجابة الصحيحة`,
      });
    }
  }

  let tx;
  try {
    tx = await db.transaction('write');
    const r = await tx.execute({
      sql: 'INSERT INTO quizzes(title,passage_ref,passage_text,bonus_points) VALUES(?,?,?,?)',
      args: [
        b.title.trim(),
        String(b.passage_ref || '').trim(),
        b.passage_text.trim(),
        Math.max(0, parseInt(b.bonus_points, 10) || 0),
      ],
    });
    const quizId = Number(r.lastInsertRowid);

    for (const [i, x] of qs.entries()) {
      const cleanedOptions = x.options.map((s) => String(s).trim()).filter(Boolean);
      await tx.execute({
        sql: 'INSERT INTO questions(quiz_id,text,options,correct_index,points,position) VALUES(?,?,?,?,?,?)',
        args: [
          quizId,
          x.text.trim(),
          JSON.stringify(cleanedOptions),
          x.correct_index,
          Math.max(1, parseInt(x.points, 10) || 10),
          i,
        ],
      });
    }

    await tx.commit();
    res.json({ id: quizId });
  } catch (e) {
    if (tx && !tx.closed) {
      try { await tx.rollback(); } catch (_) {}
    }
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.patch('/api/admin/quizzes/:id', auth, adminOnly, async (req, res) => {
  try {
    await db.execute({
      sql: 'UPDATE quizzes SET active=? WHERE id=?',
      args: [req.body.active ? 1 : 0, req.params.id],
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.delete('/api/admin/quizzes/:id', auth, adminOnly, async (req, res) => {
  let tx;
  try {
    tx = await db.transaction('write');
    await tx.execute({
      sql: `UPDATE users SET points=points-(SELECT COALESCE(SUM(score+bonus),0) FROM attempts WHERE user_id=users.id AND quiz_id=?)
            WHERE id IN (SELECT user_id FROM attempts WHERE quiz_id=?)`,
      args: [req.params.id, req.params.id],
    });
    await tx.execute({
      sql: 'DELETE FROM quizzes WHERE id=?',
      args: [req.params.id],
    });
    await tx.commit();
    res.json({ ok: true });
  } catch (e) {
    if (tx && !tx.closed) {
      try { await tx.rollback(); } catch (_) {}
    }
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/admin/quizzes/:id/results', auth, adminOnly, async (req, res) => {
  try {
    const r = await db.execute({
      sql: `SELECT u.name,a.score,a.bonus,a.finish_rank,a.submitted_at FROM attempts a JOIN users u ON u.id=a.user_id
            WHERE a.quiz_id=? ORDER BY a.finish_rank`,
      args: [req.params.id],
    });
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Sunday School app running on http://localhost:${PORT}`));
  })
  .catch((e) => {
    console.error('Failed to initialize database:', e);
    process.exit(1);
  });