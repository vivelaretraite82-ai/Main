const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const DB_PATH = path.join(DATA_DIR, 'vivelaretraite.db');

let Pool;
try { ({ Pool } = require('pg')); } catch {}
const USE_PG = !!((process.env.DATABASE_URL && Pool) || (process.env.PGHOST && Pool));
if (process.env.RENDER && !USE_PG) {
  console.error('DATABASE_URL manquant ou module pg non disponible. Configuration requise pour éviter la perte de données.');
  process.exit(1);
}
let db;
let pgPool;

function normalizePgSql(sql) {
  let q = sql;
  if (/insert\s+or\s+ignore/i.test(q)) {
    q = q.replace(/insert\s+or\s+ignore/i, 'INSERT');
    if (!/\bon\s+conflict\b/i.test(q)) q += ' ON CONFLICT DO NOTHING';
  }
  return q;
}

function toPgQuery(sql, params) {
  const values = Array.isArray(params) ? params : [];
  if (!values.length) {
    return { text: normalizePgSql(sql), values: [] };
  }
  let index = 0;
  const text = normalizePgSql(sql).replace(/\?/g, () => '$' + (++index));
  return { text, values };
}

if (USE_PG) {
  pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
  });
  db = {
    all(sql, params, cb) {
      if (typeof params === 'function') { cb = params; params = []; }
      const { text, values } = toPgQuery(sql, params || []);
      pgPool.query(text, values)
        .then(r => cb && cb(null, r.rows))
        .catch(e => cb && cb(e));
    },
    get(sql, params, cb) {
      if (typeof params === 'function') { cb = params; params = []; }
      const { text, values } = toPgQuery(sql, params || []);
      pgPool.query(text, values)
        .then(r => cb && cb(null, r.rows[0] || null))
        .catch(e => cb && cb(e));
    },
    run(sql, params, cb) {
      if (typeof params === 'function') { cb = params; params = []; }
      let { text, values } = toPgQuery(sql, params || []);
      const needsReturning = /^\s*insert/i.test(text) && !/\breturning\b/i.test(text);
      if (needsReturning) text += ' RETURNING id';
      pgPool.query(text, values)
        .then(r => {
          const ctx = { lastID: needsReturning && r.rows[0] ? r.rows[0].id : undefined, changes: r.rowCount };
          cb && cb.call(ctx, null);
        })
        .catch(e => cb && cb(e));
    },
    prepare(sql) {
      return {
        run: function() {
          const args = Array.from(arguments);
          const cb = typeof args[args.length - 1] === 'function' ? args.pop() : null;
          const params = args;
          let { text, values } = toPgQuery(sql, params);
          const needsReturning = /^\s*insert/i.test(text) && !/\breturning\b/i.test(text);
          if (needsReturning) text += ' RETURNING id';
          pgPool.query(text, values)
            .then(r => {
              const ctx = { lastID: needsReturning && r.rows[0] ? r.rows[0].id : undefined, changes: r.rowCount };
              cb && cb.call(ctx, null);
            })
            .catch(e => cb && cb(e));
        },
        finalize: function() {}
      };
    }
  };
} else {
  db = new sqlite3.Database(DB_PATH);
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prenom TEXT NOT NULL,
        nom TEXT NOT NULL,
        email TEXT NOT NULL,
        telephone TEXT,
        ville TEXT,
        naissance TEXT,
        preferences TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        email TEXT NOT NULL,
        telephone TEXT,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    db.run(`
      CREATE TABLE IF NOT EXISTS sorties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titre TEXT NOT NULL,
        description TEXT,
        date_iso TEXT,
        lieu TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    db.run('ALTER TABLE sorties ADD COLUMN categorie TEXT', () => {});
    db.run('ALTER TABLE sorties ADD COLUMN image_path TEXT', () => {});

    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        prenom TEXT,
        nom TEXT,
        telephone TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS reservations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sortie_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, sortie_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(sortie_id) REFERENCES sorties(id)
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sortie_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(sortie_id) REFERENCES sorties(id)
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
      )
    `);
  });
}

function ensureAdminUser() {
  const email = (process.env.ADMIN_EMAIL || 'vivelaretraite82@gmail.com').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || 'luanamax?';
  const hash = bcrypt.hashSync(password, 10);
  const prenom = 'Alexandra';
  const telephone = '0667095143';
  db.run(
    `
    INSERT INTO users (email, password_hash, prenom, nom, telephone)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash
    `,
    [email, hash, prenom, null, telephone]
  );
}

async function ensurePgSchema() {
  if (!USE_PG) return;
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS registrations (
      id SERIAL PRIMARY KEY,
      prenom TEXT NOT NULL,
      nom TEXT NOT NULL,
      email TEXT NOT NULL,
      telephone TEXT,
      ville TEXT,
      naissance TEXT,
      preferences TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      id SERIAL PRIMARY KEY,
      nom TEXT NOT NULL,
      email TEXT NOT NULL,
      telephone TEXT,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      prenom TEXT,
      nom TEXT,
      telephone TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS sorties (
      id SERIAL PRIMARY KEY,
      titre TEXT NOT NULL,
      description TEXT,
      date_iso TEXT,
      lieu TEXT,
      categorie TEXT,
      image_path TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS reservations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sortie_id INTEGER NOT NULL REFERENCES sorties(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, sortie_id)
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sortie_id INTEGER NOT NULL REFERENCES sorties(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
}

async function ensureAdminUserPg() {
  if (!USE_PG) return;
  const email = (process.env.ADMIN_EMAIL || 'vivelaretraite82@gmail.com').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || 'luanamax?';
  const hash = bcrypt.hashSync(password, 10);
  const prenom = 'Alexandra';
  const telephone = '0667095143';
  await pgPool.query(
    `INSERT INTO users (email, password_hash, prenom, nom, telephone)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (email) DO UPDATE SET
       password_hash = EXCLUDED.password_hash,
       prenom = COALESCE(EXCLUDED.prenom, users.prenom),
       nom = COALESCE(EXCLUDED.nom, users.nom),
       telephone = COALESCE(EXCLUDED.telephone, users.telephone)`,
    [email, hash, prenom, null, telephone]
  );
}

if (!USE_PG) {
  ensureAdminUser();
}

app.use(cors({
  origin: ['http://localhost:3000', 'https://vivelaretraite82-ai.github.io'],
  methods: ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());

app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));

app.use(express.static(__dirname));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads')));

function getTransporter() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  const port = SMTP_PORT ? parseInt(SMTP_PORT, 10) : 587;
  const secure = SMTP_SECURE ? SMTP_SECURE === 'true' : port === 465;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}

app.post('/inscription', (req, res) => {
  const { prenom, nom, email, telephone, ville, naissance, password } = req.body;
  let preferences = req.body.preferences || '';

  if (Array.isArray(preferences)) {
    preferences = preferences.join(', ');
  }

  if (!prenom || !nom || !email) {
    return res.status(400).send('Merci de remplir au minimum le prénom, le nom et l’email.');
  }

  const stmt = db.prepare(`
    INSERT INTO registrations (prenom, nom, email, telephone, ville, naissance, preferences)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    prenom.trim(),
    nom.trim(),
    email.trim(),
    telephone ? telephone.trim() : null,
    ville ? ville.trim() : null,
    naissance ? naissance.trim() : null,
    preferences || null,
    (err) => {
      if (err) {
        console.error('Erreur lors de l’enregistrement inscription:', err);
        return res.status(500).send('Une erreur est survenue, merci de réessayer plus tard.');
      }
      if (email && password) {
        const normalizedEmail = email.trim().toLowerCase();
        const hash = bcrypt.hashSync(String(password), 10);
        db.run(
          `
          INSERT INTO users (email, password_hash, prenom, nom, telephone)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(email) DO UPDATE SET
            password_hash = excluded.password_hash,
            prenom = COALESCE(excluded.prenom, users.prenom),
            nom = COALESCE(excluded.nom, users.nom),
            telephone = COALESCE(excluded.telephone, users.telephone)
          `,
          [
            normalizedEmail,
            hash,
            prenom ? prenom.trim() : null,
            nom ? nom.trim() : null,
            telephone ? telephone.trim() : null
          ]
        );
      }
      const transporter = getTransporter();
      if (transporter) {
        transporter.sendMail({
          to: 'vivelaretraite82@gmail.com',
          from: process.env.FROM_EMAIL || 'no-reply@vivelaretraite.local',
          subject: 'Nouvelle inscription Vive la Retraite',
          text: `Prénom: ${prenom}\nNom: ${nom}\nEmail: ${email}\nTéléphone: ${telephone || ''}\nVille: ${ville || ''}\nNaissance: ${naissance || ''}\nPréférences: ${preferences || ''}`
        }, (e) => {
          if (e) console.error('Envoi email inscription échoué:', e.message);
        });
      }
      return res.redirect('/?inscription=ok');
    }
  );

  stmt.finalize();
});

app.post('/contact', (req, res) => {
  const { nom, email, telephone, message } = req.body;

  if (!nom || !email || !message) {
    return res.status(400).send('Merci de remplir au minimum votre nom, votre email et votre message.');
  }

  const stmt = db.prepare(`
    INSERT INTO contacts (nom, email, telephone, message)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run(
    nom.trim(),
    email.trim(),
    telephone ? telephone.trim() : null,
    message.trim(),
    (err) => {
      if (err) {
        console.error('Erreur lors de l’enregistrement du contact:', err);
        return res.status(500).send('Une erreur est survenue, merci de réessayer plus tard.');
      }
      const transporter = getTransporter();
      if (transporter) {
        transporter.sendMail({
          to: 'vivelaretraite82@gmail.com',
          from: process.env.FROM_EMAIL || 'no-reply@vivelaretraite.local',
          subject: 'Nouveau message de contact',
          text: `Nom: ${nom}\nEmail: ${email}\nTéléphone: ${telephone || ''}\nMessage:\n${message}`
        }, (e) => {
          if (e) console.error('Envoi email contact échoué:', e.message);
        });
      }
      return res.redirect('/?contact=ok');
    }
  );

  stmt.finalize();
});

function isAdminEmail(emailRaw) {
  if (!emailRaw) return false;
  const adminEmail = (process.env.ADMIN_EMAIL || 'vivelaretraite82@gmail.com').trim().toLowerCase();
  return String(emailRaw).trim().toLowerCase() === adminEmail;
}

function getAdminUser(callback) {
  const adminEmail = (process.env.ADMIN_EMAIL || 'vivelaretraite82@gmail.com').trim().toLowerCase();
  db.get('SELECT id, email, prenom, nom, telephone FROM users WHERE email = ?', [adminEmail], callback);
}

function signToken(user) {
  const payload = { uid: user.id, email: user.email, isAdmin: isAdminEmail(user.email) };
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: '15d' });
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const secret = process.env.JWT_SECRET || 'dev-secret';
    const data = jwt.verify(token, secret);
    req.user = data;
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || !isAdminEmail(req.user.email)) {
    return res.status(403).json({ error: 'admin_only' });
  }
  next();
}

function ensureUploadsDir() {
  const dir = path.join(DATA_DIR, 'uploads');
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  } catch {}
  return dir;
}

function saveBase64Image(dataUrl) {
  if (!dataUrl) return null;
  const m = String(dataUrl).match(/^data:(.+);base64,(.*)$/);
  if (!m) return null;
  const mime = m[1];
  const base64 = m[2];
  const allowed = ['image/jpeg','image/png','image/webp'];
  const extMap = { 'image/jpeg':'jpg', 'image/png':'png', 'image/webp':'webp' };
  if (!allowed.includes(mime)) return null;
  const buf = Buffer.from(base64, 'base64');
  // basic server-side size guard ~5MB
  if (buf.length > 5 * 1024 * 1024) return null;
  if (USE_PG) {
    return dataUrl;
  }
  const uploadsDir = ensureUploadsDir();
  const fname = `sortie-${Date.now()}-${Math.random().toString(36).slice(2,8)}.${extMap[mime]}`;
  const full = path.join(uploadsDir, fname);
  try {
    fs.writeFileSync(full, buf);
    return '/uploads/' + fname;
  } catch {
    return null;
  }
}

app.post('/auth/signup', (req, res) => {
  const { email, password, prenom, nom, telephone } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (email, password_hash, prenom, nom, telephone) VALUES (?, ?, ?, ?, ?)');
  stmt.run(email.trim().toLowerCase(), hash, prenom || null, nom || null, telephone || null, function(err) {
    if (err) return res.status(400).json({ error: 'email_exists' });
    const user = { id: this.lastID, email };
    const token = signToken(user);
    res.json({ token, user: { id: user.id, email, prenom, nom, telephone, isAdmin: isAdminEmail(email) } });
  });
  stmt.finalize();
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });
  db.get('SELECT id, email, password_hash, prenom, nom, telephone FROM users WHERE email = ?', [email.trim().toLowerCase()], (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = bcrypt.compareSync(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    const token = signToken(row);
    res.json({ token, user: { id: row.id, email: row.email, prenom: row.prenom, nom: row.nom, telephone: row.telephone, isAdmin: isAdminEmail(row.email) } });
  });
});

app.get('/me', auth, (req, res) => {
  db.get('SELECT id, email, prenom, nom, telephone, created_at FROM users WHERE id = ?', [req.user.uid], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not_found' });
    res.json({ ...row, isAdmin: isAdminEmail(row.email) });
  });
});

app.get('/me/reservations', auth, (req, res) => {
  const q = `
    SELECT r.id, r.created_at, s.id AS sortie_id, s.titre, s.date_iso, s.lieu, s.description
    FROM reservations r
    JOIN sorties s ON s.id = r.sortie_id
    WHERE r.user_id = ?
    ORDER BY r.created_at DESC
  `;
  db.all(q, [req.user.uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.post('/sorties/:id/reserver', auth, (req, res) => {
  const sortieId = parseInt(req.params.id, 10);
  if (!sortieId) return res.status(400).json({ error: 'invalid_sortie' });
  const stmt = db.prepare('INSERT OR IGNORE INTO reservations (user_id, sortie_id) VALUES (?, ?)');
  stmt.run(req.user.uid, sortieId, (err) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ ok: true });
  });
  stmt.finalize();
});

app.post('/sorties/:id/comment', auth, (req, res) => {
  const sortieId = parseInt(req.params.id, 10);
  const { text } = req.body;
  if (!sortieId || !text) return res.status(400).json({ error: 'invalid_input' });
  const q = 'SELECT 1 FROM reservations WHERE user_id = ? AND sortie_id = ?';
  db.get(q, [req.user.uid, sortieId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!row) return res.status(403).json({ error: 'not_reserved' });
    const stmt = db.prepare('INSERT INTO comments (user_id, sortie_id, text) VALUES (?, ?, ?)');
    stmt.run(req.user.uid, sortieId, text.trim(), (e) => {
      if (e) return res.status(500).json({ error: 'db_error' });
      res.json({ ok: true });
    });
    stmt.finalize();
  });
});

app.get('/api/comments', (req, res) => {
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const iso = sixMonthsAgo.toISOString();
  const q = `
    SELECT c.id, c.text, c.created_at, s.titre, s.id AS sortie_id
    FROM comments c
    JOIN sorties s ON s.id = c.sortie_id
    WHERE c.created_at >= ?
    ORDER BY c.created_at DESC
  `;
  db.all(q, [iso], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});
app.get('/api/registrations', (req, res) => {
  db.all('SELECT id, prenom, nom, email, telephone, ville, naissance, preferences, created_at FROM registrations ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.get('/api/contacts', (req, res) => {
  db.all('SELECT id, nom, email, telephone, message, created_at FROM contacts ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.get('/api/sorties', (req, res) => {
  db.all('SELECT id, titre, description, date_iso, lieu, categorie, image_path, created_at FROM sorties ORDER BY date_iso ASC, created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.get('/messages', auth, (req, res) => {
  const currentId = req.user.uid;
  const isAdmin = isAdminEmail(req.user.email);
  const otherUserIdParam = parseInt(req.query.user_id || '', 10);

  function sendConversation(otherId) {
    if (!otherId) return res.json([]);
    const q = `
      SELECT m.id, m.sender_id, m.recipient_id, m.body, m.created_at,
             us.email AS sender_email, us.prenom AS sender_prenom, us.nom AS sender_nom
      FROM messages m
      JOIN users us ON us.id = m.sender_id
      WHERE (m.sender_id = ? AND m.recipient_id = ?)
         OR (m.sender_id = ? AND m.recipient_id = ?)
      ORDER BY m.created_at ASC
    `;
    db.all(q, [currentId, otherId, otherId, currentId], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json(rows);
    });
  }

  if (isAdmin) {
    if (!otherUserIdParam) return res.json([]);
    return sendConversation(otherUserIdParam);
  }

  getAdminUser((err, admin) => {
    if (err || !admin) return res.json([]);
    sendConversation(admin.id);
  });
});

app.post('/messages', auth, (req, res) => {
  const senderId = req.user.uid;
  const isAdmin = isAdminEmail(req.user.email);
  const text = (req.body && req.body.body ? String(req.body.body) : '').trim();
  const targetUserId = req.body && req.body.user_id ? parseInt(req.body.user_id, 10) : null;
  if (!text) return res.status(400).json({ error: 'empty' });

  function insertMessage(recipientId) {
    if (!recipientId) return res.status(400).json({ error: 'invalid_recipient' });
    const stmt = db.prepare('INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)');
    stmt.run(senderId, recipientId, text, (err) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ ok: true });
    });
    stmt.finalize();
  }

  if (isAdmin) {
    return insertMessage(targetUserId);
  }

  getAdminUser((err, admin) => {
    if (err || !admin) return res.status(500).json({ error: 'no_admin' });
    insertMessage(admin.id);
  });
});

app.get('/admin/reservations', auth, requireAdmin, (req, res) => {
  const q = `
    SELECT r.id, r.created_at, u.email, u.prenom, u.nom, u.telephone,
           s.titre, s.date_iso, s.lieu
    FROM reservations r
    JOIN users u ON u.id = r.user_id
    JOIN sorties s ON s.id = r.sortie_id
    ORDER BY r.created_at DESC
    LIMIT 200
  `;
  db.all(q, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.post('/admin/api/sorties', auth, requireAdmin, (req, res) => {
  const { titre, description, date_iso, lieu, categorie, image_base64 } = req.body || {};
  if (!titre || !String(titre).trim()) return res.status(400).json({ error: 'titre_required' });
  let image_path = null;
  if (image_base64) {
    image_path = saveBase64Image(image_base64) || null;
  }
  const stmt = db.prepare(`
    INSERT INTO sorties (titre, description, date_iso, lieu, categorie, image_path)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    String(titre).trim(),
    description ? String(description).trim() : null,
    date_iso ? String(date_iso).trim() : null,
    lieu ? String(lieu).trim() : null,
    categorie ? String(categorie).trim() : null,
    image_path,
    function(err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ id: this.lastID });
    }
  );
  stmt.finalize();
});

app.delete('/admin/sorties/:id', auth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  db.get('SELECT image_path FROM sorties WHERE id = ?', [id], (e, row) => {
    db.run('DELETE FROM sorties WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (row && row.image_path) {
        const clean = String(row.image_path).replace(/^\/+/, ''); // remove leading slash
        const full = path.join(DATA_DIR, clean);
        fs.unlink(full, () => {});
      }
      res.json({ deleted: this.changes > 0 });
    });
  });
});

app.get('/admin/messages/threads', auth, requireAdmin, (req, res) => {
  const adminId = req.user.uid;
  const q = `
    SELECT
      CASE
        WHEN m.sender_id = ? THEN m.recipient_id
        ELSE m.sender_id
      END AS other_id,
      u.email,
      u.prenom,
      u.nom,
      MAX(m.created_at) AS last_created
    FROM messages m
    JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
    WHERE m.sender_id = ? OR m.recipient_id = ?
    GROUP BY other_id, u.email, u.prenom, u.nom
    ORDER BY last_created DESC
  `;
  db.all(q, [adminId, adminId, adminId, adminId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

function checkAdminKey(req, res, next) {
  const required = process.env.ADMIN_KEY;
  if (!required) return next();
  const key = req.query.key || req.headers['x-admin-key'];
  if (key && key === required) return next();
  res.status(401).send('Accès refusé');
}

app.post('/admin/sorties', checkAdminKey, (req, res) => {
  const { titre, description, date_iso, lieu } = req.body;
  if (!titre) return res.status(400).send('Titre requis');
  const stmt = db.prepare(`
    INSERT INTO sorties (titre, description, date_iso, lieu)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(
    titre.trim(),
    description ? description.trim() : null,
    date_iso ? date_iso.trim() : null,
    lieu ? lieu.trim() : null,
    (err) => {
      if (err) return res.status(500).send('Erreur base de données');
      res.redirect('/admin?created=1');
    }
  );
  stmt.finalize();
});

app.get('/admin', checkAdminKey, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

function startServer(initialPort) {
  let port = initialPort;
  function attempt() {
    const server = app.listen(port, () => {
      console.log(`Serveur Vive la Retraite démarré sur http://localhost:${port}`);
    });
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        port += 1;
        if (port < initialPort + 10) {
          attempt();
        } else {
          console.error('Aucun port disponible');
          process.exit(1);
        }
      } else {
        console.error('Erreur serveur:', err);
        process.exit(1);
      }
    });
  }
  attempt();
}

const PREFERRED_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

async function bootstrap() {
  if (USE_PG) {
    try {
      await ensurePgSchema();
      await ensureAdminUserPg();
    } catch (e) {
      console.error('Erreur initialisation PostgreSQL:', e);
      process.exit(1);
    }
  }
  startServer(PREFERRED_PORT);
}

bootstrap();
