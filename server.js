const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const DB_PATH = path.join(__dirname, 'vivelaretraite.db');

const db = new sqlite3.Database(DB_PATH);

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
});

app.use(cors({
  origin: ['http://localhost:3000', 'https://vivelaretraite82-ai.github.io'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(__dirname));

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
  const { prenom, nom, email, telephone, ville, naissance } = req.body;
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

function signToken(user) {
  const payload = { uid: user.id, email: user.email };
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

app.post('/auth/signup', (req, res) => {
  const { email, password, prenom, nom, telephone } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare('INSERT INTO users (email, password_hash, prenom, nom, telephone) VALUES (?, ?, ?, ?, ?)');
  stmt.run(email.trim().toLowerCase(), hash, prenom || null, nom || null, telephone || null, function(err) {
    if (err) return res.status(400).json({ error: 'email_exists' });
    const user = { id: this.lastID, email };
    const token = signToken(user);
    res.json({ token, user: { id: user.id, email, prenom, nom, telephone } });
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
    res.json({ token, user: { id: row.id, email: row.email, prenom: row.prenom, nom: row.nom, telephone: row.telephone } });
  });
});

app.get('/me', auth, (req, res) => {
  db.get('SELECT id, email, prenom, nom, telephone, created_at FROM users WHERE id = ?', [req.user.uid], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not_found' });
    res.json(row);
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
  db.all('SELECT id, titre, description, date_iso, lieu, created_at FROM sorties ORDER BY date_iso ASC, created_at DESC', (err, rows) => {
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
startServer(PREFERRED_PORT);
