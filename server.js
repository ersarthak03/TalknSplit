// server.js — TalknSplit backend with auth + SQLite + email + local parser + OpenAI
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');

const app = express();

// ---------- CONFIG ----------
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'voicesplit.db');

const MAIL_HOST = process.env.EMAIL_HOST;
const MAIL_PORT = process.env.EMAIL_PORT || 587;
const MAIL_USER = process.env.EMAIL_USER;
const MAIL_PASS = process.env.EMAIL_PASS;
const MAIL_FROM = process.env.EMAIL_FROM || MAIL_USER;

if (!OPENAI_API_KEY) {
  console.warn('Warning: OPENAI_API_KEY is not set in .env (OpenAI fallback may not work).');
}

// ---------- DATABASE SETUP (SQLite) ----------
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT UNIQUE NOT NULL,
       password TEXT NOT NULL
     )`,
    (err) => {
      if (err) console.error('Error creating users table:', err);
      else console.log('Users table ready.');
    }
  );
});

function getUserByUsername(username, callback) {
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    callback(err, row);
  });
}

function createUser(username, password, callback) {
  db.run(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, password],
    function (err) {
      callback(err, this?.lastID);
    }
  );
}

// ---------- EMAIL SETUP ----------
let mailer = null;
if (MAIL_HOST && MAIL_USER && MAIL_PASS) {
  mailer = nodemailer.createTransport({
    host: MAIL_HOST,
    port: MAIL_PORT,
    secure: false,
    auth: {
      user: MAIL_USER,
      pass: MAIL_PASS,
    },
  });
  console.log('Email transport configured.');
} else {
  console.warn('Email not configured (missing EMAIL_HOST/EMAIL_USER/EMAIL_PASS)');
}

// Helper: send result emails (non-blocking in API)
async function sendResultEmails(emails, result, options = {}) {
  if (!mailer) {
    console.warn('Mailer not configured, skipping email send.');
    return;
  }
  if (!Array.isArray(emails) || emails.length === 0) return;

  const { transcript, username } = options;
  const { expenses = [], balances = {}, settleUp = [], note } = result || {};

  let text = '';
  if (username) {
    text += `Hi,\n\n${username} just recorded a new expense.\n\n`;
  } else {
    text += `Hi,\n\nA new expense was recorded.\n\n`;
  }

  if (transcript) {
    text += `Transcript:\n"${transcript}"\n\n`;
  }

  text += `Parsed expenses:\n`;
  if (Array.isArray(expenses) && expenses.length > 0) {
    for (const e of expenses) {
      text += `  - ${e.payer} paid ${e.amount} for ${e.description} (split among: ${
        Array.isArray(e.split_with) ? e.split_with.join(', ') : ''
      })\n`;
    }
  } else {
    text += `  (none)\n`;
  }

  text += `\nBalances:\n`;
  const balKeys = Object.keys(balances || {});
  if (balKeys.length > 0) {
    for (const name of balKeys) {
      text += `  - ${name}: ${balances[name]}\n`;
    }
  } else {
    text += `  (none)\n`;
  }

  text += `\nSuggested settlements:\n`;
  if (Array.isArray(settleUp) && settleUp.length > 0) {
    for (const s of settleUp) {
      text += `  - ${s.from} → ${s.to}: ${s.amount}\n`;
    }
  } else {
    text += `  Already balanced.\n`;
  }

  if (note) {
    text += `\nNote: ${note}\n`;
  }

  text += `\n\n— Sent by TalknSplit`;

  const mailOptions = {
    from: MAIL_FROM,
    to: emails.join(','),
    subject: 'New expense split from TalknSplit',
    text,
  };

  try {
    const info = await mailer.sendMail(mailOptions);
    console.log('Emails sent:', info.messageId, 'to', emails);
  } catch (err) {
    console.error('Error sending emails:', err);
  }
}

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: 'change-this-secret-key', // change this in production
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

// ---------- AUTH ROUTES ----------
app.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.redirect('/login?error=1');
  }

  getUserByUsername(username, (err, user) => {
    if (err) {
      console.error('DB error on login:', err);
      return res.redirect('/login?error=1');
    }
    if (!user || user.password !== password) {
      return res.redirect('/login?error=1');
    }
    req.session.user = { id: user.id, username: user.username };
    return res.redirect('/');
  });
});

app.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body || {};
  const u = (username || '').trim();
  const p = (password || '').trim();

  if (!u || !p) {
    return res.redirect('/register?error=empty');
  }

  getUserByUsername(u, (err, existing) => {
    if (err) {
      console.error('DB error on register:', err);
      return res.redirect('/register?error=unknown');
    }
    if (existing) {
      return res.redirect('/register?error=exists');
    }

    createUser(u, p, (err2, newId) => {
      if (err2) {
        console.error('DB error creating user:', err2);
        return res.redirect('/register?error=unknown');
      }
      req.session.user = { id: newId, username: u };
      return res.redirect('/');
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ---------- ACCOUNT / PROFILE API ROUTES ----------
app.get('/api/me', requireLogin, (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  res.json({
    id: req.session.user.id,
    username: req.session.user.username,
  });
});

app.post('/api/change-password', requireLogin, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const userId = req.session.user.id;

  // SQLite mode (local dev)
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error('DB error on change-password (select):', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) return res.status(404).json({ error: 'User not found' });
    if (row.password !== currentPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    db.run('UPDATE users SET password = ? WHERE id = ?', [newPassword, userId], (err2) => {
      if (err2) {
        console.error('DB error on change-password (update):', err2);
        return res.status(500).json({ error: 'Database error' });
      }
      return res.json({ ok: true });
    });
  });
});

// ---------- MAIN PAGES (PROTECTED) ----------
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/index.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Static assets
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------
// Local deterministic parser
// ---------------------------
function parseAndComputeSimpleSplit(transcript, participantsArg = []) {
  if (!transcript || typeof transcript !== 'string') {
    return { expenses: [], balances: {}, settleUp: [], note: 'Empty transcript' };
  }
  const text = transcript.replace(/[\r\n]/g, ' ').replace(/\s+/g, ' ').trim();

  const transferRegex = /([A-Za-z][A-Za-z']*)\s+paid\s+([A-Za-z][A-Za-z']*)\s+(\d{1,7}(?:\.\d{1,2})?)/gi;
  const paidRegex = /(\b[Ii]\b|\bme\b|\bmy\b|[A-Za-z][A-Za-z']*)\s+paid\s+(\d{1,7}(?:\.\d{1,2})?)/gi;
  const directRegex = /([A-Za-z][A-Za-z']*)\s+(\d{1,7}(?:\.\d{1,2})?)/gi;

  const STOPWORDS = new Set(['paid','split','between','and','all','us','the','for','with']);
  const paymentsCents = new Map();
  const transfers = [];
  const usedRanges = [];
  const defaultUserLabel =
    Array.isArray(participantsArg) && participantsArg.length > 0
      ? participantsArg[0]
      : 'You';

  const overlapsUsed = (s, e) =>
    usedRanges.some((r) => !(e <= r.start || s >= r.end));
  const markUsed = (s, e) => usedRanges.push({ start: s, end: e });

  // 1) "X paid Y N"
  for (const m of text.matchAll(transferRegex)) {
    const start = m.index ?? -1;
    const end = start + (m[0]?.length || 0);
    if (start >= 0 && overlapsUsed(start, end)) continue;

    let payer = m[1].trim();
    let recipient = m[2].trim();
    const amount = Number(m[3]);
    if (Number.isNaN(amount)) continue;

    const pLower = payer.toLowerCase();
    if (pLower === 'i' || pLower === 'me' || pLower === 'my') {
      payer = defaultUserLabel;
    }

    payer = payer.charAt(0).toUpperCase() + payer.slice(1);
    recipient = recipient.charAt(0).toUpperCase() + recipient.slice(1);
    if (STOPWORDS.has(payer.toLowerCase()) || STOPWORDS.has(recipient.toLowerCase())) continue;

    transfers.push({
      from: payer,
      to: recipient,
      cents: Math.round(amount * 100),
    });

    if (start >= 0) markUsed(start, end);
  }

  // 2) "X paid N"
  for (const m of text.matchAll(paidRegex)) {
    const start = m.index ?? -1;
    const end = start + (m[0]?.length || 0);
    if (start >= 0 && overlapsUsed(start, end)) continue;

    let who = m[1].trim();
    const amount = Number(m[2]);
    if (Number.isNaN(amount)) continue;

    const wLower = who.toLowerCase();
    if (wLower === 'i' || wLower === 'me' || wLower === 'my') {
      who = defaultUserLabel;
    }

    who = who.charAt(0).toUpperCase() + who.slice(1);
    if (STOPWORDS.has(who.toLowerCase())) continue;

    paymentsCents.set(
      who,
      (paymentsCents.get(who) || 0) + Math.round(amount * 100)
    );

    if (start >= 0) markUsed(start, end);
  }

  // 3) "Name 300"
  for (const m of text.matchAll(directRegex)) {
    const start = m.index ?? -1;
    const end = start + (m[0]?.length || 0);
    if (start >= 0 && overlapsUsed(start, end)) continue;

    let whoRaw = m[1].trim();
    const amount = Number(m[2]);
    if (Number.isNaN(amount)) continue;

    let who = whoRaw;
    const whoLower = who.toLowerCase();
    if (whoLower === 'i' || whoLower === 'me' || whoLower === 'my') {
      who = defaultUserLabel;
    }
    if (STOPWORDS.has(who.toLowerCase())) continue;

    who = who.charAt(0).toUpperCase() + who.slice(1);
    paymentsCents.set(
      who,
      (paymentsCents.get(who) || 0) + Math.round(amount * 100)
    );

    if (start >= 0) markUsed(start, end);
  }

  if (paymentsCents.size === 0 && transfers.length === 0) {
    return {
      expenses: [],
      balances: {},
      settleUp: [],
      note: 'No payments or transfers found',
    };
  }

  const participantsSet = new Set();
  for (const k of paymentsCents.keys()) participantsSet.add(k);
  for (const t of transfers) {
    participantsSet.add(t.from);
    participantsSet.add(t.to);
  }
  let participants = Array.from(participantsSet);
  if (participants.length === 0 && participantsArg.length > 0) {
    participants = participantsArg.map(
      (p) => p.charAt(0).toUpperCase() + p.slice(1)
    );
  }
  for (const p of participants) {
    if (!paymentsCents.has(p)) paymentsCents.set(p, 0);
  }

  const balancesCents = {};
  participants.forEach((p) => (balancesCents[p] = 0));

  const totalExpensesCents = Array.from(paymentsCents.values()).reduce(
    (a, b) => a + b,
    0
  );
  const n = participants.length;

  if (totalExpensesCents > 0 && n > 0) {
    const shareFloor = Math.floor(totalExpensesCents / n);
    const remainder = totalExpensesCents - shareFloor * n;
    const shareCents = participants.map(
      (_, i) => shareFloor + (i < remainder ? 1 : 0)
    );

    participants.forEach((p, i) => {
      balancesCents[p] -= shareCents[i];
    });

    for (const [payer, cents] of paymentsCents.entries()) {
      balancesCents[payer] += cents;
    }
  }

  for (const t of transfers) {
    if (!(t.from in balancesCents)) balancesCents[t.from] = 0;
    if (!(t.to in balancesCents)) balancesCents[t.to] = 0;

    balancesCents[t.from] += t.cents;
    balancesCents[t.to] -= t.cents;
  }

  const balances = {};
  for (const [p, c] of Object.entries(balancesCents)) {
    balances[p] = Number((c / 100).toFixed(2));
  }

  const expenses = [];
  for (const [payer, cents] of paymentsCents.entries()) {
    expenses.push({
      payer,
      amount: Number((cents / 100).toFixed(2)),
      description: 'split expense',
      split_with: participants.slice(),
    });
  }

  const creditors = [];
  const debtors = [];
  for (const [p, c] of Object.entries(balancesCents)) {
    if (c > 0) creditors.push({ name: p, cents: c });
    else if (c < 0) debtors.push({ name: p, cents: -c });
  }
  creditors.sort((a, b) => b.cents - a.cents);
  debtors.sort((a, b) => b.cents - a.cents);

  const settleUp = [];
  let i = 0,
    j = 0;
  while (i < debtors.length && j < creditors.length) {
    const debtor = debtors[i];
    const creditor = creditors[j];
    const amount = Math.min(debtor.cents, creditor.cents);

    settleUp.push({
      from: debtor.name,
      to: creditor.name,
      amount: Number((amount / 100).toFixed(2)),
    });

    debtor.cents -= amount;
    creditor.cents -= amount;
    if (debtor.cents === 0) i++;
    if (creditor.cents === 0) j++;
  }

  return { expenses, balances, settleUp, note: null };
}

// ---------------------------
// API endpoint (PROTECTED)
// ---------------------------
app.post('/api/process-transcript', requireLogin, async (req, res) => {
  try {
    const { transcript, participants = [], emails = [] } = req.body;
    if (!transcript || typeof transcript !== 'string') {
      return res
        .status(400)
        .json({ error: 'Missing or invalid `transcript` in request body.' });
    }

    const allStrings = [
      ...(Array.isArray(participants) ? participants : []),
      ...(Array.isArray(emails) ? emails : []),
    ];
    const emailList = [...new Set(
      allStrings
        .map((s) => String(s).trim())
        .filter((s) => s.includes('@'))
    )];

    const fast = parseAndComputeSimpleSplit(
      transcript,
      Array.isArray(participants) ? participants : []
    );
    if (fast && Array.isArray(fast.expenses) && fast.expenses.length > 0) {
      console.log(
        'Handled locally with deterministic parser. Participants:',
        Object.keys(fast.balances)
      );

      // fire and forget
      sendResultEmails(emailList, fast, {
        transcript,
        username: req.session.user?.username,
      });

      return res.json(fast);
    }

    if (!OPENAI_API_KEY) {
      const result = {
        expenses: [],
        balances: {},
        settleUp: [],
        note:
          'No expenses detected by local parser and OpenAI API key is not configured / quota exceeded.',
      };

      sendResultEmails(emailList, result, {
        transcript,
        username: req.session.user?.username,
      });

      return res.status(200).json(result);
    }

    const safeTranscript = JSON.stringify(transcript);
    const participantList =
      Array.isArray(participants) && participants.length
        ? participants.join(', ')
        : 'unspecified';

    const systemPrompt =
      'You are a JSON-only assistant that extracts structured expense records from free text and computes splits/balances. Only output valid JSON (no explanatory text).';
    const userPrompt = `Transcript: ${safeTranscript}

Participants: ${participantList}

Return JSON with the following structure:
{
  "expenses": [
    { "payer": "name", "amount": 12.5, "description": "text", "split_with": ["A","B"] }
  ],
  "balances": { "Alice": 10.5, "Bob": -5.25 },
  "settleUp": [ { "from": "Bob", "to": "Alice", "amount": 5.25 } ],
  "note": "optional short note if needed"
}

Rules:
- Only return a single JSON object, nothing else.
- If you can't parse amounts, return an empty expenses array and set the 'note' field explaining the issue.
- Use participant names from the Participants field when possible.
`;

    const payload = {
      model: OPENAI_MODEL,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
      max_tokens: 800,
    };

    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify(payload),
    });

    if (!r.ok) {
      const errText = await r.text();
      console.error('OpenAI API error:', r.status, errText);
      const errorResult = { error: 'OpenAI API error', details: errText };

      sendResultEmails(emailList, errorResult, {
        transcript,
        username: req.session.user?.username,
      });

      return res.status(502).json(errorResult);
    }

    const j = await r.json();
    const assistantText = j.choices?.[0]?.message?.content;
    if (!assistantText) {
      console.error('OpenAI returned empty response body', j);
      const errorResult = { error: 'Empty response from OpenAI' };

      sendResultEmails(emailList, errorResult, {
        transcript,
        username: req.session.user?.username,
      });

      return res.status(502).json(errorResult);
    }

    let parsed;
    try {
      parsed = JSON.parse(assistantText);
    } catch {
      const maybe = assistantText.match(/\{[\s\S]*\}/);
      if (maybe) {
        try {
          parsed = JSON.parse(maybe[0]);
        } catch (err2) {
          console.error('Failed to parse extracted JSON substring', err2);
          const errorResult = {
            error: 'Model returned non-JSON or malformed JSON',
            raw: assistantText,
          };

          sendResultEmails(emailList, errorResult, {
            transcript,
            username: req.session.user?.username,
          });

          return res.status(502).json(errorResult);
        }
      } else {
        console.error('Model returned non-JSON:', assistantText);
        const errorResult = {
          error: 'Model returned non-JSON',
          raw: assistantText,
        };

        sendResultEmails(emailList, errorResult, {
          transcript,
          username: req.session.user?.username,
        });

        return res.status(502).json(errorResult);
      }
    }

    parsed.expenses = Array.isArray(parsed.expenses) ? parsed.expenses : [];
    parsed.balances =
      parsed.balances && typeof parsed.balances === 'object'
        ? parsed.balances
        : {};
    parsed.settleUp = Array.isArray(parsed.settleUp) ? parsed.settleUp : [];
    parsed.note = parsed.note || null;

    console.log(`Parsed by LLM ${parsed.expenses.length} expense(s).`);

    sendResultEmails(emailList, parsed, {
      transcript,
      username: req.session.user?.username,
    });

    return res.json(parsed);
  } catch (err) {
    console.error('Server error in /api/process-transcript:', err);
    const errorResult = {
      error: 'Internal server error',
      details: err?.message || String(err),
    };

    const { participants = [], emails = [] } = req.body || {};
    const allStrings = [
      ...(Array.isArray(participants) ? participants : []),
      ...(Array.isArray(emails) ? emails : []),
    ];
    const emailList = [...new Set(
      allStrings
        .map((s) => String(s).trim())
        .filter((s) => s.includes('@'))
    )];

    sendResultEmails(emailList, errorResult, {
      transcript: req.body?.transcript,
      username: req.session?.user?.username,
    });

    return res.status(500).json(errorResult);
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log(`SQLite DB file: ${DB_FILE}`);
});
