// TQS Bill Tracker — Local Office Server
// Node.js + Express + sql.js (pure JavaScript SQLite — no Python/compilation needed!)
const express   = require('express');
const path      = require('path');
const fs        = require('fs');
const os        = require('os');
const crypto    = require('crypto');
const initSqlJs = require('sql.js');
const nodemailer = require('nodemailer');

const app     = express();
const PORT    = 3000; // merged PO+WO tracker
const DB_PATH = path.join(__dirname, 'tqs_erp.db');

// ── AUTO-BACKUP DIRECTORY ──
const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  console.log('[AutoBackup] Created backups directory:', BACKUP_DIR);
}

// ── UPLOADS DIRECTORY (bill scan files stored on disk) ──
const UPLOADS_DIR = path.join(__dirname, 'uploads', 'bills');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  console.log('[Uploads] Created uploads directory:', UPLOADS_DIR);
}

// ── SERVER-SIDE SESSIONS ──
// Tokens are random 32-byte hex strings; sessions expire after 8 hours.
const SESSIONS_FILE = path.join(__dirname, '.sessions.json');
const sessions = new Map(); // token → { dept, userId, name, email, projectId, projectName, expiresAt }
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Load sessions from disk on startup
function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
      const now = Date.now();
      Object.entries(data).forEach(([token, session]) => {
        if (session.expiresAt > now) sessions.set(token, session);
      });
      console.log(`[Sessions] Loaded ${sessions.size} valid sessions from disk`);
    }
  } catch (err) {
    console.warn('[Sessions] Could not load persisted sessions:', err.message);
  }
}

// Save sessions to disk
function saveSessions() {
  try {
    const data = Object.fromEntries(sessions);
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('[Sessions] Failed to save sessions:', err.message);
  }
}

// Save sessions every 5 minutes
setInterval(saveSessions, 5 * 60 * 1000);

// Password hashing — scrypt with per-user salt (no extra dependencies)
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function verifyPassword(password, salt, storedHash) {
  try {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
  } catch { return false; }
}

// Purge expired sessions every hour
setInterval(() => {
  const now = Date.now();
  let purged = 0;
  for (const [tok, s] of sessions) {
    if (s.expiresAt < now) { sessions.delete(tok); purged++; }
  }
  if (purged > 0) { console.log(`[Sessions] Purged ${purged} expired sessions`); saveSessions(); }
}, 60 * 60 * 1000);

// Graceful shutdown — persist sessions
process.on('SIGINT', () => { saveSessions(); process.exit(0); });
process.on('SIGTERM', () => { saveSessions(); process.exit(0); });
process.on('exit', saveSessions);

// Paths that do NOT require a valid session token
const AUTH_EXEMPT = new Set(['/auth/login', '/auth/logout', '/auth/me', '/health', '/projects']);

function requireAuth(req, res, next) {
  // req.path is relative to the '/api' mount point → e.g. '/auth/login'
  if (AUTH_EXEMPT.has(req.path)) return next();
  // Allow unauthenticated reads of public settings (company branding)
  if (req.path === '/settings' && req.method === 'GET') return next();

  const token = req.headers['x-auth-token'];
  const session = token ? sessions.get(token) : null;
  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(token); // remove stale
    return res.status(401).json({ ok: false, error: 'Authentication required. Please log in.' });
  }
  req.dept      = session.dept;
  req.userId    = session.userId;
  req.userName  = session.name;
  req.userEmail = session.email;
  req.projectId = session.projectId || 0;
  next();
}

// Helper: sanitize filename to prevent path traversal
function sanitizeFilename(name) {
  return path.basename(name).replace(/[^a-zA-Z0-9._\-() ]/g, '_').substring(0, 200);
}

// Helper: get the folder for a specific SL
function getBillUploadDir(sl) {
  const dir = path.join(UPLOADS_DIR, `SL-${sl}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// ── CORS — restrict to local network only ──
function isLocalNetwork(ip) {
  if (!ip) return false;
  const cleaned = ip.replace(/^::ffff:/, '');
  return (
    cleaned === '127.0.0.1' ||
    cleaned === '::1' ||
    /^192\.168\./.test(cleaned) ||
    /^10\./.test(cleaned) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(cleaned)
  );
}

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  const ip = req.ip || req.socket?.remoteAddress || '';
  if (isLocalNetwork(ip) || !origin) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,X-Auth-Token');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE — applies to all /api/* routes ──
// Exempt paths (login, logout, me, health) bypass the check inside requireAuth.
app.use('/api', requireAuth);

let db;

function getDbErrorMessage(err) {
  if (err.code === 'EPERM' || err.code === 'EACCES') {
    return 'Permission denied. Database folder may be protected or located in OneDrive/Google Drive.';
  }
  if (err.code === 'ENOSPC') return 'No space left on device. Check disk storage.';
  if (err.code === 'EISDIR') return 'Database path is a directory, not a file.';
  return err.message || 'Unknown database error';
}

function saveDb() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
    return { success: true };
  } catch (err) {
    const errorMsg = getDbErrorMessage(err);
    console.error('Database save error:', errorMsg);
    return { success: false, error: errorMsg };
  }
}

function query(sql, params) {
  params = params || [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function run(sql, params) {
  db.run(sql, params || []);
}

async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
    console.log('Loaded existing database');
  } else {
    db = new SQL.Database();
    console.log('Created new database');
  }

  run(`CREATE TABLE IF NOT EXISTS bills (
    sl TEXT PRIMARY KEY, vendor TEXT NOT NULL,
    po_number TEXT DEFAULT '', po_date TEXT DEFAULT '',
    inv_number TEXT DEFAULT '', inv_date TEXT DEFAULT '',
    inv_month TEXT DEFAULT '', received_date TEXT DEFAULT '',
    basic_amount REAL DEFAULT 0, gst_amount REAL DEFAULT 0,
    total_amount REAL DEFAULT 0, credit_note_num TEXT DEFAULT '',
    credit_note_val REAL DEFAULT 0, remarks TEXT DEFAULT '',
    tracker_type TEXT DEFAULT 'po',
    is_new INTEGER DEFAULT 0, is_deleted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);
  // Migrate existing DBs — add tracker_type if missing, then backfill NULLs
  try { run("ALTER TABLE bills ADD COLUMN tracker_type TEXT DEFAULT 'po'"); } catch(e){}
  run("UPDATE bills SET tracker_type = 'po' WHERE tracker_type IS NULL OR tracker_type = ''")
  // Migrate file_path column (disk-based file storage)
  try { run("ALTER TABLE bill_files ADD COLUMN file_path TEXT DEFAULT ''"); } catch(e){}
  // Migrate additional charge columns
  try { run("ALTER TABLE bills ADD COLUMN transport_charges REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN other_charges REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN other_charges_desc TEXT DEFAULT ''"); } catch(e){}
  // Migrate GST breakdown columns (CGST / SGST / IGST)
  try { run("ALTER TABLE bills ADD COLUMN cgst_pct REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN cgst_amt REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN sgst_pct REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN sgst_amt REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN igst_pct REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bills ADD COLUMN igst_amt REAL DEFAULT 0"); } catch(e){}
  // Migrate WO deduction columns
  try { run("ALTER TABLE bill_updates ADD COLUMN retention_money REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN tds_deduction REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN other_deductions REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN dc_number TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN vehicle_number TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN inspection_status TEXT DEFAULT 'Accepted'"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN shortage_flag INTEGER DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN storage_location TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE bill_updates ADD COLUMN received_by TEXT DEFAULT ''"); } catch(e){}

  run(`CREATE TABLE IF NOT EXISTS bill_updates (
    sl TEXT PRIMARY KEY,
    store_handover_date TEXT DEFAULT '', store_recv_date TEXT DEFAULT '',
    store_remarks TEXT DEFAULT '', ho_received_date TEXT DEFAULT '',
    qs_received_date TEXT DEFAULT '', doc_ctrl_remarks TEXT DEFAULT '',
    qs_certified_date TEXT DEFAULT '', qs_gross REAL DEFAULT 0,
    qs_tax REAL DEFAULT 0, qs_total REAL DEFAULT 0,
    advance_recovered REAL DEFAULT 0, credit_note_amt REAL DEFAULT 0,
    retention_money REAL DEFAULT 0, tds_deduction REAL DEFAULT 0,
    other_deductions REAL DEFAULT 0,
    total_deductions REAL DEFAULT 0, certified_net REAL DEFAULT 0,
    payment_cert TEXT DEFAULT '', qs_remarks TEXT DEFAULT '',
    proc_date TEXT DEFAULT '', proc_verify_date TEXT DEFAULT '',
    proc_received_date TEXT DEFAULT '', mgmt_approval_date TEXT DEFAULT '',
    proc_remarks TEXT DEFAULT '', accts_jv_date TEXT DEFAULT '',
    accts_dept1 TEXT DEFAULT '', accts_dept2 TEXT DEFAULT '',
    transfer_status TEXT DEFAULT '', accts_remarks TEXT DEFAULT '',
    transferred INTEGER DEFAULT 0, payment_status TEXT DEFAULT '',
    paid_amount REAL DEFAULT 0, balance_to_pay REAL DEFAULT 0,
    payment_date TEXT DEFAULT '', ai_summary TEXT DEFAULT '',
    ai_warnings TEXT DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS bill_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl TEXT NOT NULL, dept TEXT DEFAULT '',
    action TEXT DEFAULT '',
    ts TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS bill_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl TEXT NOT NULL,
    name TEXT NOT NULL,
    size TEXT DEFAULT '',
    type TEXT DEFAULT '',
    data TEXT NOT NULL,
    uploaded_by TEXT DEFAULT '',
    uploaded_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    trade_name TEXT DEFAULT '',
    contact_person TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    city TEXT DEFAULT '',
    state TEXT DEFAULT '',
    pincode TEXT DEFAULT '',
    gstin TEXT DEFAULT '',
    pan TEXT DEFAULT '',
    trade_license TEXT DEFAULT '',
    msme_reg TEXT DEFAULT '',
    vendor_type TEXT DEFAULT '',
    bank_name TEXT DEFAULT '',
    bank_account TEXT DEFAULT '',
    bank_ifsc TEXT DEFAULT '',
    bank_branch TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);


  // ── PO LIFECYCLE TABLES ──
  run(`CREATE TABLE IF NOT EXISTS purchase_orders (
    po_number TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    po_date TEXT DEFAULT '',
    po_value REAL DEFAULT 0,
    description TEXT DEFAULT '',
    site_code TEXT DEFAULT '',
    tracker_type TEXT DEFAULT 'po',
    status TEXT DEFAULT 'Active',
    approved_by TEXT DEFAULT '',
    approval_date TEXT DEFAULT '',
    amendment_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS po_amendments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT NOT NULL,
    amendment_no INTEGER DEFAULT 1,
    original_value REAL DEFAULT 0,
    revised_value REAL DEFAULT 0,
    reason TEXT DEFAULT '',
    amended_by TEXT DEFAULT '',
    amendment_date TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS grn_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT NOT NULL,
    bill_sl TEXT DEFAULT '',
    grn_date TEXT DEFAULT '',
    grn_value REAL DEFAULT 0,
    received_by TEXT DEFAULT '',
    remarks TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS po_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT NOT NULL,
    sl_no INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    uom TEXT DEFAULT '',
    quantity REAL DEFAULT 0,
    rate REAL DEFAULT 0,
    amount REAL DEFAULT 0,
    gst_pct REAL DEFAULT 18,
    gst_amt REAL DEFAULT 0,
    total_amt REAL DEFAULT 0,
    heads TEXT DEFAULT ''
  )`);
  try { run("ALTER TABLE po_items ADD COLUMN gst_pct REAL DEFAULT 18"); } catch(e){}
  try { run("ALTER TABLE po_items ADD COLUMN gst_amt REAL DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE po_items ADD COLUMN total_amt REAL DEFAULT 0"); } catch(e){}

  // Migrate: add new company settings columns (safe - already key/value store)
  // Ensure po_items exists on upgrade
  try { run("ALTER TABLE purchase_orders ADD COLUMN po_req_no TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN po_req_date TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN approval_no TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN delivery_address TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN delivery_contact TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN narration TEXT DEFAULT ''"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN form_no TEXT DEFAULT 'PUR-F-01'"); } catch(e){}


  // ── INVENTORY & INDENT TABLES ──────────────────────────────────────────────
  run(`CREATE TABLE IF NOT EXISTS stock_items (
    item_code TEXT PRIMARY KEY,
    item_name TEXT NOT NULL,
    category TEXT DEFAULT '',
    unit TEXT DEFAULT '',
    reorder_qty REAL DEFAULT 0,
    min_stock REAL DEFAULT 0,
    current_qty REAL DEFAULT 0,
    current_value REAL DEFAULT 0,
    last_rate REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS material_indents (
    indent_no TEXT PRIMARY KEY,
    raised_by TEXT DEFAULT '',
    raised_date TEXT DEFAULT (date('now','localtime')),
    site_code TEXT DEFAULT '',
    purpose TEXT DEFAULT '',
    required_date TEXT DEFAULT '',
    status TEXT DEFAULT 'Pending Stores',
    stores_checked_by TEXT DEFAULT '',
    stores_checked_date TEXT DEFAULT '',
    stores_remarks TEXT DEFAULT '',
    qs_approved_by TEXT DEFAULT '',
    qs_approved_date TEXT DEFAULT '',
    qs_remarks TEXT DEFAULT '',
    pm_approved_by TEXT DEFAULT '',
    pm_approved_date TEXT DEFAULT '',
    pm_remarks TEXT DEFAULT '',
    md_approved_by TEXT DEFAULT '',
    md_approved_date TEXT DEFAULT '',
    md_remarks TEXT DEFAULT '',
    po_number TEXT DEFAULT '',
    closed_date TEXT DEFAULT '',
    tracker_type TEXT DEFAULT 'po',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  run(`CREATE TABLE IF NOT EXISTS indent_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indent_no TEXT NOT NULL,
    item_code TEXT NOT NULL,
    item_name TEXT DEFAULT '',
    unit TEXT DEFAULT '',
    qty_requested REAL DEFAULT 0,
    qty_approved REAL DEFAULT 0,
    qty_issued REAL DEFAULT 0,
    qty_ordered REAL DEFAULT 0,
    est_rate REAL DEFAULT 0,
    est_value REAL DEFAULT 0,
    remarks TEXT DEFAULT ''
  )`);

  run(`CREATE TABLE IF NOT EXISTS stock_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_code TEXT NOT NULL,
    txn_date TEXT DEFAULT (date('now','localtime')),
    txn_type TEXT DEFAULT '',
    ref_type TEXT DEFAULT '',
    ref_id TEXT DEFAULT '',
    indent_no TEXT DEFAULT '',
    bill_sl TEXT DEFAULT '',
    qty_in REAL DEFAULT 0,
    qty_out REAL DEFAULT 0,
    rate REAL DEFAULT 0,
    value_in REAL DEFAULT 0,
    value_out REAL DEFAULT 0,
    balance_qty REAL DEFAULT 0,
    balance_value REAL DEFAULT 0,
    narration TEXT DEFAULT '',
    recorded_by TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  // ── PROJECTS TABLE ──
  run(`CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    color TEXT DEFAULT '#2563eb',
    icon TEXT DEFAULT '🏗️',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  // Seed default projects if none exist
  const projCount = query('SELECT COUNT(*) as c FROM projects')[0].c;
  if (!projCount) {
    run(`INSERT INTO projects (name, code, color, icon) VALUES ('Godrej-Ascend', 'GODREJ', '#2563eb', '🏗️')`);
    run(`INSERT INTO projects (name, code, color, icon) VALUES ('TQS-Bengaluru', 'TQS-BLR', '#059669', '🏢')`);
    console.log('[Projects] Seeded 2 default projects');
  }

  // Rename legacy placeholder projects to actual project names (one-time migration)
  try {
    run(`UPDATE projects SET name='Godrej-Ascend', code='GODREJ' WHERE code='PROJ-A'`);
    run(`UPDATE projects SET name='TQS-Bengaluru', code='TQS-BLR' WHERE code='PROJ-B'`);
    run(`UPDATE projects SET is_active=0 WHERE code='PROJ-C'`);
  } catch(e) {}

  // Migrate project_id into main data tables
  try { run("ALTER TABLE bills ADD COLUMN project_id INTEGER DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE purchase_orders ADD COLUMN project_id INTEGER DEFAULT 0"); } catch(e){}
  try { run("ALTER TABLE material_indents ADD COLUMN project_id INTEGER DEFAULT 0"); } catch(e){}

  // Assign all existing unassigned data (project_id=0) to TQS-Bengaluru
  const tqsProj = query(`SELECT id FROM projects WHERE code='TQS-BLR' LIMIT 1`);
  if (tqsProj.length) {
    const tqsId = tqsProj[0].id;
    run(`UPDATE bills SET project_id=? WHERE project_id=0 OR project_id IS NULL`, [tqsId]);
    run(`UPDATE purchase_orders SET project_id=? WHERE project_id=0 OR project_id IS NULL`, [tqsId]);
    run(`UPDATE material_indents SET project_id=? WHERE project_id=0 OR project_id IS NULL`, [tqsId]);
    console.log(`[Migration] Assigned existing data to TQS-Bengaluru (id=${tqsId})`);
  }

  // ── USER-PROJECTS JUNCTION TABLE ──
  run(`CREATE TABLE IF NOT EXISTS user_projects (
    user_id    INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, project_id)
  )`);

  // Assign all existing users to TQS-Bengaluru by default (if not yet assigned)
  const tqsRow = query(`SELECT id FROM projects WHERE code='TQS-BLR' LIMIT 1`);
  if (tqsRow.length) {
    const tqsId = tqsRow[0].id;
    const allUsers = query('SELECT id FROM users');
    allUsers.forEach(u => {
      run('INSERT OR IGNORE INTO user_projects (user_id, project_id) VALUES (?,?)', [u.id, tqsId]);
    });
  }

  // ── USERS TABLE ──
  run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT DEFAULT '',
    dept TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  // Seed one default account per department if none exist yet
  const userCount = query('SELECT COUNT(*) as c FROM users')[0].c;
  if (!userCount) {
    const defaultPass = 'TQS@1234';
    const defaultUsers = [
      { email: 'stores@tqs.local',      name: 'Stores User',      dept: 'stores' },
      { email: 'docctrl@tqs.local',     name: 'Doc Controller',   dept: 'doc_ctrl' },
      { email: 'qs@tqs.local',          name: 'Qty Surveyor',     dept: 'qs' },
      { email: 'procurement@tqs.local', name: 'Procurement User', dept: 'procurement' },
      { email: 'accounts@tqs.local',    name: 'Accounts User',    dept: 'accounts' },
      { email: 'admin@tqs.local',       name: 'Administrator',    dept: 'admin' },
    ];
    defaultUsers.forEach(u => {
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(defaultPass, salt);
      run(`INSERT INTO users (email, name, dept, password_hash, salt) VALUES (?,?,?,?,?)`,
        [u.email, u.name, u.dept, hash, salt]);
    });
    console.log('[Auth] Seeded 6 default user accounts (password: TQS@1234)');
  }

  saveDb();
  console.log('Tables ready');

  // Load persisted sessions after DB is ready
  loadSessions();
}

// ── AUTH ENDPOINTS ──

// ── BRUTE FORCE PROTECTION ──
const loginAttempts = new Map(); // email → { count, lockedUntil, lastAttempt }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_RESET_MS    = 60 * 60 * 1000; // Reset after 1 hour of inactivity

function checkLoginAttempts(email) {
  const now = Date.now();
  const attempt = loginAttempts.get(email);
  if (!attempt) return { allowed: true };
  if (attempt.lockedUntil && attempt.lockedUntil > now) {
    const remainingSeconds = Math.ceil((attempt.lockedUntil - now) / 1000);
    return { allowed: false, locked: true, message: `Account temporarily locked. Try again in ${remainingSeconds}s` };
  }
  if (now - attempt.lastAttempt > ATTEMPT_RESET_MS) { loginAttempts.delete(email); return { allowed: true }; }
  return { allowed: true };
}

function recordFailedLogin(email) {
  const now = Date.now();
  const attempt = loginAttempts.get(email) || { count: 0, lockedUntil: null, lastAttempt: now };
  attempt.count++;
  attempt.lastAttempt = now;
  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.lockedUntil = now + LOCKOUT_DURATION_MS;
    console.warn(`[Security] Account ${email} locked after ${attempt.count} failed attempts`);
  }
  loginAttempts.set(email, attempt);
}

function clearLoginAttempts(email) { loginAttempts.delete(email); }

// Clean up old login attempt records every 30 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [email, attempt] of loginAttempts) {
    if (now - attempt.lastAttempt > ATTEMPT_RESET_MS) { loginAttempts.delete(email); cleaned++; }
  }
  if (cleaned > 0) console.log(`[Security] Cleaned up ${cleaned} old login attempt records`);
}, 30 * 60 * 1000);

// POST /api/auth/login — verify email + password + project, return session token
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password, project_id } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }
    const emailLower = email.trim().toLowerCase();
    // Validate email format (simple check — avoid complex regex to prevent ReDoS)
    if (emailLower.length > 254 || !emailLower.includes('@') || emailLower.indexOf('@') === 0 || emailLower.endsWith('@')) {
      return res.status(400).json({ ok: false, error: 'Invalid email format' });
    }
    if (!project_id) {
      return res.status(400).json({ ok: false, error: 'Please select a project to continue' });
    }
    // Check brute force protection
    const attemptCheck = checkLoginAttempts(emailLower);
    if (!attemptCheck.allowed) {
      return res.status(429).json({ ok: false, error: attemptCheck.message });
    }
    const projectRows = query('SELECT * FROM projects WHERE id=? AND is_active=1', [project_id]);
    if (!projectRows.length) {
      return res.status(400).json({ ok: false, error: 'Invalid or inactive project' });
    }
    const project = projectRows[0];
    const rows = query('SELECT * FROM users WHERE LOWER(email)=LOWER(?) AND is_active=1', [emailLower]);
    if (!rows.length || !verifyPassword(password, rows[0].salt, rows[0].password_hash)) {
      recordFailedLogin(emailLower);
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }
    const user = rows[0];
    // Check project access (admin can access all projects)
    if (user.dept !== 'admin') {
      const access = query('SELECT 1 FROM user_projects WHERE user_id=? AND project_id=?', [user.id, project.id]);
      if (!access.length) {
        recordFailedLogin(emailLower);
        return res.status(403).json({ ok: false, error: `You don't have access to ${project.name}` });
      }
    }
    // Login successful — clear failed attempts
    clearLoginAttempts(emailLower);
    const token = generateToken();
    sessions.set(token, {
      dept: user.dept, userId: user.id, name: user.name, email: user.email,
      projectId: project.id, projectName: project.name,
      expiresAt: Date.now() + SESSION_TTL_MS,
      createdAt: Date.now()
    });
    saveSessions(); // Persist immediately after successful login
    console.log(`[Auth] User ${emailLower} logged in (project: ${project.name})`);
    res.json({ ok: true, token, dept: user.dept, name: user.name, email: user.email, userId: user.id,
               projectId: project.id, projectName: project.name });
  } catch (err) {
    console.error('[Login error]', err.message);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// POST /api/auth/logout — invalidate session token
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// GET /api/auth/me — validate token and return current user info
app.get('/api/auth/me', (req, res) => {
  const token = req.headers['x-auth-token'];
  const session = token ? sessions.get(token) : null;
  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(token);
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  res.json({ ok: true, dept: session.dept, name: session.name, email: session.email, userId: session.userId,
             projectId: session.projectId || 0, projectName: session.projectName || '' });
});

// ── PROJECT ENDPOINTS ──

// GET /api/projects — public, used on login page
app.get('/api/projects', (req, res) => {
  try {
    const projects = query('SELECT id, name, code, color, icon FROM projects WHERE is_active=1 ORDER BY id');
    res.json({ ok: true, projects });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// POST /api/projects — admin only, create project
app.post('/api/projects', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  try {
    const { name, code, color, icon } = req.body;
    if (!name || !code) return res.status(400).json({ ok: false, error: 'name and code required' });
    const exists = query('SELECT id FROM projects WHERE LOWER(code)=LOWER(?)', [code]);
    if (exists.length) return res.status(409).json({ ok: false, error: 'Project code already exists' });
    run(`INSERT INTO projects (name, code, color, icon) VALUES (?,?,?,?)`,
      [name, code, color||'#2563eb', icon||'🏗️']);
    saveDb();
    const proj = query('SELECT * FROM projects WHERE LOWER(code)=LOWER(?)', [code])[0];
    res.json({ ok: true, project: proj });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// PATCH /api/projects/:id — admin only, update project
app.patch('/api/projects/:id', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  try {
    const { name, color, icon, is_active } = req.body;
    const fields = [], vals = [];
    if (name      !== undefined) { fields.push('name=?');      vals.push(name); }
    if (color     !== undefined) { fields.push('color=?');     vals.push(color); }
    if (icon      !== undefined) { fields.push('icon=?');      vals.push(icon); }
    if (is_active !== undefined) { fields.push('is_active=?'); vals.push(is_active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ ok: false, error: 'No fields to update' });
    vals.push(req.params.id);
    run(`UPDATE projects SET ${fields.join(',')} WHERE id=?`, vals);
    saveDb();
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ── USER MANAGEMENT ENDPOINTS (admin only) ──

// GET /api/users
app.get('/api/users', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  const users = query('SELECT id,email,name,dept,is_active,created_at FROM users ORDER BY dept,name');
  users.forEach(u => {
    const projs = query('SELECT project_id FROM user_projects WHERE user_id=?', [u.id]);
    u.project_ids = projs.map(p => p.project_id);
  });
  res.json({ ok: true, users });
});

// POST /api/users
app.post('/api/users', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  const { email, name, dept, password, project_ids } = req.body || {};
  if (!email || !name || !dept || !password) {
    return res.status(400).json({ ok: false, error: 'email, name, dept, and password are required' });
  }
  const validDepts = ['stores','doc_ctrl','qs','procurement','accounts','admin'];
  if (!validDepts.includes(dept)) return res.status(400).json({ ok: false, error: 'Invalid department' });
  const existing = query('SELECT id FROM users WHERE LOWER(email)=LOWER(?)', [email.trim()]);
  if (existing.length) return res.status(409).json({ ok: false, error: 'Email already in use' });
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  run(`INSERT INTO users (email,name,dept,password_hash,salt) VALUES (?,?,?,?,?)`,
    [email.trim().toLowerCase(), name.trim(), dept, hash, salt]);
  const id = query('SELECT last_insert_rowid() as id')[0].id;
  if (Array.isArray(project_ids)) {
    project_ids.forEach(pid => {
      run('INSERT OR IGNORE INTO user_projects (user_id, project_id) VALUES (?,?)', [id, pid]);
    });
  }
  saveDb();
  res.json({ ok: true, id });
});

// PUT /api/users/:id — partial update (only fields present in body are changed)
app.put('/api/users/:id', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  const { name, dept, password, is_active, project_ids } = req.body || {};
  const { id } = req.params;
  const sets = [], params = [];
  if (name !== undefined)      { sets.push('name=?');      params.push(name || ''); }
  if (dept !== undefined)      { sets.push('dept=?');      params.push(dept || ''); }
  if (is_active !== undefined) { sets.push('is_active=?'); params.push(is_active ? 1 : 0); }
  if (password && password.trim()) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    sets.push('password_hash=?'); params.push(hash);
    sets.push('salt=?');          params.push(salt);
  }
  if (sets.length) {
    sets.push("updated_at=datetime('now','localtime')");
    params.push(id);
    run(`UPDATE users SET ${sets.join(',')} WHERE id=?`, params);
  }
  if (Array.isArray(project_ids)) {
    run('DELETE FROM user_projects WHERE user_id=?', [id]);
    project_ids.forEach(pid => {
      run('INSERT OR IGNORE INTO user_projects (user_id, project_id) VALUES (?,?)', [id, pid]);
    });
  }
  saveDb();
  res.json({ ok: true });
});

// DELETE /api/users/:id — soft-delete
app.delete('/api/users/:id', (req, res) => {
  if (req.dept !== 'admin') return res.status(403).json({ ok: false, error: 'Admin only' });
  run(`UPDATE users SET is_active=0,updated_at=datetime('now','localtime') WHERE id=?`, [req.params.id]);
  saveDb();
  res.json({ ok: true });
});

// ── VENDOR ENDPOINTS ──

// GET /api/vendors
app.get('/api/vendors', (req, res) => {
  try {
    const vendors = query('SELECT * FROM vendors WHERE is_active=1 ORDER BY name ASC');
    res.json({ ok: true, vendors });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// POST /api/vendors — create
app.post('/api/vendors', (req, res) => {
  try {
    const d = req.body;
    if (!d.name || !d.name.trim()) return res.status(400).json({ ok: false, error: 'Vendor name required' });
    const existing = query('SELECT id FROM vendors WHERE LOWER(name)=LOWER(?)', [d.name.trim()]);
    if (existing.length) return res.status(409).json({ ok: false, error: 'Vendor already exists: ' + d.name.trim() });
    run(`INSERT INTO vendors (name,trade_name,contact_person,phone,email,address,city,state,pincode,
         gstin,pan,trade_license,msme_reg,vendor_type,bank_name,bank_account,bank_ifsc,bank_branch,notes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [d.name.trim(),d.trade_name||'',d.contact_person||'',d.phone||'',d.email||'',
       d.address||'',d.city||'',d.state||'',d.pincode||'',
       d.gstin||'',d.pan||'',d.trade_license||'',d.msme_reg||'',d.vendor_type||'',
       d.bank_name||'',d.bank_account||'',d.bank_ifsc||'',d.bank_branch||'',d.notes||'']);
    const id = query('SELECT last_insert_rowid() as id')[0].id;
    saveDb();
    res.json({ ok: true, id });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// PUT /api/vendors/:id — update
app.put('/api/vendors/:id', (req, res) => {
  try {
    const d = req.body;
    const { id } = req.params;
    if (!d.name || !d.name.trim()) return res.status(400).json({ ok: false, error: 'Vendor name required' });
    const dup = query('SELECT id FROM vendors WHERE LOWER(name)=LOWER(?) AND id!=?', [d.name.trim(), id]);
    if (dup.length) return res.status(409).json({ ok: false, error: 'Another vendor with this name already exists' });
    run(`UPDATE vendors SET name=?,trade_name=?,contact_person=?,phone=?,email=?,address=?,city=?,state=?,
         pincode=?,gstin=?,pan=?,trade_license=?,msme_reg=?,vendor_type=?,bank_name=?,bank_account=?,
         bank_ifsc=?,bank_branch=?,notes=?,updated_at=datetime('now','localtime') WHERE id=?`,
      [d.name.trim(),d.trade_name||'',d.contact_person||'',d.phone||'',d.email||'',
       d.address||'',d.city||'',d.state||'',d.pincode||'',
       d.gstin||'',d.pan||'',d.trade_license||'',d.msme_reg||'',d.vendor_type||'',
       d.bank_name||'',d.bank_account||'',d.bank_ifsc||'',d.bank_branch||'',d.notes||'',id]);
    saveDb();
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// DELETE /api/vendors/:id — soft delete
app.delete('/api/vendors/:id', (req, res) => {
  try {
    run('UPDATE vendors SET is_active=0 WHERE id=?', [req.params.id]);
    saveDb();
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ── APP SETTINGS ENDPOINTS ──

// GET /api/settings — returns all settings as flat object
app.get('/api/settings', (req, res) => {
  try {
    const rows = query('SELECT key, value FROM app_settings');
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json({ ok: true, settings });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PUT /api/settings — upsert one or many key/value pairs
app.put('/api/settings', (req, res) => {
  try {
    const updates = req.body; // { key: value, ... }
    if (!updates || typeof updates !== 'object') {
      return res.status(400).json({ ok: false, error: 'Invalid body' });
    }
    for (const [key, value] of Object.entries(updates)) {
      run(
        `INSERT INTO app_settings (key, value, updated_at)
         VALUES (?, ?, datetime('now','localtime'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
        [key, value == null ? '' : String(value)]
      );
    }
    saveDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({ ok: true, bills: query('SELECT COUNT(*) as c FROM bills WHERE is_deleted=0')[0].c });
});

// GET /api/bills
app.get('/api/bills', (req, res) => {
  try {
    const trackerType = (req.query.type === 'wo') ? 'wo' : (req.query.type === 'po') ? 'po' : null;
    // Fix #11: Pagination — default 50, max 500
    const limit  = Math.min(parseInt(req.query.limit, 10) || 50, 500);
    const page   = Math.max(parseInt(req.query.page, 10)  || 1, 1);
    const offset = (page - 1) * limit;
    const qParams = [req.projectId || 0];
    let typeFilter = '';
    if (trackerType) { typeFilter = 'AND b.tracker_type = ?'; qParams.push(trackerType); }
    const totalRow = query(
      `SELECT COUNT(*) as cnt FROM bills b WHERE b.is_deleted=0 AND b.project_id=? ${typeFilter}`,
      qParams
    );
    const total = totalRow[0]?.cnt || 0;
    const bills = query(`
      SELECT b.*, u.store_handover_date, u.store_recv_date, u.store_remarks, u.dc_number, u.vehicle_number, u.inspection_status, u.shortage_flag, u.storage_location, u.received_by,
        u.ho_received_date, u.qs_received_date, u.doc_ctrl_remarks,
        u.qs_certified_date, u.qs_gross, u.qs_tax, u.qs_total,
        u.advance_recovered, u.credit_note_amt,
        u.retention_money, u.tds_deduction, u.other_deductions,
        u.total_deductions,
        u.certified_net, u.payment_cert, u.qs_remarks,
        u.proc_date, u.proc_verify_date, u.proc_received_date,
        u.mgmt_approval_date, u.proc_remarks, u.accts_jv_date,
        u.accts_dept1, u.accts_dept2, u.transfer_status, u.accts_remarks,
        u.transferred, u.payment_status, u.paid_amount,
        u.balance_to_pay, u.payment_date, u.ai_summary, u.ai_warnings
      FROM bills b
      LEFT JOIN bill_updates u ON b.sl = u.sl
      WHERE b.is_deleted = 0 AND b.project_id = ? ${typeFilter}
      ORDER BY CAST(b.sl AS REAL) ASC
      LIMIT ? OFFSET ?
    `, [...qParams, limit, offset]);
    bills.forEach(b => {
      b._hist = query('SELECT dept,action,ts FROM bill_history WHERE sl=? ORDER BY ts DESC LIMIT 20', [b.sl]);
      b._files = query('SELECT id,name,size,type,uploaded_by,uploaded_at FROM bill_files WHERE sl=? ORDER BY uploaded_at ASC', [b.sl]);
      b.transferred = !!b.transferred;
      b.is_new = !!b.is_new;
      // Derive inv_month from inv_date — handle both YYYY-MM-DD and DD-MM-YYYY
      if (b.inv_date && b.inv_date.length >= 7) {
        if (b.inv_date.charAt(4) === '-') {
          b.inv_month = b.inv_date.slice(0, 7); // YYYY-MM-DD → YYYY-MM
        } else if (b.inv_date.charAt(2) === '-') {
          const pts = b.inv_date.split('-');     // DD-MM-YYYY → YYYY-MM
          if (pts.length === 3 && pts[2].length === 4) b.inv_month = pts[2] + '-' + pts[1];
        }
      }
    });
    res.json({ ok: true, bills, pagination: { total, page, limit, pages: Math.ceil(total / limit) } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Fix #7: Thread-safe SL generation — in-memory lock (Node.js is single-threaded but async I/O can cause races)
let slGenerationLock = false;

// POST /api/bills
app.post('/api/bills', (req, res) => {
  try {
    const d = req.body;
    if (!d.vendor) return res.status(400).json({ ok: false, error: 'vendor required' });

    // Fix #10: Input validation — amount bounds checking
    const basicAmt = parseFloat(d.basic_amount) || 0;
    const gstAmt   = parseFloat(d.gst_amount)   || 0;
    const totalAmt = parseFloat(d.total_amount)  || 0;
    if (basicAmt < 0 || gstAmt < 0 || totalAmt < 0) {
      return res.status(400).json({ ok: false, error: 'Amount values cannot be negative' });
    }
    if (basicAmt > 1e10 || gstAmt > 1e10 || totalAmt > 1e10) {
      return res.status(400).json({ ok: false, error: 'Amount values exceed maximum allowed limit' });
    }

    // Duplicate invoice number check — skip if ?force=1
    if (d.inv_number && d.inv_number.trim() && req.query.force !== '1') {
      // Sanitize inputs before DB operation (Fix #1: SQL Injection prevention)
      const invNumber = (d.inv_number || '').trim().toLowerCase();
      const vendorName = (d.vendor || '').trim().toLowerCase();
      const dup = query(
        'SELECT sl FROM bills WHERE LOWER(inv_number)=LOWER(?) AND LOWER(vendor)=LOWER(?) AND is_deleted=0',
        [invNumber, vendorName]
      );
      if (dup.length) {
        return res.status(409).json({
          ok: false,
          duplicate: true,
          existing_sl: dup[0].sl,
          error: `Duplicate: Invoice "${d.inv_number}" from "${d.vendor}" already exists as SL#${dup[0].sl}`
        });
      }
    }

    // Fix #7: Thread-safe SL generation
    if (slGenerationLock) {
      return res.status(503).json({ ok: false, error: 'Server busy, please retry' });
    }
    slGenerationLock = true;
    let sl;
    try {
      const maxRow = query('SELECT MAX(CAST(sl AS REAL)) as m FROM bills');
      sl = String(Math.floor((maxRow[0].m || 0)) + 1);
      const ttype = d.tracker_type === 'wo' ? 'wo' : 'po';
      run(`INSERT INTO bills (sl,vendor,po_number,po_date,inv_number,inv_date,inv_month,
           received_date,basic_amount,gst_amount,total_amount,credit_note_num,credit_note_val,remarks,tracker_type,project_id,is_new)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)`,
        [sl,d.vendor,d.po_number||'',d.po_date||'',d.inv_number||'',
         d.inv_date||'',d.inv_month||'',d.received_date||'',
         basicAmt,gstAmt,totalAmt,
         d.credit_note_num||'',parseFloat(d.credit_note_val)||0,d.remarks||'',ttype,
         req.projectId||0]);
    } finally {
      slGenerationLock = false;
    }
    run('INSERT OR IGNORE INTO bill_updates (sl) VALUES (?)', [sl]);
    if (d.dept) run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl,d.dept,'New bill added']);
    const saveResult = saveDb();
    if (!saveResult.success) return res.status(500).json({ ok: false, error: saveResult.error });
    console.log(`[Bills] Created SL#${sl} for vendor: ${String(d.vendor).substring(0, 50)}`);
    res.json({ ok: true, sl });
  } catch (err) {
    console.error('[POST /api/bills error]', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/bills/bulk-update — update same fields across multiple SLs at once
app.post('/api/bills/bulk-update', (req, res) => {
  try {
    const { sls, updates, dept, action } = req.body;
    if (!Array.isArray(sls) || !sls.length) return res.status(400).json({ ok: false, error: 'sls array required' });

    const allowed = [
      'store_handover_date','store_recv_date','ho_received_date','qs_received_date','dc_number','vehicle_number','inspection_status','shortage_flag','storage_location','received_by',
      'qs_certified_date','qs_gross','qs_tax','qs_total','advance_recovered',
      'retention_money','tds_deduction','other_deductions',
      'certified_net','payment_cert','proc_date','proc_received_date',
      'mgmt_approval_date','accts_jv_date','accts_dept1','transfer_status',
      'transferred','payment_status','paid_amount','balance_to_pay','payment_date'
    ];
    const fields = Object.keys(updates || {}).filter(k => allowed.includes(k));
    if (!fields.length) return res.status(400).json({ ok: false, error: 'No valid fields to update' });

    let updated = 0;
    for (const sl of sls) {
      const exists = query('SELECT sl FROM bills WHERE sl=? AND is_deleted=0', [sl]);
      if (!exists.length) continue;
      run('INSERT OR IGNORE INTO bill_updates (sl) VALUES (?)', [sl]);
      const vals = fields.map(f => updates[f]);
      vals.push(sl);
      run(`UPDATE bill_updates SET ${fields.map(f => f+'=?').join(',')} WHERE sl=?`, vals);
      run(`UPDATE bills SET updated_at=datetime('now','localtime') WHERE sl=?`, [sl]);
      if (dept) run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl, dept, action||'Bulk updated']);
      updated++;
    }
    saveDb();
    res.json({ ok: true, updated });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/bills/bulk
app.post('/api/bills/bulk', (req, res) => {
  try {
    const { bills, dept } = req.body;
    if (!Array.isArray(bills)) return res.status(400).json({ ok: false, error: 'bills array required' });

    // Fix #12: Bulk Import Validation — detect duplicates within batch AND against existing data
    const batchKeys = new Set();
    const skipped = [];
    const validBills = [];
    for (const d of bills) {
      if (!d.vendor || !d.vendor.trim()) { skipped.push({ reason: 'Missing vendor', data: d }); continue; }
      if (d.inv_number && d.inv_number.trim()) {
        const batchKey = `${(d.inv_number||'').trim().toLowerCase()}|${(d.vendor||'').trim().toLowerCase()}`;
        if (batchKeys.has(batchKey)) {
          skipped.push({ reason: `Duplicate within batch: inv_number="${d.inv_number}"`, data: d });
          continue;
        }
        // Check against existing DB data
        const existing = query(
          'SELECT sl FROM bills WHERE LOWER(inv_number)=LOWER(?) AND LOWER(vendor)=LOWER(?) AND is_deleted=0',
          [(d.inv_number||'').trim(), (d.vendor||'').trim()]
        );
        if (existing.length) {
          skipped.push({ reason: `Duplicate in DB: inv_number="${d.inv_number}" already exists as SL#${existing[0].sl}`, data: d });
          continue;
        }
        batchKeys.add(batchKey);
      }
      validBills.push(d);
    }

    const maxRow = query('SELECT MAX(CAST(sl AS REAL)) as m FROM bills');
    let nextSL = Math.floor((maxRow[0].m || 0)) + 1;
    let count = 0;
    for (const d of validBills) {
      const sl = String(nextSL++);
      const ttype = d.tracker_type === 'wo' ? 'wo' : 'po';
      // Core bill
      run(`INSERT OR IGNORE INTO bills (sl,vendor,po_number,po_date,inv_number,inv_date,
           inv_month,received_date,basic_amount,gst_amount,total_amount,
           credit_note_num,credit_note_val,remarks,tracker_type,is_new)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)`,
        [sl, d.vendor||'', d.po_number||'', d.po_date||'', d.inv_number||'',
         d.inv_date||'', d.inv_month||'', d.received_date||'',
         parseFloat(d.basic_amount)||0, parseFloat(d.gst_amount)||0,
         parseFloat(d.total_amount)||0, d.credit_note_num||'',
         parseFloat(d.credit_note_val)||0, d.remarks||'', ttype]);
      // All dept update columns
      run(`INSERT OR IGNORE INTO bill_updates
           (sl,store_handover_date,store_recv_date,store_remarks,
            ho_received_date,qs_received_date,doc_ctrl_remarks,
            qs_certified_date,qs_gross,qs_tax,qs_total,
            advance_recovered,credit_note_amt,
            retention_money,tds_deduction,other_deductions,
            total_deductions,
            certified_net,payment_cert,qs_remarks,
            proc_date,proc_verify_date,proc_received_date,
            mgmt_approval_date,proc_remarks,
            accts_jv_date,accts_dept1,transfer_status,
            transferred,accts_remarks,
            payment_status,paid_amount,balance_to_pay,payment_date)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [sl,
         d.store_handover_date||'', d.store_recv_date||'', d.store_remarks||'',
         d.ho_received_date||'', d.qs_received_date||'', d.doc_ctrl_remarks||'',
         d.qs_certified_date||'',
         parseFloat(d.qs_gross)||0, parseFloat(d.qs_tax)||0, parseFloat(d.qs_total)||0,
         parseFloat(d.advance_recovered)||0, parseFloat(d.credit_note_amt)||0,
         parseFloat(d.retention_money)||0, parseFloat(d.tds_deduction)||0,
         parseFloat(d.other_deductions)||0,
         parseFloat(d.total_deductions)||0, parseFloat(d.certified_net)||0,
         d.payment_cert||'', d.qs_remarks||'',
         d.proc_date||'', d.proc_verify_date||'', d.proc_received_date||'',
         d.mgmt_approval_date||'', d.proc_remarks||'',
         d.accts_jv_date||'', d.accts_dept1||'', d.transfer_status||'',
         d.transferred ? 1 : 0, d.accts_remarks||'',
         d.payment_status||'', parseFloat(d.paid_amount)||0,
         parseFloat(d.balance_to_pay)||0, d.payment_date||'']);
      if (dept) run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl, dept, 'Imported']);
      count++;
    }
    saveDb();
    res.json({ ok: true, imported: count, skipped: skipped.length, skipped_details: skipped });
  } catch (err) {
    console.error('bulk import:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PATCH /api/bills/:sl
app.patch('/api/bills/:sl', (req, res) => {
  try {
    const { sl } = req.params;
    const { updates, dept, action } = req.body;
    const exists = query('SELECT sl FROM bills WHERE sl=?', [sl]);
    if (!exists.length) return res.status(404).json({ ok: false, error: 'Not found' });

    // Build field-level change log
    const currentBill = query('SELECT * FROM bills WHERE sl=?', [sl])[0] || {};
    const currentUpdates = query('SELECT * FROM bill_updates WHERE sl=?', [sl])[0] || {};
    const currentMerged = { ...currentBill, ...currentUpdates };
    const changedFields = [];

    // Core bill fields (bills table) — admin only
    const coreFields = [
      'vendor','po_number','po_date','inv_number','inv_date','inv_month',
      'received_date','basic_amount','gst_amount','total_amount',
      'credit_note_num','credit_note_val','remarks','tracker_type'
    ];
    const coreToSave = Object.keys(updates || {}).filter(k => coreFields.includes(k));
    if (coreToSave.length > 0) {
      coreToSave.forEach(f => {
        const oldVal = String(currentMerged[f] || '');
        const newVal = String(updates[f] || '');
        if (oldVal !== newVal) changedFields.push(`${f}: "${oldVal}" → "${newVal}"`);
      });
      const vals = coreToSave.map(f => {
        const v = updates[f];
        if (['basic_amount','gst_amount','total_amount','credit_note_val'].includes(f)) return parseFloat(v)||0;
        return v||'';
      });
      vals.push(sl);
      run(`UPDATE bills SET ${coreToSave.map(f => f+'=?').join(',')}, updated_at=datetime('now','localtime') WHERE sl=?`, vals);
    }

    // Dept update fields (bill_updates table)
    run('INSERT OR IGNORE INTO bill_updates (sl) VALUES (?)', [sl]);
    const allowed = [
      'store_handover_date','store_recv_date','store_remarks',
      'ho_received_date','qs_received_date','doc_ctrl_remarks',
      'qs_certified_date','qs_gross','qs_tax','qs_total',
      'advance_recovered','credit_note_amt',
      'retention_money','tds_deduction','other_deductions',
      'total_deductions',
      'certified_net','payment_cert','qs_remarks',
      'proc_date','proc_verify_date','proc_received_date',
      'mgmt_approval_date','proc_remarks','accts_jv_date',
      'accts_dept1','accts_dept2','transfer_status','accts_remarks',
      'transferred','payment_status','paid_amount','balance_to_pay','payment_date'
    ];
    const fields = Object.keys(updates || {}).filter(k => allowed.includes(k));
    if (fields.length > 0) {
      fields.forEach(f => {
        const oldVal = String(currentMerged[f] || '');
        const newVal = String(updates[f] || '');
        if (oldVal !== newVal) changedFields.push(`${f}: "${oldVal}" → "${newVal}"`);
      });
      const vals = fields.map(f => updates[f]);
      vals.push(sl);
      run(`UPDATE bill_updates SET ${fields.map(f => f+'=?').join(',')} WHERE sl=?`, vals);
    }

    if (coreToSave.length === 0) {
      run(`UPDATE bills SET updated_at=datetime('now','localtime') WHERE sl=?`, [sl]);
    }

    // Log with field-level detail when changes detected
    if (dept) {
      const actionText = changedFields.length > 0
        ? `${action||'Updated'} | ${changedFields.slice(0,5).join('; ')}`
        : (action || 'Updated');
      run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl, dept, actionText]);
    }
    saveDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// DELETE /api/bills/:sl
app.delete('/api/bills/:sl', (req, res) => {
  try {
    const { sl } = req.params;
    const { dept } = req.body;
    run(`UPDATE bills SET is_deleted=1, updated_at=datetime('now','localtime') WHERE sl=?`, [sl]);
    if (dept) run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl,dept||'admin','Deleted']);
    saveDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/seed
app.post('/api/seed', (req, res) => {
  try {
    const { bills } = req.body;
    if (!Array.isArray(bills)) return res.status(400).json({ ok: false, error: 'bills array required' });
    let count = 0;
    for (const d of bills) {
      const sl = String(d.sl);
      run(`INSERT OR IGNORE INTO bills
           (sl,vendor,po_number,po_date,inv_number,inv_date,inv_month,
            received_date,basic_amount,gst_amount,total_amount,
            credit_note_num,credit_note_val,remarks,is_new)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
        [sl,d.vendor||'',d.po_number||'',d.po_date||'',
         d.inv_number||'',d.inv_date||'',d.inv_month||'',
         d.received_date||'',d.basic_amount||0,d.gst_amount||0,
         d.total_amount||0,d.credit_note_num||'',d.credit_note_val||0,d.remarks||'']);
      run(`INSERT OR IGNORE INTO bill_updates
           (sl,store_handover_date,ho_received_date,qs_received_date,
            qs_gross,qs_tax,qs_total,advance_recovered,credit_note_amt,
            retention_money,tds_deduction,other_deductions,
            total_deductions,certified_net,payment_cert,accts_jv_date,
            accts_dept1,proc_date,proc_received_date,mgmt_approval_date,
            transfer_status,transferred,payment_status,paid_amount,
            balance_to_pay,payment_date)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [sl,d.store_handover_date||'',d.ho_received_date||'',d.qs_received_date||'',
         d.qs_gross||0,d.qs_tax||0,d.qs_total||0,d.advance_recovered||0,
         d.credit_note_amt||0,
         d.retention_money||0,d.tds_deduction||0,d.other_deductions||0,
         d.total_deductions||0,d.certified_net||0,
         d.payment_cert||'',d.accts_jv_date||'',d.accts_dept1||'',
         d.proc_date||'',d.proc_received_date||'',d.mgmt_approval_date||'',
         d.transfer_status||'',d.transferred?1:0,d.payment_status||'',
         d.paid_amount||0,d.balance_to_pay||0,d.payment_date||'']);
      count++;
    }
    saveDb();
    res.json({ ok: true, seeded: count });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/clear-all — wipe all data (Admin only — no recovery!)
app.post('/api/clear-all', (req, res) => {
  try {
    const { confirm_text } = req.body;
    // Require exact confirmation phrase as a safety check
    if (confirm_text !== 'DELETE ALL DATA') {
      return res.status(400).json({ ok: false, error: 'Confirmation phrase incorrect' });
    }
    run('DELETE FROM bill_history');
    run('DELETE FROM bill_files');
    run('DELETE FROM bill_updates');
    run('DELETE FROM bills');
    // Reset autoincrement
    run(`DELETE FROM sqlite_sequence WHERE name IN ('bill_history')`);
    saveDb();
    console.log('⚠  All data cleared by admin');
    res.json({ ok: true, message: 'All data deleted' });
  } catch (err) {
    console.error('clear-all:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── FILE UPLOAD VALIDATION ──
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
const ALLOWED_MIME_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];
// Magic bytes for file type verification
const MAGIC_NUMBERS = {
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png':  [0x89, 0x50, 0x4E, 0x47],
  'image/gif':  [0x47, 0x49, 0x46],
};

function validateFileUpload(name, size, type, data) {
  const errors = [];
  if (!name || typeof name !== 'string' || !name.trim()) errors.push('Invalid filename');
  const sizeNum = parseInt(size, 10) || 0;
  if (sizeNum > MAX_FILE_SIZE) errors.push(`File exceeds maximum size of ${MAX_FILE_SIZE / (1024*1024)}MB`);
  if (!type || !ALLOWED_MIME_TYPES.includes(type)) errors.push(`File type not allowed: ${type}`);
  if (!data || typeof data !== 'string') { errors.push('No file data provided'); return { valid: false, errors }; }
  try {
    const base64 = data.includes(',') ? data.split(',')[1] : data;
    if (!base64 || !base64.trim()) { errors.push('File data is empty'); return { valid: false, errors }; }
    const buffer = Buffer.from(base64, 'base64');
    if (buffer.length === 0) errors.push('File buffer is empty');
    if (buffer.length > MAX_FILE_SIZE) errors.push(`Actual file size exceeds ${MAX_FILE_SIZE/(1024*1024)}MB`);
    if (MAGIC_NUMBERS[type]) {
      const expected = MAGIC_NUMBERS[type];
      const matches = expected.every((byte, i) => buffer[i] === byte);
      if (!matches) errors.push(`File content does not match declared type ${type}`);
    }
  } catch (err) { errors.push(`Invalid file data: ${err.message}`); }
  return { valid: errors.length === 0, errors };
}

// POST /api/bills/:sl/files — upload file → saved to disk + metadata in DB
app.post('/api/bills/:sl/files', (req, res) => {
  try {
    const { sl } = req.params;
    const { name, size, type, data, uploaded_by } = req.body;

    // Fix #5: File Upload Validation
    const validation = validateFileUpload(name, size, type, data);
    if (!validation.valid) {
      return res.status(400).json({ ok: false, errors: validation.errors });
    }

    // Verify bill exists
    const billExists = query('SELECT sl FROM bills WHERE sl=? AND is_deleted=0', [sl]);
    if (!billExists.length) return res.status(404).json({ ok: false, error: 'Bill not found' });

    // Ensure uploads directory exists (safety — in case folder was deleted)
    if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

    // Save file to disk: uploads/bills/SL-{sl}/{filename}
    const safeFilename = sanitizeFilename(name);
    const uploadDir    = getBillUploadDir(sl);
    // Add timestamp prefix to avoid collisions
    const diskFilename = `${Date.now()}_${safeFilename}`;
    const filePath     = path.join(uploadDir, diskFilename);

    // Verify the resolved path stays within the upload directory (path injection guard)
    const resolvedPath = path.resolve(filePath);
    const resolvedDir  = path.resolve(uploadDir);
    if (!resolvedPath.startsWith(resolvedDir + path.sep)) {
      return res.status(400).json({ ok: false, error: 'Invalid file path' });
    }

    const base64 = data.includes(',') ? data.split(',')[1] : data;
    const buffer = Buffer.from(base64, 'base64');
    fs.writeFileSync(resolvedPath, buffer);

    // Store metadata in DB (no raw base64 data — just the path)
    run(`INSERT INTO bill_files (sl,name,size,type,data,file_path,uploaded_by) VALUES (?,?,?,?,?,?,?)`,
      [sl, name, buffer.length, type||'', '', resolvedPath, uploaded_by||'']);
    const id = query('SELECT last_insert_rowid() as id')[0].id;
    saveDb();

    const sizeKB = Math.round(buffer.length / 1024);
    console.log(`[Upload] SL#${sl} → ${diskFilename} (${sizeKB}KB) by ${uploaded_by||'unknown'}`);
    res.json({ ok: true, id, file_path: resolvedPath, size: buffer.length, filename: diskFilename });
  } catch (err) {
    console.error('file upload:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/bills/:sl/files/:id — download / view file
app.get('/api/bills/:sl/files/:id', (req, res) => {
  try {
    const rows = query('SELECT * FROM bill_files WHERE id=? AND sl=?', [req.params.id, req.params.sl]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'File not found' });
    const f = rows[0];

    // Prefer disk file
    if (f.file_path && fs.existsSync(f.file_path)) {
      const inline = ['image/jpeg','image/png','image/gif','image/webp','application/pdf'].includes(f.type);
      res.setHeader('Content-Type', f.type || 'application/octet-stream');
      res.setHeader('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename="${f.name}"`);
      return res.sendFile(f.file_path);
    }

    // Fallback: legacy base64 from DB
    if (f.data) {
      const base64 = f.data.includes(',') ? f.data.split(',')[1] : f.data;
      const buf = Buffer.from(base64, 'base64');
      res.setHeader('Content-Disposition', `attachment; filename="${f.name}"`);
      res.setHeader('Content-Type', f.type || 'application/octet-stream');
      return res.send(buf);
    }

    res.status(404).json({ ok: false, error: 'File data not found' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/bills/:sl/files/:id/view — inline preview (images/PDF)
app.get('/api/bills/:sl/files/:id/view', (req, res) => {
  try {
    const rows = query('SELECT * FROM bill_files WHERE id=? AND sl=?', [req.params.id, req.params.sl]);
    if (!rows.length) return res.status(404).send('Not found');
    const f = rows[0];
    if (f.file_path && fs.existsSync(f.file_path)) {
      res.setHeader('Content-Type', f.type || 'application/octet-stream');
      res.setHeader('Content-Disposition', `inline; filename="${f.name}"`);
      return res.sendFile(f.file_path);
    }
    if (f.data) {
      const base64 = f.data.includes(',') ? f.data.split(',')[1] : f.data;
      res.setHeader('Content-Type', f.type || 'application/octet-stream');
      res.setHeader('Content-Disposition', `inline; filename="${f.name}"`);
      return res.send(Buffer.from(base64, 'base64'));
    }
    res.status(404).send('Not found');
  } catch (err) { res.status(500).send(err.message); }
});

// DELETE /api/bills/:sl/files/:id — delete file from disk + DB
app.delete('/api/bills/:sl/files/:id', (req, res) => {
  try {
    const rows = query('SELECT * FROM bill_files WHERE id=? AND sl=?', [req.params.id, req.params.sl]);
    if (rows.length && rows[0].file_path) {
      try { fs.unlinkSync(rows[0].file_path); } catch(e) {} // remove from disk
    }
    run('DELETE FROM bill_files WHERE id=? AND sl=?', [req.params.id, req.params.sl]);
    saveDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/uploads/browse — list all uploaded files organised by SL (Admin use)
app.get('/api/uploads/browse', (req, res) => {
  try {
    const result = [];
    if (fs.existsSync(UPLOADS_DIR)) {
      const slDirs = fs.readdirSync(UPLOADS_DIR).filter(d => d.startsWith('SL-'));
      slDirs.forEach(slDir => {
        const fullDir = path.join(UPLOADS_DIR, slDir);
        const files   = fs.readdirSync(fullDir).map(f => {
          const stat = fs.statSync(path.join(fullDir, f));
          return { name: f, size: stat.size, mtime: stat.mtime.toISOString() };
        });
        result.push({ sl: slDir.replace('SL-',''), folder: fullDir, files });
      });
    }
    res.json({ ok: true, uploads_dir: UPLOADS_DIR, bills: result });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/send-email — Gmail
app.post('/api/send-email', async (req, res) => {
  try {
    const { from, pass, to, subject, htmlBody } = req.body;
    if (!from || !pass || !to) return res.status(400).json({ ok: false, error: 'Missing from/pass/to' });

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: { user: from, pass: pass },
      tls: { rejectUnauthorized: false }
    });

    await transporter.sendMail({
      from: `"TQS Bill Tracker" <${from}>`,
      to: to,
      subject: subject || 'TQS Bill Tracker — Management Report',
      html: htmlBody
    });

    console.log('Email report sent to:', to);
    res.json({ ok: true });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── BACKUP ENDPOINTS ──

// GET /api/backup — full JSON export of all tables
app.get('/api/backup', (req, res) => {
  try {
    const bills    = query('SELECT * FROM bills ORDER BY sl');
    const updates  = query('SELECT * FROM bill_updates ORDER BY sl');
    const history  = query('SELECT * FROM bill_history ORDER BY id');
    const vendors  = query('SELECT * FROM vendors ORDER BY id');
    const settings = query('SELECT * FROM app_settings');
    const files    = query('SELECT id,sl,name,size,type,uploaded_by,uploaded_at FROM bill_files ORDER BY id');

    const backup = {
      version: 3,
      app: 'TQS Bill Tracker',
      created_at: new Date().toISOString(),
      stats: { bills: bills.length, vendors: vendors.length, updates: updates.length, history: history.length, files: files.length },
      data: { bills, bill_updates: updates, bill_history: history, vendors, app_settings: settings, bill_files_meta: files }
    };

    const filename = `TQS_Backup_${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(backup);
  } catch (err) {
    console.error('Backup error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// GET /api/backup/full — full backup including file data (larger)
app.get('/api/backup/full', (req, res) => {
  try {
    const bills    = query('SELECT * FROM bills ORDER BY sl');
    const updates  = query('SELECT * FROM bill_updates ORDER BY sl');
    const history  = query('SELECT * FROM bill_history ORDER BY id');
    const vendors  = query('SELECT * FROM vendors ORDER BY id');
    const settings = query('SELECT * FROM app_settings');
    const files    = query('SELECT * FROM bill_files ORDER BY id');

    const backup = {
      version: 3,
      app: 'TQS Bill Tracker',
      full: true,
      created_at: new Date().toISOString(),
      stats: { bills: bills.length, vendors: vendors.length, updates: updates.length, history: history.length, files: files.length },
      data: { bills, bill_updates: updates, bill_history: history, vendors, app_settings: settings, bill_files: files }
    };

    const filename = `TQS_FullBackup_${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(backup);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/restore — restore from JSON backup
app.post('/api/restore', (req, res) => {
  try {
    const { backup, mode } = req.body; // mode: 'merge' | 'replace'
    if (!backup || !backup.data) return res.status(400).json({ ok: false, error: 'Invalid backup file' });

    const d = backup.data;
    let restored = { bills: 0, vendors: 0, updates: 0, history: 0, files: 0 };

    if (mode === 'replace') {
      // Wipe and replace everything
      run('DELETE FROM bill_files');
      run('DELETE FROM bill_history');
      run('DELETE FROM bill_updates');
      run('DELETE FROM bills');
      run('DELETE FROM vendors');
    }

    // Restore vendors
    if (d.vendors && d.vendors.length) {
      for (const v of d.vendors) {
        try {
          run(`INSERT OR IGNORE INTO vendors 
            (id,name,trade_name,contact_person,phone,email,address,city,state,pincode,
             gstin,pan,trade_license,msme_reg,vendor_type,bank_name,bank_account,
             bank_ifsc,bank_branch,notes,is_active,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [v.id,v.name||'',v.trade_name||'',v.contact_person||'',v.phone||'',v.email||'',
             v.address||'',v.city||'',v.state||'',v.pincode||'',v.gstin||'',v.pan||'',
             v.trade_license||'',v.msme_reg||'',v.vendor_type||'',v.bank_name||'',
             v.bank_account||'',v.bank_ifsc||'',v.bank_branch||'',v.notes||'',
             v.is_active??1,v.created_at||'',v.updated_at||'']);
          restored.vendors++;
        } catch(e) { /* skip duplicates */ }
      }
    }

    // Restore bills
    if (d.bills && d.bills.length) {
      for (const b of d.bills) {
        try {
          run(`INSERT OR IGNORE INTO bills
            (sl,vendor,po_number,po_date,inv_number,inv_date,inv_month,received_date,
             basic_amount,gst_amount,total_amount,credit_note_num,credit_note_val,
             remarks,tracker_type,is_deleted,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [b.sl,b.vendor||'',b.po_number||'',b.po_date||'',b.inv_number||'',
             b.inv_date||'',b.inv_month||'',b.received_date||'',
             parseFloat(b.basic_amount)||0,parseFloat(b.gst_amount)||0,
             parseFloat(b.total_amount)||0,b.credit_note_num||'',
             parseFloat(b.credit_note_val)||0,b.remarks||'',
             b.tracker_type||'po',
             b.is_deleted||0,b.created_at||'',b.updated_at||'']);
          restored.bills++;
        } catch(e) { /* skip duplicates */ }
      }
    }

    // Restore bill_updates
    if (d.bill_updates && d.bill_updates.length) {
      for (const u of d.bill_updates) {
        try {
          const keys = Object.keys(u).filter(k => k !== 'sl');
          if (!keys.length) continue;
          run('INSERT OR IGNORE INTO bill_updates (sl) VALUES (?)', [u.sl]);
          run(`UPDATE bill_updates SET ${keys.map(k=>k+'=?').join(',')} WHERE sl=?`,
            [...keys.map(k=>u[k]), u.sl]);
          restored.updates++;
        } catch(e) { /* skip */ }
      }
    }

    // Restore bill_history
    if (d.bill_history && d.bill_history.length) {
      for (const h of d.bill_history) {
        try {
          run('INSERT OR IGNORE INTO bill_history (id,sl,dept,action,ts) VALUES (?,?,?,?,?)',
            [h.id, h.sl, h.dept||'', h.action||'', h.ts||'']);
          restored.history++;
        } catch(e) { /* skip */ }
      }
    }

    // Restore files (if full backup)
    const fileSource = d.bill_files || [];
    if (fileSource.length) {
      for (const f of fileSource) {
        if (!f.data) continue; // skip metadata-only entries
        try {
          run('INSERT OR IGNORE INTO bill_files (id,sl,name,size,type,data,uploaded_by,uploaded_at) VALUES (?,?,?,?,?,?,?,?)',
            [f.id, f.sl, f.name||'', f.size||'', f.type||'', f.data, f.uploaded_by||'', f.uploaded_at||'']);
          restored.files++;
        } catch(e) { /* skip */ }
      }
    }

    // Restore app_settings (branding etc.)
    if (d.app_settings && d.app_settings.length) {
      for (const s of d.app_settings) {
        try {
          run(`INSERT INTO app_settings (key, value, updated_at)
               VALUES (?, ?, datetime('now','localtime'))
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
            [s.key, s.value||'']);
        } catch(e) { /* skip */ }
      }
    }

    saveDb();
    console.log('Restore complete:', restored);
    res.json({ ok: true, restored });
  } catch (err) {
    console.error('Restore error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ══════════════════════════════════════════════════════
// AUTO-BACKUP
// ══════════════════════════════════════════════════════

// Fix #14: Async/Await — backup uses async file I/O to avoid blocking the event loop
async function runAutoBackup() {
  try {
    const bills    = query('SELECT * FROM bills ORDER BY sl');
    const updates  = query('SELECT * FROM bill_updates ORDER BY sl');
    const history  = query('SELECT * FROM bill_history ORDER BY id');
    const vendors  = query('SELECT * FROM vendors ORDER BY id');
    const settings = query('SELECT * FROM app_settings');
    const files    = query('SELECT id,sl,name,size,type,uploaded_by,uploaded_at FROM bill_files ORDER BY id');

    const now = new Date();
    const backup = {
      version: 3,
      app: 'TQS Bill Tracker',
      created_at: now.toISOString(),
      auto: true,
      stats: { bills: bills.length, vendors: vendors.length, updates: updates.length, history: history.length },
      data: { bills, bill_updates: updates, bill_history: history, vendors, app_settings: settings, bill_files_meta: files }
    };

    const dateStr = now.toISOString().slice(0, 10);
    const timeStr = now.toISOString().slice(11, 16).replace(':', '');
    const filename = `TQS_AutoBackup_${dateStr}_${timeStr}.json`;
    const filepath = path.join(BACKUP_DIR, filename);
    await fs.promises.writeFile(filepath, JSON.stringify(backup));

    // Save last backup timestamp to settings
    run(`INSERT INTO app_settings (key, value, updated_at) VALUES ('last_autobackup_at', ?, datetime('now','localtime'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
      [now.toISOString()]);
    run(`INSERT INTO app_settings (key, value, updated_at) VALUES ('last_autobackup_file', ?, datetime('now','localtime'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
      [filename]);
    saveDb();

    // Keep only last 7 backups
    const allBackups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('TQS_AutoBackup_') && f.endsWith('.json'))
      .sort();
    if (allBackups.length > 7) {
      allBackups.slice(0, allBackups.length - 7).forEach(f => {
        try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch(e) {}
      });
    }

    console.log(`[AutoBackup] ✓ Saved: ${filename}  (${bills.length} bills, ${vendors.length} vendors)`);
    return { ok: true, filename, stats: backup.stats };
  } catch (err) {
    console.error('[AutoBackup] Error:', err.message);
    return { ok: false, error: err.message };
  }
}

// GET /api/autobackup/status — list saved auto-backups
app.get('/api/autobackup/status', (req, res) => {
  try {
    const backups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('TQS_AutoBackup_') && f.endsWith('.json'))
      .sort().reverse().slice(0, 7)
      .map(f => {
        const stat = fs.statSync(path.join(BACKUP_DIR, f));
        return { filename: f, size: stat.size, mtime: stat.mtime.toISOString() };
      });
    const lastRow = query("SELECT value FROM app_settings WHERE key='last_autobackup_at'");
    res.json({ ok: true, backups, last_at: lastRow[0]?.value || null });
  } catch (err) {
    res.json({ ok: true, backups: [], last_at: null });
  }
});

// POST /api/autobackup/now — trigger manual backup immediately
app.post('/api/autobackup/now', (req, res) => {
  runAutoBackup().then(result => res.json(result)).catch(err => res.status(500).json({ ok: false, error: err.message }));
});

// GET /api/autobackup/download/:filename — download a saved auto-backup
app.get('/api/autobackup/download/:filename', (req, res) => {
  try {
    const filename = path.basename(req.params.filename); // strip any directory component
    // Fix #2: Path Traversal prevention — check filename pattern
    if (!filename.startsWith('TQS_AutoBackup_') || !filename.endsWith('.json')) {
      return res.status(400).json({ ok: false, error: 'Invalid filename format' });
    }
    // Resolve full path and verify it is inside BACKUP_DIR
    const filepath = path.resolve(path.join(BACKUP_DIR, filename));
    const backupDirResolved = path.resolve(BACKUP_DIR);
    if (!filepath.startsWith(backupDirResolved + path.sep)) {
      return res.status(403).json({ ok: false, error: 'Access denied' });
    }
    if (!fs.existsSync(filepath)) return res.status(404).json({ ok: false, error: 'File not found' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.sendFile(filepath);
  } catch (err) {
    console.error('Backup download error:', err.message);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    const nets = os.networkInterfaces();
    let localIP = 'localhost';
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) { localIP = net.address; break; }
      }
    }
    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log('║     TQS Bill Tracker — Server Running            ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Local:   http://localhost:${PORT}                  ║`);
    console.log(`║  Network: http://${localIP}:${PORT}              ║`);
    console.log('╠══════════════════════════════════════════════════╣');
    console.log('║  Share the Network URL with all office users     ║');
    console.log('║  Database saved to: tqs_erp.db               ║');
    console.log('╚══════════════════════════════════════════════════╝\n');

    // ── Start auto-backup scheduler (every 24 hours) ──
    const BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
    setInterval(runAutoBackup, BACKUP_INTERVAL_MS);
    console.log('[AutoBackup] Scheduled: daily backup every 24 hours');
    console.log('[AutoBackup] Backups folder:', BACKUP_DIR);

    // Run an initial backup on first start if none exists today
    const today = new Date().toISOString().slice(0, 10);
    const todayBackup = fs.readdirSync(BACKUP_DIR).find(f => f.includes(today));
    if (!todayBackup) {
      setTimeout(runAutoBackup, 5000); // 5s delay to let server fully init
    }
  });
}).catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});

// ══════════════════════════════════════════════════════
// PO LIFECYCLE ENDPOINTS
// ══════════════════════════════════════════════════════

// GET /api/po — list all POs with live computed financials
app.get('/api/po', (req, res) => {
  try {
    const type = req.query.type || null;
    const poParams = [req.projectId || 0];
    let poTypeFilter = '';
    if (type === 'po' || type === 'wo') { poTypeFilter = 'AND p.tracker_type = ?'; poParams.push(type); }
    const pos = query(`
      SELECT p.*,
        COALESCE(SUM(b.total_amount),0) AS billed_to_date,
        COALESCE(SUM(u.certified_net),0) AS certified_to_date,
        COUNT(b.sl) AS invoice_count,
        p.po_value - COALESCE(SUM(b.total_amount),0) AS balance_uncommitted,
        ROUND(CASE WHEN p.po_value>0 THEN COALESCE(SUM(b.total_amount),0)/p.po_value*100 ELSE 0 END,1) AS utilisation_pct
      FROM purchase_orders p
      LEFT JOIN bills b ON b.po_number = p.po_number AND b.is_deleted=0
      LEFT JOIN bill_updates u ON u.sl = b.sl
      WHERE p.project_id = ? ${poTypeFilter}
      GROUP BY p.po_number
      ORDER BY p.created_at DESC
    `, poParams);
    res.json({ ok: true, pos });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// GET /api/po/:po_number — single PO detail with amendments, invoices, GRNs
app.get('/api/po/:po_number', (req, res) => {
  try {
    const pn = req.params.po_number;
    const rows = query('SELECT * FROM purchase_orders WHERE po_number=?', [pn]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'PO not found' });
    const po = rows[0];
    po.amendments = query('SELECT * FROM po_amendments WHERE po_number=? ORDER BY amendment_no', [pn]);
    po.invoices   = query(`SELECT b.sl, b.inv_number, b.inv_date, b.total_amount, u.certified_net, u.payment_status, b.tracker_type
                            FROM bills b LEFT JOIN bill_updates u ON u.sl=b.sl
                            WHERE b.po_number=? AND b.is_deleted=0`, [pn]);
    po.grns       = query('SELECT * FROM grn_entries WHERE po_number=? ORDER BY grn_date DESC', [pn]);
    // live match summary
    const totalInv  = po.invoices.reduce((s,r)=>s+(parseFloat(r.total_amount)||0),0);
    const totalGRN  = po.grns.reduce((s,r)=>s+(parseFloat(r.grn_value)||0),0);
    const totalCert = po.invoices.reduce((s,r)=>s+(parseFloat(r.certified_net)||0),0);
    po.match = {
      po_value: po.po_value,
      billed_to_date: totalInv,
      grn_to_date: totalGRN,
      certified_to_date: totalCert,
      balance: po.po_value - totalInv,
      inv_vs_po_pct: po.po_value>0 ? +((totalInv/po.po_value)*100).toFixed(1) : 0,
      inv_vs_grn_pct: totalGRN>0   ? +((totalInv/totalGRN)*100).toFixed(1)   : 0,
    };
    res.json({ ok: true, po });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// POST /api/po — create new PO
app.post('/api/po', (req, res) => {
  try {
    const d = req.body;
    if (!d.po_number || !d.vendor) return res.status(400).json({ ok: false, error: 'po_number and vendor required' });
    const exists = query('SELECT po_number FROM purchase_orders WHERE po_number=?', [d.po_number]);
    if (exists.length) return res.status(409).json({ ok: false, error: 'PO number already exists' });
    run(`INSERT INTO purchase_orders (po_number,vendor,po_date,po_value,description,site_code,tracker_type,status,approved_by,approval_date,project_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [d.po_number, d.vendor, d.po_date||'', parseFloat(d.po_value)||0,
       d.description||'', d.site_code||'', d.tracker_type==='wo'?'wo':'po',
       d.status||'Active', d.approved_by||'', d.approval_date||'',
       req.projectId||0]);
    saveDb();
    res.json({ ok: true, po_number: d.po_number });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// PATCH /api/po/:po_number — update PO status / fields
app.patch('/api/po/:po_number', (req, res) => {
  try {
    const pn = req.params.po_number;
    const d  = req.body;
    const allowed = ['status','approved_by','approval_date','description','site_code','po_date'];
    const fields  = Object.keys(d).filter(k => allowed.includes(k));
    if (!fields.length) return res.status(400).json({ ok: false, error: 'No valid fields' });
    run(`UPDATE purchase_orders SET ${fields.map(f=>f+'=?').join(',')}, updated_at=datetime('now','localtime') WHERE po_number=?`,
      [...fields.map(f=>d[f]), pn]);
    saveDb();
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// POST /api/po/:po_number/amend — raise a variation order
app.post('/api/po/:po_number/amend', (req, res) => {
  try {
    const pn = req.params.po_number;
    const d  = req.body;
    const rows = query('SELECT * FROM purchase_orders WHERE po_number=?', [pn]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'PO not found' });
    const po = rows[0];
    const amendNo = (po.amendment_count||0) + 1;
    const originalVal = parseFloat(po.po_value)||0;
    const revisedVal  = parseFloat(d.revised_value)||0;
    run(`INSERT INTO po_amendments (po_number,amendment_no,original_value,revised_value,reason,amended_by,amendment_date)
         VALUES (?,?,?,?,?,?,?)`,
      [pn, amendNo, originalVal, revisedVal, d.reason||'', d.amended_by||'', d.amendment_date||new Date().toISOString().slice(0,10)]);
    run(`UPDATE purchase_orders SET po_value=?, amendment_count=?, updated_at=datetime('now','localtime') WHERE po_number=?`,
      [revisedVal, amendNo, pn]);
    saveDb();
    res.json({ ok: true, amendment_no: amendNo, original_value: originalVal, revised_value: revisedVal });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// POST /api/grn — record a GRN against a PO
app.post('/api/grn', (req, res) => {
  try {
    const d = req.body;
    if (!d.po_number) return res.status(400).json({ ok: false, error: 'po_number required' });
    run(`INSERT INTO grn_entries (po_number,bill_sl,grn_date,grn_value,received_by,remarks)
         VALUES (?,?,?,?,?,?)`,
      [d.po_number, d.bill_sl||'', d.grn_date||new Date().toISOString().slice(0,10),
       parseFloat(d.grn_value)||0, d.received_by||'', d.remarks||'']);
    saveDb();
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// GET /api/po/:po_number/match — three-way match result
app.get('/api/po/:po_number/match', (req, res) => {
  try {
    const pn  = req.params.po_number;
    const tol = parseFloat(req.query.tol || '2');
    const rows = query('SELECT po_value FROM purchase_orders WHERE po_number=?', [pn]);
    if (!rows.length) return res.json({ ok: true, match: null, reason: 'PO not registered' });
    const poVal  = parseFloat(rows[0].po_value)||0;
    const invs   = query('SELECT total_amount FROM bills WHERE po_number=? AND is_deleted=0', [pn]);
    const grns   = query('SELECT grn_value FROM grn_entries WHERE po_number=?', [pn]);
    const totalInv = invs.reduce((s,r)=>s+(parseFloat(r.total_amount)||0),0);
    const totalGRN = grns.reduce((s,r)=>s+(parseFloat(r.grn_value)||0),0);
    const pct = (a,b) => b===0 ? 0 : Math.abs((a-b)/b*100);
    const grade = (p) => p<=tol?'pass': p<=tol*2.5?'warn':'fail';
    const checks = {
      inv_vs_po:  { diff: totalInv-poVal,    pct: pct(totalInv,poVal),   result: grade(pct(totalInv,poVal)),  label:'Invoice vs PO' },
      inv_vs_grn: { diff: totalInv-totalGRN, pct: pct(totalInv,totalGRN),result: grade(pct(totalInv,totalGRN)),label:'Invoice vs GRN' },
      grn_vs_po:  { diff: totalGRN-poVal,    pct: pct(totalGRN,poVal),   result: grade(pct(totalGRN,poVal)),  label:'GRN vs PO' },
    };
    const results = Object.values(checks).map(c=>c.result);
    const overall = results.includes('fail')?'fail': results.includes('warn')?'warn':'pass';
    res.json({ ok:true, po_value:poVal, billed:totalInv, grn:totalGRN, checks, overall, tolerance:tol });
  } catch(err) { res.status(500).json({ ok:false, error:err.message }); }
});

// ══════════════════════════════════════════════════════
// PO ITEMS ENDPOINTS
// ══════════════════════════════════════════════════════

// POST /api/po/:po_number/items — save/replace all line items for a PO
app.post('/api/po/:po_number/items', (req, res) => {
  try {
    const pn = req.params.po_number;
    const { items } = req.body;
    if (!Array.isArray(items)) return res.status(400).json({ ok:false, error:'items array required' });
    // Delete existing and re-insert
    run('DELETE FROM po_items WHERE po_number=?', [pn]);
    let totalVal = 0;
    items.forEach((it, idx) => {
      const amt = parseFloat(it.amount) || (parseFloat(it.quantity||0) * parseFloat(it.rate||0));
      totalVal += amt;
      const gp = parseFloat(it.gst_pct)||0;
      const ga = parseFloat(it.gst_amt)||parseFloat((amt*gp/100).toFixed(2));
      const ta = parseFloat(it.total_amt)||(amt+ga);
      run(`INSERT INTO po_items (po_number,sl_no,description,uom,quantity,rate,amount,gst_pct,gst_amt,total_amt,heads)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [pn, idx+1, it.description||'', it.uom||'', parseFloat(it.quantity)||0,
         parseFloat(it.rate)||0, amt, gp, ga, ta, it.heads||'']);
    });
    // Update po_value from items total
    run(`UPDATE purchase_orders SET po_value=?, updated_at=datetime('now','localtime') WHERE po_number=?`,
      [totalVal, pn]);
    saveDb();
    res.json({ ok:true, item_count: items.length, total_value: totalVal });
  } catch(err) { res.status(500).json({ ok:false, error:err.message }); }
});

// GET /api/po/:po_number/items — get line items for a PO
app.get('/api/po/:po_number/items', (req, res) => {
  try {
    const pn = req.params.po_number;
    const items = query('SELECT * FROM po_items WHERE po_number=? ORDER BY sl_no', [pn]);
    res.json({ ok:true, items });
  } catch(err) { res.status(500).json({ ok:false, error:err.message }); }
});

// POST /api/po — updated to also accept items and extra fields
// (extends existing POST /api/po by also saving items if provided)
app.post('/api/po/full', (req, res) => {
  try {
    const d = req.body;
    if (!d.po_number || !d.vendor) return res.status(400).json({ ok:false, error:'po_number and vendor required' });
    const exists = query('SELECT po_number FROM purchase_orders WHERE po_number=?', [d.po_number]);
    if (exists.length) return res.status(409).json({ ok:false, error:'PO number already exists' });

    // Compute total from items
    const items = d.items || [];
    let totalVal = items.reduce((s,it) => {
      const basic = parseFloat(it.amount) || (parseFloat(it.quantity||0)*parseFloat(it.rate||0));
      const gstPct = parseFloat(it.gst_pct)||0;
      const gstAmt = parseFloat(it.gst_amt)||parseFloat((basic*gstPct/100).toFixed(2));
      const tot = parseFloat(it.total_amt)||(basic+gstAmt);
      return s + tot;
    }, 0);
    if (totalVal === 0) totalVal = parseFloat(d.po_value)||0;

    run(`INSERT INTO purchase_orders
         (po_number,vendor,po_date,po_value,description,site_code,tracker_type,status,
          approved_by,approval_date,po_req_no,po_req_date,approval_no,
          delivery_address,delivery_contact,narration,form_no)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [d.po_number, d.vendor, d.po_date||'', totalVal,
       d.description||'', d.site_code||'', d.tracker_type==='wo'?'wo':'po',
       d.status||'Active', d.approved_by||'', d.approval_date||'',
       d.po_req_no||'', d.po_req_date||'', d.approval_no||'',
       d.delivery_address||'', d.delivery_contact||'',
       d.narration||'', d.form_no||'BCIM-PUR-F-03']);

    // Save items
    items.forEach((it, idx) => {
      const amt = parseFloat(it.amount) || (parseFloat(it.quantity||0)*parseFloat(it.rate||0));
      const gstPct = parseFloat(it.gst_pct)||0;
      const gstAmt = parseFloat(it.gst_amt)||parseFloat((amt*gstPct/100).toFixed(2));
      const totAmt = parseFloat(it.total_amt)||(amt+gstAmt);
      run(`INSERT INTO po_items (po_number,sl_no,description,uom,quantity,rate,amount,gst_pct,gst_amt,total_amt,heads)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [d.po_number, idx+1, it.description||'', it.uom||'', parseFloat(it.quantity)||0,
         parseFloat(it.rate)||0, amt, gstPct, gstAmt, totAmt, it.heads||'']);
    });

    saveDb();
    res.json({ ok:true, po_number:d.po_number, total_value:totalVal, item_count:items.length });
  } catch(err) { res.status(500).json({ ok:false, error:err.message }); }
});

// GET /api/po/:po_number/print — generate PDF using PDFKit (pure Node.js, no Python)
app.get('/api/po/:po_number/print', (req, res) => {
  const pn = req.params.po_number;
  try {
    const PDFDocument = require('pdfkit');
    const rows = query('SELECT * FROM purchase_orders WHERE po_number=?', [pn]);
    if (!rows.length) return res.status(404).json({ ok:false, error:'PO not found' });
    const po    = rows[0];
    const items = query('SELECT * FROM po_items WHERE po_number=? ORDER BY sl_no', [pn]);
    const vrows = query('SELECT * FROM vendors WHERE LOWER(name)=LOWER(?) LIMIT 1', [po.vendor]);
    const v     = vrows[0] || {};
    const settRows = query('SELECT key,value FROM app_settings');
    const S = {}; settRows.forEach(r => { S[r.key] = r.value; });

    // ── Company defaults — Fix #9: Configurable settings (no hardcoded company details) ──
    // Configure these via PUT /api/settings: company_name, company_addr, company_gstin, etc.
    const coName   = S.company_name   || S.company || 'Your Company Name';
    const coWing   = S.company_wing   || '';
    const coAddr   = S.company_addr   || '';
    const coGstin  = S.company_gstin  || '';
    const coFooter = S.company_footer || (coName + (coAddr ? ', ' + coAddr : ''));
    const formNo   = po.form_no || S.form_no || 'PUR-F-01';

    // ── Helpers ──
    const fN = v => { const n=parseFloat(v)||0; return n.toLocaleString('en-IN',{maximumFractionDigits:2}); };
    const fQ = v => { try{return parseFloat(v).toFixed(2);}catch(e){return String(v||'');} };

    function numWords(n) {
      n = Math.round(parseFloat(n)||0);
      const ones=['','One','Two','Three','Four','Five','Six','Seven','Eight','Nine','Ten',
        'Eleven','Twelve','Thirteen','Fourteen','Fifteen','Sixteen','Seventeen','Eighteen','Nineteen'];
      const tens=['','','Twenty','Thirty','Forty','Fifty','Sixty','Seventy','Eighty','Ninety'];
      function b1000(n){
        if(n<20)return ones[n];
        if(n<100)return tens[Math.floor(n/10)]+(n%10?' '+ones[n%10]:'');
        return ones[Math.floor(n/100)]+' Hundred'+(n%100?' '+b1000(n%100):'');
      }
      if(n===0)return 'Zero Only.';
      let p=[];
      if(n>=10000000){p.push(b1000(Math.floor(n/10000000))+' Crore');n%=10000000;}
      if(n>=100000) {p.push(b1000(Math.floor(n/100000))+' Lakh');  n%=100000;}
      if(n>=1000)   {p.push(b1000(Math.floor(n/1000))+' Thousand');n%=1000;}
      if(n>0)        p.push(b1000(n));
      return p.join(' ')+' Only.';
    }

    // ── Totals ──
    let subTotal=0, totalGst=0;
    const gstGroups={};
    items.forEach(it=>{
      const basic = parseFloat(it.amount)||0;
      const gPct  = parseFloat(it.gst_pct)||0;
      const gAmt  = parseFloat(it.gst_amt)||parseFloat((basic*gPct/100).toFixed(2));
      const tot   = parseFloat(it.total_amt)||(basic+gAmt);
      subTotal += basic; totalGst += gAmt;
      if(gAmt>0){ gstGroups[gPct]=(gstGroups[gPct]||0)+gAmt; }
    });
    const grandTotal = subTotal + totalGst;

    // ── PDF setup ──
    const doc = new PDFDocument({ size:'A4', margins:{top:40,bottom:50,left:35,right:30}, autoFirstPage:true });
    const chunks=[];
    doc.on('data', d=>chunks.push(d));
    doc.on('end', ()=>{
      const buf = Buffer.concat(chunks);
      res.setHeader('Content-Type','application/pdf');
      res.setHeader('Content-Disposition',`inline; filename="PO_${pn}.pdf"`);
      res.send(buf);
    });

    const PW = doc.page.width;
    const LM = doc.page.margins.left;
    const RM = doc.page.margins.right;
    const TW = PW - LM - RM; // usable width ~530

    // ── Draw helpers ──
    function rule(y,thick=0.5,color='#888888'){
      doc.save().moveTo(LM,y).lineTo(PW-RM,y).lineWidth(thick).strokeColor(color).stroke().restore();
    }
    function rect(x,y,w,h,fill,stroke){
      doc.save().rect(x,y,w,h);
      if(fill)doc.fillColor(fill).fill();
      if(stroke)doc.strokeColor(stroke).lineWidth(0.5).stroke();
      doc.restore();
    }
    function cell(txt,x,y,w,h,opts={}){
      const { align='left', bold=false, size=7, color='#000000', bg=null, wrap=true } = opts;
      if(bg) rect(x,y,w,h,bg,null);
      doc.save()
        .font(bold?'Helvetica-Bold':'Helvetica').fontSize(size).fillColor(color);
      const pad=3;
      if(wrap){
        doc.text(String(txt||''), x+pad, y+pad, {width:w-pad*2, height:h-pad*2, align, lineBreak:true, ellipsis:true});
      } else {
        doc.text(String(txt||''), x+pad, y+2, {width:w-pad*2, align, lineBreak:false});
      }
      doc.restore();
    }

    // ── PAGE HEADER (runs on every page) ──
    function drawHeader(pageNum) {
      let y = doc.page.margins.top - 5;

      // Form number top-right
      doc.save().font('Helvetica-Bold').fontSize(7).fillColor('#000')
        .text(formNo, PW-RM-80, 18, {width:80, align:'right'}).restore();

      // Logo box
      rect(LM, y, 28, 22, null, '#1a5276');
      doc.save().font('Helvetica-Bold').fontSize(14).fillColor('#1a5276')
        .text('3', LM+2, y+1, {width:24, align:'center'}).restore();
      doc.save().font('Helvetica-Bold').fontSize(8).fillColor('#1a5276')
        .text('BCIM', LM+2, y+12, {width:24, align:'center'}).restore();

      // Company name block
      doc.save().font('Helvetica-Bold').fontSize(8).fillColor('#000')
        .text(coName, LM+32, y+1, {width:200}).restore();
      doc.save().font('Helvetica').fontSize(7).fillColor('#444')
        .text(coWing, LM+32, y+11, {width:200}).restore();
      doc.save().font('Helvetica').fontSize(7).fillColor('#444')
        .text(coAddr, LM+32, y+19, {width:200}).restore();

      // PURCHASE ORDER title
      doc.save().font('Helvetica-Bold').fontSize(13).fillColor('#000')
        .text('PURCHASE ORDER', LM+260, y+4, {width:TW-260, align:'center'}).restore();

      y += 26;
      rule(y, 1.5, '#000000');
      y += 4;

      // Vendor address + PO info box side by side
      const poInfoX = LM + TW - 150;
      const poInfoW = 150;
      const addrW   = TW - poInfoW - 8;

      // Vendor address
      doc.save().font('Helvetica').fontSize(7).fillColor('#000')
        .text('To,', LM, y).restore();
      y += 9;
      doc.save().font('Helvetica-Bold').fontSize(7.5).fillColor('#000')
        .text('M/s. '+po.vendor, LM, y, {width:addrW}).restore();
      y += 10;
      if(v.address){ doc.save().font('Helvetica').fontSize(7).fillColor('#333').text(v.address+(v.city?', '+v.city:''), LM, y,{width:addrW}).restore(); y+=9; }
      if(v.email){   doc.save().font('Helvetica').fontSize(7).fillColor('#333').text('Email: '+v.email, LM, y,{width:addrW}).restore(); y+=9; }
      if(v.phone||v.contact_person){
        const cp = v.contact_person ? 'Contact: '+v.contact_person+(v.phone?' Mob: '+v.phone:'') : 'Ph: '+v.phone;
        doc.save().font('Helvetica').fontSize(7).fillColor('#333').text(cp, LM, y,{width:addrW}).restore(); y+=9;
      }
      if(v.gstin){ doc.save().font('Helvetica').fontSize(7).fillColor('#333').text('GST No: '+v.gstin, LM, y,{width:addrW}).restore(); y+=9; }

      // PO Info box (right side)
      const poInfoY = doc.page.margins.top + 30;
      const rows2 = [
        ['Project:',   po.site_code||po.description||''],
        ['PO No:',     po.po_number||''],
        ['Date:',      po.po_date||''],
        ['PO Req No:', po.po_req_no||''],
        ['PO Req Date:',po.po_req_date||''],
        ['Approval No:',po.approval_no||''],
      ];
      let ry = poInfoY;
      rows2.forEach(([lbl,val])=>{
        rect(poInfoX, ry, 55, 11, null, '#cccccc');
        rect(poInfoX+55, ry, poInfoW-55, 11, null, '#cccccc');
        doc.save().font('Helvetica').fontSize(6.5).fillColor('#444')
          .text(lbl, poInfoX+2, ry+3, {width:52, lineBreak:false}).restore();
        doc.save().font('Helvetica-Bold').fontSize(6.5).fillColor('#000')
          .text(val, poInfoX+57, ry+3, {width:poInfoW-60, lineBreak:false}).restore();
        ry += 11;
      });

      y = Math.max(y, ry) + 4;

      // Delivery address
      rule(y, 0.5);
      y += 3;
      doc.save().font('Helvetica-Bold').fontSize(7).fillColor('#000')
        .text('DELIVERY ADDRESS:-', LM, y).restore();
      y += 10;
      doc.save().font('Helvetica-Bold').fontSize(7).fillColor('#000')
        .text('Project: '+(po.site_code||''), LM, y, {width:TW}).restore();
      y += 9;
      if(po.delivery_address){
        const dlines = po.delivery_address.split('\n');
        dlines.forEach(dl=>{
          doc.save().font('Helvetica').fontSize(7).fillColor('#333')
            .text(dl, LM, y, {width:TW}).restore(); y+=9;
        });
      }
      if(po.delivery_contact){
        doc.save().font('Helvetica').fontSize(7).fillColor('#333')
          .text('Contact Person: '+po.delivery_contact, LM, y,{width:TW}).restore(); y+=9;
      }
      y += 2;
      doc.save().font('Helvetica').fontSize(7).fillColor('#333')
        .text('We hereby place an order on you for supply of the following materials with same terms and conditions as per original order.', LM, y, {width:TW}).restore();
      y += 10;

      return y;
    }

    // ── LINE ITEMS TABLE ──
    // Col widths: Sl|Description|UOM|Qty|Rate|Basic Amt|GST%|GST Amt|Total Amt|Heads
    const CW = [18, 145, 28, 32, 38, 40, 22, 36, 42, 30];
    const CH = 10; // col header height
    const RH = 11; // default row height

    function drawTableHeader(y){
      const hdrs = ['Sl No','Description','UOM','Quantity','Rate','Basic Amt','GST%','GST Amt','Total Amt','HEADS'];
      let x = LM;
      hdrs.forEach((h,i)=>{
        rect(x, y, CW[i], CH, '#d6e4f0', '#aaaaaa');
        doc.save().font('Helvetica-Bold').fontSize(6.5).fillColor('#000')
          .text(h, x+1, y+2, {width:CW[i]-2, align:'center', lineBreak:false}).restore();
        x += CW[i];
      });
      return y + CH;
    }

    function drawTableRow(it, y, rowBg){
      const basic  = parseFloat(it.amount)||0;
      const gPct   = parseFloat(it.gst_pct)||0;
      const gAmt   = parseFloat(it.gst_amt)||parseFloat((basic*gPct/100).toFixed(2));
      const totAmt = parseFloat(it.total_amt)||(basic+gAmt);
      const rate   = it.rate!=null && it.rate!==''&&parseFloat(it.rate||0)>0 ? fN(it.rate) : '';

      const vals = [
        {t:String(it.sl_no||''), a:'center'},
        {t:String(it.description||''), a:'left'},
        {t:String(it.uom||''), a:'center'},
        {t:fQ(it.quantity), a:'right'},
        {t:rate, a:'right'},
        {t:basic?fN(basic):'', a:'right'},
        {t:gPct?gPct+'%':'0%', a:'center'},
        {t:gAmt?fN(gAmt):'', a:'right'},
        {t:totAmt?fN(totAmt):'', a:'right'},
        {t:String(it.heads||''), a:'center'},
      ];

      // Measure description height
      doc.save().font('Helvetica').fontSize(6.5);
      const descLines = doc.heightOfString(vals[1].t, {width:CW[1]-4});
      doc.restore();
      const rowH = Math.max(RH, descLines + 4);

      // Draw row
      let x = LM;
      if(rowBg) rect(x, y, CW.reduce((a,b)=>a+b,0), rowH, rowBg, null);

      vals.forEach((v,i)=>{
        doc.save().rect(x,y,CW[i],rowH).lineWidth(0.3).strokeColor('#aaaaaa').stroke().restore();
        const fnt = (i===8)?'Helvetica-Bold':'Helvetica';
        const clr = (i===8)?'#1a3c6e':'#000';
        doc.save().font(fnt).fontSize(6.5).fillColor(clr)
          .text(v.t, x+2, y+2, {width:CW[i]-4, align:v.a, lineBreak:i===1});
        doc.restore();
        x += CW[i];
      });
      return y + rowH;
    }

    // ── BUILD PAGES ──
    let y = drawHeader(1);

    // Table header
    y = drawTableHeader(y);

    let pageNum = 1;
    let headsDone = {}; // track HEADS spans

    for(let i=0; i<items.length; i++){
      const it = items[i];

      // Check if we need a new page
      if(y > doc.page.height - doc.page.margins.bottom - 15){
        // Footer on current page
        drawFooter(pageNum);
        doc.addPage();
        pageNum++;
        y = doc.page.margins.top;
        y = drawTableHeader(y);
      }

      const rowBg = i%2===0 ? null : '#fafafa';
      y = drawTableRow(it, y, rowBg);
    }

    // ── TOTALS ──
    const needSpace = 8 + Object.keys(gstGroups).length*10 + 14 + 30 + 40;
    if(y + needSpace > doc.page.height - doc.page.margins.bottom){
      drawFooter(pageNum); doc.addPage(); pageNum++;
      y = doc.page.margins.top;
    }

    y += 3;
    const totX = LM + TW - 200;
    const totLW = 130, totVW = 68;

    function totRow(lbl, val, bold=false){
      rect(totX, y, totLW, 11, bold?'#d6e4f0':null, '#bbbbbb');
      rect(totX+totLW, y, totVW, 11, bold?'#d6e4f0':null, '#bbbbbb');
      const fnt = bold?'Helvetica-Bold':'Helvetica';
      doc.save().font(fnt).fontSize(7.5).fillColor('#000')
        .text(lbl, totX+4, y+3, {width:totLW-6, lineBreak:false}).restore();
      doc.save().font(fnt).fontSize(7.5).fillColor(bold?'#1a3c6e':'#000')
        .text(val, totX+totLW+2, y+3, {width:totVW-4, align:'right', lineBreak:false}).restore();
      y += 11;
    }

    totRow('Sub Total (Basic)', '₹'+fN(subTotal));
    Object.keys(gstGroups).sort().forEach(pct=>{
      totRow('GST @ '+pct+'%', '₹'+fN(gstGroups[pct]));
    });
    rule(y,0.8,'#000'); y+=2;
    totRow('Grand Total', '₹'+fN(grandTotal), true);

    y += 5;
    doc.save().font('Helvetica-Bold').fontSize(7.5).fillColor('#000')
      .text('Rupees: '+numWords(grandTotal), LM, y, {width:TW}).restore();
    y += 12;

    if(po.narration||po.description){
      doc.save().font('Helvetica').fontSize(7).fillColor('#000')
        .text('Narration: '+(po.narration||po.description||''), LM, y, {width:TW}).restore();
      y += 11;
    }

    // ── TERMS ──
    const terms = [
      'All Bills and DCs should contain the Reference of the Concerned PO.',
      'All materials supplied will be subject to inspections & test when received at our site.',
      'Final Bill shall be cleared after Certification by the Concerned Engg & on actual measurements taken at Site.',
      'If any Goods damaged or rejected must be replaced immediately at the suppliers own expenses.',
      'Payment: 60 Days from the date of supply. Lead Time: Within 2-3 days from the date of order.',
      'Bill must carry details of Order number, site acceptance signature, GST number, HSN Code, Bill number, LUT details, Transporter challan.',
      'Quantity mentioned in the Order may be approximate; actual & mutually certified measurement will be accounted for payment.',
      'Price mentioned is absolute and frozen. Any price escalation will be considered breach of Contract terms.',
      'Buyer reserves the right to cancel this order without liability if delivery is not made as specified.',
      'TDS as applicable under Income Tax Laws and GST Laws shall be deducted at applicable rates.',
      'NOTE: 3 Copies of Tax invoice (original, duplicate & triplicate) to be submitted with each consignment.',
      'Order to be acknowledged within 4 hours. If not it will be considered as accepted.',
    ];

    if(y + 15 + terms.length*10 > doc.page.height - doc.page.margins.bottom - 30){
      drawFooter(pageNum); doc.addPage(); pageNum++;
      y = doc.page.margins.top;
    }

    y += 3;
    doc.save().font('Helvetica-Bold').fontSize(7.5).fillColor('#000')
      .text('Terms & Conditions:', LM, y).restore();
    y += 11;

    terms.forEach((t,i)=>{
      if(y > doc.page.height - doc.page.margins.bottom - 20){
        drawFooter(pageNum); doc.addPage(); pageNum++;
        y = doc.page.margins.top;
      }
      doc.save().font('Helvetica').fontSize(7).fillColor('#000')
        .text((i+1)+'.  '+t, LM+4, y, {width:TW-4}).restore();
      const th = doc.heightOfString((i+1)+'.  '+t, {width:TW-4});
      y += Math.max(10, th+2);
    });

    // ── SIGNATURE ──
    if(y + 30 > doc.page.height - doc.page.margins.bottom){
      drawFooter(pageNum); doc.addPage(); pageNum++;
      y = doc.page.margins.top;
    }
    y += 8;
    rule(y, 0.5); y += 4;
    doc.save().font('Helvetica').fontSize(7).fillColor('#555')
      .text('Checked by', LM, y).restore();
    doc.save().font('Helvetica').fontSize(7).fillColor('#555')
      .text(po.po_date||'', LM, y+16).restore();
    doc.save().font('Helvetica-Bold').fontSize(7.5).fillColor('#000')
      .text('Director', LM + TW/2 - 20, y+18).restore();
    doc.save().font('Helvetica-Bold').fontSize(7.5).fillColor('#000')
      .text('Managing Director', PW-RM-80, y+18, {width:80, align:'right'}).restore();

    // ── FOOTER ──
    function drawFooter(pgNum){
      const fy = doc.page.height - 42;
      doc.save().moveTo(LM,fy).lineTo(PW-RM,fy).lineWidth(0.5).strokeColor('#888').stroke().restore();
      doc.save().font('Helvetica-Bold').fontSize(6.5).fillColor('#000')
        .text(coName, LM, fy+4, {width:TW, align:'center'}).restore();
      doc.save().font('Helvetica').fontSize(6).fillColor('#444')
        .text(coFooter, LM, fy+13, {width:TW-60, align:'center'}).restore();
      doc.save().font('Helvetica').fontSize(6).fillColor('#444')
        .text('Page '+pgNum, PW-RM-35, fy+13, {width:35, align:'right'}).restore();
    }

    drawFooter(pageNum);
    doc.end();

  } catch(err) {
    console.error('Print error:', err.message);
    if(!res.headersSent) res.status(500).json({ ok:false, error:err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════
// STOCK ITEMS ENDPOINTS
// ══════════════════════════════════════════════════════════════════════

// GET /api/stock-items
app.get('/api/stock-items', (req, res) => {
  try {
    const items = query('SELECT * FROM stock_items ORDER BY category, item_name');
    res.json({ ok: true, items });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// POST /api/stock-items
app.post('/api/stock-items', (req, res) => {
  try {
    const d = req.body;
    if (!d.item_code || !d.item_name) return res.status(400).json({ ok:false, error:'item_code and item_name required' });
    const exists = query('SELECT item_code FROM stock_items WHERE item_code=?',[d.item_code]);
    if (exists.length) return res.status(409).json({ ok:false, error:'Item code already exists' });
    run(`INSERT INTO stock_items (item_code,item_name,category,unit,reorder_qty,min_stock,last_rate)
         VALUES (?,?,?,?,?,?,?)`,
      [d.item_code, d.item_name, d.category||'', d.unit||'', parseFloat(d.reorder_qty)||0,
       parseFloat(d.min_stock)||0, parseFloat(d.last_rate)||0]);
    saveDb();
    res.json({ ok:true, item_code:d.item_code });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// PUT /api/stock-items/:code
app.put('/api/stock-items/:code', (req, res) => {
  try {
    const d = req.body;
    run(`UPDATE stock_items SET item_name=?,category=?,unit=?,reorder_qty=?,min_stock=?,last_rate=?,updated_at=datetime('now','localtime')
         WHERE item_code=?`,
      [d.item_name, d.category||'', d.unit||'', parseFloat(d.reorder_qty)||0,
       parseFloat(d.min_stock)||0, parseFloat(d.last_rate)||0, req.params.code]);
    saveDb();
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// GET /api/stock-ledger/:item_code
app.get('/api/stock-ledger/:item_code', (req, res) => {
  try {
    const rows = query('SELECT * FROM stock_ledger WHERE item_code=? ORDER BY txn_date DESC, id DESC LIMIT 100',[req.params.item_code]);
    const item = query('SELECT * FROM stock_items WHERE item_code=?',[req.params.item_code]);
    res.json({ ok:true, ledger:rows, item: item[0]||null });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// POST /api/stock-adjust — manual receipt or adjustment
app.post('/api/stock-adjust', (req, res) => {
  try {
    const d = req.body;
    if (!d.item_code || !d.txn_type) return res.status(400).json({ ok:false, error:'item_code and txn_type required' });
    const item = query('SELECT * FROM stock_items WHERE item_code=?',[d.item_code]);
    if (!item.length) return res.status(404).json({ ok:false, error:'Item not found' });
    const it = item[0];
    const qty    = parseFloat(d.qty)||0;
    const rate   = parseFloat(d.rate)||parseFloat(it.last_rate)||0;
    const value  = qty * rate;
    const isIn   = ['Receipt','GRN','Opening','Return'].includes(d.txn_type);
    const qtyIn  = isIn ? qty : 0;
    const qtyOut = isIn ? 0 : qty;
    const valIn  = isIn ? value : 0;
    const valOut = isIn ? 0 : value;
    const newQty = parseFloat(it.current_qty) + qtyIn - qtyOut;
    const newVal = Math.max(0, parseFloat(it.current_value) + valIn - valOut);
    const newRate= newQty > 0 ? newVal/newQty : rate;
    run(`INSERT INTO stock_ledger (item_code,txn_date,txn_type,ref_type,ref_id,indent_no,bill_sl,qty_in,qty_out,rate,value_in,value_out,balance_qty,balance_value,narration,recorded_by)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [d.item_code, d.txn_date||new Date().toISOString().slice(0,10), d.txn_type,
       d.ref_type||'', d.ref_id||'', d.indent_no||'', d.bill_sl||'',
       qtyIn, qtyOut, rate, valIn, valOut, newQty, newVal, d.narration||'', d.recorded_by||'']);
    run(`UPDATE stock_items SET current_qty=?,current_value=?,last_rate=?,updated_at=datetime('now','localtime') WHERE item_code=?`,
      [newQty, newVal, newRate, d.item_code]);
    saveDb();
    res.json({ ok:true, new_qty:newQty, new_value:newVal });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// ══════════════════════════════════════════════════════════════════════
// MATERIAL INDENT ENDPOINTS
// ══════════════════════════════════════════════════════════════════════

// GET /api/indents
app.get('/api/indents', (req, res) => {
  try {
    const status = req.query.status || '';
    const type   = req.query.type   || '';
    const conds = ['project_id=?'];
    const params = [req.projectId || 0];
    if (status) { conds.push('status=?'); params.push(status); }
    if (type)   { conds.push('tracker_type=?'); params.push(type); }
    let q = 'SELECT * FROM material_indents WHERE ' + conds.join(' AND ');
    q += ' ORDER BY created_at DESC';
    const indents = query(q, params);
    // Attach item count to each
    indents.forEach(ind => {
      const items = query('SELECT COUNT(*) as cnt FROM indent_items WHERE indent_no=?',[ind.indent_no]);
      ind.item_count = items[0]?.cnt || 0;
    });
    res.json({ ok:true, indents });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// GET /api/indents/:indent_no
app.get('/api/indents/:indent_no', (req, res) => {
  try {
    const rows = query('SELECT * FROM material_indents WHERE indent_no=?',[req.params.indent_no]);
    if (!rows.length) return res.status(404).json({ ok:false, error:'Indent not found' });
    const indent = rows[0];
    indent.items = query('SELECT * FROM indent_items WHERE indent_no=? ORDER BY id',[req.params.indent_no]);
    res.json({ ok:true, indent });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// POST /api/indents — create new indent
app.post('/api/indents', (req, res) => {
  try {
    const d = req.body;
    if (!d.indent_no || !d.raised_by) return res.status(400).json({ ok:false, error:'indent_no and raised_by required' });
    const exists = query('SELECT indent_no FROM material_indents WHERE indent_no=?',[d.indent_no]);
    if (exists.length) return res.status(409).json({ ok:false, error:'Indent number already exists' });
    run(`INSERT INTO material_indents (indent_no,raised_by,raised_date,site_code,purpose,required_date,tracker_type,project_id,status)
         VALUES (?,?,?,?,?,?,?,?,?)`,
      [d.indent_no, d.raised_by, d.raised_date||new Date().toISOString().slice(0,10),
       d.site_code||'', d.purpose||'', d.required_date||'',
       d.tracker_type==='wo'?'wo':'po', req.projectId||0, 'Pending Stores']);
    const items = d.items || [];
    items.forEach(it => {
      const estVal = (parseFloat(it.qty_requested)||0) * (parseFloat(it.est_rate)||0);
      run(`INSERT INTO indent_items (indent_no,item_code,item_name,unit,qty_requested,est_rate,est_value,remarks)
           VALUES (?,?,?,?,?,?,?,?)`,
        [d.indent_no, it.item_code||'', it.item_name||it.item_code||'',
         it.unit||'', parseFloat(it.qty_requested)||0,
         parseFloat(it.est_rate)||0, estVal, it.remarks||'']);
    });
    saveDb();
    res.json({ ok:true, indent_no:d.indent_no, item_count:items.length });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// PATCH /api/indents/:indent_no/approve — advance approval stage
app.patch('/api/indents/:indent_no/approve', (req, res) => {
  try {
    const d = req.body;
    const ind = req.params.indent_no;
    const row = query('SELECT * FROM material_indents WHERE indent_no=?',[ind]);
    if (!row.length) return res.status(404).json({ ok:false, error:'Indent not found' });
    const current = row[0];

    // Fix #13: Workflow State Machine — enforce valid transitions
    // Pending Stores → Stores Checked → QS Approved → PM Approved → MD Approved → PO Raised → Closed
    const FLOW = ['Pending Stores','Stores Checked','QS Approved','PM Approved','MD Approved','PO Raised','Closed'];
    const ACTION_REQUIRED_STATUS = {
      'stores_check': 'Pending Stores',
      'qs_approve':   'Stores Checked',
      'pm_approve':   'QS Approved',
      'md_approve':   'PM Approved',
      'raise_po':     'MD Approved',
    };

    if (d.action === 'reject') {
      // Allow rejection from any non-terminal state
      if (current.status === 'Closed' || current.status === 'Rejected') {
        return res.status(400).json({ ok:false, error:`Cannot reject an indent with status "${current.status}"` });
      }
    } else if (ACTION_REQUIRED_STATUS[d.action]) {
      const required = ACTION_REQUIRED_STATUS[d.action];
      if (current.status !== required) {
        return res.status(400).json({
          ok: false,
          error: `Action "${d.action}" requires status "${required}" but current status is "${current.status}"`
        });
      }
    } else if (d.action !== 'reject') {
      return res.status(400).json({ ok:false, error:'Unknown action' });
    }

    let sets = [], params = [];
    if (d.action === 'stores_check') {
      sets = ['status=?','stores_checked_by=?','stores_checked_date=?','stores_remarks=?'];
      params = ['Stores Checked', d.by||'', d.date||new Date().toISOString().slice(0,10), d.remarks||''];
      // Also update approved qty on each item
      if (d.items) {
        d.items.forEach(it => {
          run('UPDATE indent_items SET qty_approved=? WHERE id=?',[parseFloat(it.qty_approved)||0, it.id]);
        });
      }
    } else if (d.action === 'qs_approve') {
      sets = ['status=?','qs_approved_by=?','qs_approved_date=?','qs_remarks=?'];
      params = ['QS Approved', d.by||'', d.date||new Date().toISOString().slice(0,10), d.remarks||''];
    } else if (d.action === 'pm_approve') {
      sets = ['status=?','pm_approved_by=?','pm_approved_date=?','pm_remarks=?'];
      params = ['PM Approved', d.by||'', d.date||new Date().toISOString().slice(0,10), d.remarks||''];
    } else if (d.action === 'md_approve') {
      sets = ['status=?','md_approved_by=?','md_approved_date=?','md_remarks=?'];
      params = ['MD Approved', d.by||'', d.date||new Date().toISOString().slice(0,10), d.remarks||''];
    } else if (d.action === 'raise_po') {
      sets = ['status=?','po_number=?'];
      params = ['PO Raised', d.po_number||''];
    } else if (d.action === 'reject') {
      sets = ['status=?'];
      params = ['Rejected'];
    }

    sets.push("updated_at=datetime('now','localtime')");
    run(`UPDATE material_indents SET ${sets.join(',')} WHERE indent_no=?`, [...params, ind]);
    saveDb();
    const newStatus = params[0]; // first param is always the new status value
    res.json({ ok:true, new_status: newStatus, previous_status: current.status });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// POST /api/indents/:indent_no/issue — issue material from stock against indent
app.post('/api/indents/:indent_no/issue', (req, res) => {
  try {
    const d = req.body;
    const ind = req.params.indent_no;
    const items = d.items || [];
    if (!items.length) return res.status(400).json({ ok:false, error:'No items to issue' });

    items.forEach(it => {
      const stockRow = query('SELECT * FROM stock_items WHERE item_code=?',[it.item_code]);
      if (!stockRow.length) return;
      const stock = stockRow[0];
      const qty   = parseFloat(it.qty_issue)||0;
      const rate  = parseFloat(stock.last_rate)||0;
      const value = qty * rate;
      const newQty = Math.max(0, parseFloat(stock.current_qty) - qty);
      const newVal = Math.max(0, parseFloat(stock.current_value) - value);
      run(`INSERT INTO stock_ledger (item_code,txn_date,txn_type,ref_type,ref_id,indent_no,qty_out,rate,value_out,balance_qty,balance_value,narration,recorded_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [it.item_code, d.issue_date||new Date().toISOString().slice(0,10), 'Issue',
         'Indent', ind, ind, qty, rate, value, newQty, newVal,
         `Issued against ${ind} — ${it.narration||''}`, d.issued_by||'']);
      run('UPDATE stock_items SET current_qty=?,current_value=?,updated_at=datetime(\'now\',\'localtime\') WHERE item_code=?',
        [newQty, newVal, it.item_code]);
      run('UPDATE indent_items SET qty_issued=qty_issued+? WHERE indent_no=? AND item_code=?',
        [qty, ind, it.item_code]);
    });
    saveDb();
    res.json({ ok:true, issued: items.length });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// GET /api/stock-alerts — items below reorder level
app.get('/api/stock-alerts', (req, res) => {
  try {
    const alerts = query(`SELECT * FROM stock_items WHERE is_active=1 AND reorder_qty>0 AND current_qty<=reorder_qty ORDER BY (current_qty/reorder_qty) ASC`);
    res.json({ ok:true, alerts });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// GET /api/stock-items/seed-defaults — seed the 5 starting categories if empty
app.post('/api/stock-items/seed', (req, res) => {
  try {
    const existing = query('SELECT COUNT(*) as cnt FROM stock_items');
    if (existing[0].cnt > 0) return res.json({ ok:true, msg:'Already has items', seeded:0 });
    const defaults = [
      { item_code:'RMC-M20',   item_name:'Concrete M20 — Ready Mix',         category:'Concrete',   unit:'Cu.M',     reorder_qty:50,   last_rate:5800 },
      { item_code:'RMC-M25',   item_name:'Concrete M25 — Ready Mix',         category:'Concrete',   unit:'Cu.M',     reorder_qty:50,   last_rate:6200 },
      { item_code:'RMC-M30',   item_name:'Concrete M30 — Ready Mix',         category:'Concrete',   unit:'Cu.M',     reorder_qty:30,   last_rate:6800 },
      { item_code:'STL-TMT8',  item_name:'TMT Steel 8mm Fe500D',             category:'Steel',      unit:'MT',       reorder_qty:5,    last_rate:58000 },
      { item_code:'STL-TMT12', item_name:'TMT Steel 12mm Fe500D',            category:'Steel',      unit:'MT',       reorder_qty:5,    last_rate:57000 },
      { item_code:'STL-TMT16', item_name:'TMT Steel 16mm Fe500D',            category:'Steel',      unit:'MT',       reorder_qty:5,    last_rate:56500 },
      { item_code:'STL-TMT20', item_name:'TMT Steel 20mm Fe500D',            category:'Steel',      unit:'MT',       reorder_qty:3,    last_rate:56000 },
      { item_code:'PLY-12MM',  item_name:'Shuttering Plywood 12mm (8x4)',    category:'Plywood',    unit:'Nos',      reorder_qty:100,  last_rate:1050 },
      { item_code:'PLY-18MM',  item_name:'Shuttering Plywood 18mm (8x4)',    category:'Plywood',    unit:'Nos',      reorder_qty:50,   last_rate:1450 },
      { item_code:'BRK-RED',   item_name:'Red Bricks (Class A)',             category:'Bricks',     unit:'Nos',      reorder_qty:5000, last_rate:8 },
      { item_code:'BRK-AAC',   item_name:'AAC Blocks 600x200x150',          category:'Bricks',     unit:'Nos',      reorder_qty:1000, last_rate:52 },
      { item_code:'CEM-OPC',   item_name:'Cement OPC 53 Grade (50kg bag)',   category:'Aggregate',  unit:'Bags',     reorder_qty:200,  last_rate:380 },
      { item_code:'SND-MSND',  item_name:'M-Sand (Manufactured Sand)',       category:'Aggregate',  unit:'Cu.M',     reorder_qty:20,   last_rate:1800 },
      { item_code:'AGG-20MM',  item_name:'Aggregate 20mm Crushed Stone',     category:'Aggregate',  unit:'Cu.M',     reorder_qty:20,   last_rate:1400 },
      { item_code:'AGG-10MM',  item_name:'Aggregate 10mm Crushed Stone',     category:'Aggregate',  unit:'Cu.M',     reorder_qty:10,   last_rate:1600 },
    ];
    defaults.forEach(d => {
      run(`INSERT OR IGNORE INTO stock_items (item_code,item_name,category,unit,reorder_qty,last_rate) VALUES (?,?,?,?,?,?)`,
        [d.item_code, d.item_name, d.category, d.unit, d.reorder_qty, d.last_rate]);
    });
    saveDb();
    res.json({ ok:true, seeded: defaults.length });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});
