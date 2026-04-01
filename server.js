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
const sessions = new Map(); // token → { dept, expiresAt }
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

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
  for (const [tok, s] of sessions) {
    if (s.expiresAt < now) sessions.delete(tok);
  }
}, 60 * 60 * 1000);

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

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,X-Auth-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE — applies to all /api/* routes ──
// Exempt paths (login, logout, me, health) bypass the check inside requireAuth.
app.use('/api', requireAuth);

let db;

function saveDb() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err) {
    if (err.code === 'EPERM' || err.code === 'EACCES') {
      console.error('═══════════════════════════════════════════════════════');
      console.error('  DATABASE WRITE ERROR — PERMISSION DENIED');
      console.error('  Path:', DB_PATH);
      console.error('');
      console.error('  Fix: Move the tqs-merged folder out of any protected');
      console.error('  location (e.g. Downloads, Program Files, OneDrive).');
      console.error('  Recommended: Place it in C:\\TQS-Server\\');
      console.error('  Then re-run START_SERVER.bat from the new location.');
      console.error('═══════════════════════════════════════════════════════');
    }
    throw err;
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
  try { run("ALTER TABLE purchase_orders ADD COLUMN form_no TEXT DEFAULT 'BCIM-PUR-F-03'"); } catch(e){}


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
}

// ── AUTH ENDPOINTS ──

// POST /api/auth/login — verify email + password + project, return session token
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password, project_id } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }
    if (!project_id) {
      return res.status(400).json({ ok: false, error: 'Please select a project to continue' });
    }
    const projectRows = query('SELECT * FROM projects WHERE id=? AND is_active=1', [project_id]);
    if (!projectRows.length) {
      return res.status(400).json({ ok: false, error: 'Invalid or inactive project' });
    }
    const project = projectRows[0];
    const rows = query('SELECT * FROM users WHERE LOWER(email)=LOWER(?) AND is_active=1', [email.trim()]);
    if (!rows.length || !verifyPassword(password, rows[0].salt, rows[0].password_hash)) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }
    const user = rows[0];
    // Check project access (admin can access all projects)
    if (user.dept !== 'admin') {
      const access = query('SELECT 1 FROM user_projects WHERE user_id=? AND project_id=?', [user.id, project.id]);
      if (!access.length) {
        return res.status(403).json({ ok: false, error: `You don't have access to ${project.name}` });
      }
    }
    const token = generateToken();
    sessions.set(token, {
      dept: user.dept, userId: user.id, name: user.name, email: user.email,
      projectId: project.id, projectName: project.name,
      expiresAt: Date.now() + SESSION_TTL_MS
    });
    res.json({ ok: true, token, dept: user.dept, name: user.name, email: user.email, userId: user.id,
               projectId: project.id, projectName: project.name });
  } catch (err) {
    console.error('[Login error]', err.message);
    res.status(500).json({ ok: false, error: 'Server error: ' + err.message });
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
    const qParams = [req.projectId || 0];
    let typeFilter = '';
    if (trackerType) { typeFilter = 'AND b.tracker_type = ?'; qParams.push(trackerType); }
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
    `, qParams);
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
    res.json({ ok: true, bills });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /api/bills
app.post('/api/bills', (req, res) => {
  try {
    const d = req.body;
    if (!d.vendor) return res.status(400).json({ ok: false, error: 'vendor required' });

    // Duplicate invoice number check — skip if ?force=1
    if (d.inv_number && d.inv_number.trim() && req.query.force !== '1') {
      const dup = query(
        'SELECT sl FROM bills WHERE LOWER(TRIM(inv_number))=LOWER(TRIM(?)) AND LOWER(TRIM(vendor))=LOWER(TRIM(?)) AND is_deleted=0',
        [d.inv_number, d.vendor]
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

    const maxRow = query('SELECT MAX(CAST(sl AS REAL)) as m FROM bills');
    const sl = String(Math.floor((maxRow[0].m || 0)) + 1);
    const ttype = d.tracker_type === 'wo' ? 'wo' : 'po';
    run(`INSERT INTO bills (sl,vendor,po_number,po_date,inv_number,inv_date,inv_month,
         received_date,basic_amount,gst_amount,total_amount,credit_note_num,credit_note_val,remarks,tracker_type,project_id,is_new)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)`,
      [sl,d.vendor,d.po_number||'',d.po_date||'',d.inv_number||'',
       d.inv_date||'',d.inv_month||'',d.received_date||'',
       d.basic_amount||0,d.gst_amount||0,d.total_amount||0,
       d.credit_note_num||'',d.credit_note_val||0,d.remarks||'',ttype,
       req.projectId||0]);
    run('INSERT OR IGNORE INTO bill_updates (sl) VALUES (?)', [sl]);
    if (d.dept) run('INSERT INTO bill_history (sl,dept,action) VALUES (?,?,?)', [sl,d.dept,'New bill added']);
    saveDb();
    res.json({ ok: true, sl });
  } catch (err) {
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
    const maxRow = query('SELECT MAX(CAST(sl AS REAL)) as m FROM bills');
    let nextSL = Math.floor((maxRow[0].m || 0)) + 1;
    let count = 0;
    for (const d of bills) {
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
    res.json({ ok: true, imported: count });
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

// POST /api/bills/:sl/files — upload file → saved to disk + metadata in DB
app.post('/api/bills/:sl/files', (req, res) => {
  try {
    const { sl } = req.params;
    const { name, size, type, data, uploaded_by } = req.body;
    if (!name || !data) return res.status(400).json({ ok: false, error: 'name and data required' });

    // Ensure uploads directory exists (safety — in case folder was deleted)
    if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

    // Save file to disk: uploads/bills/SL-{sl}/{filename}
    const safeFilename = sanitizeFilename(name);
    const uploadDir    = getBillUploadDir(sl);
    // Add timestamp prefix to avoid collisions
    const diskFilename = `${Date.now()}_${safeFilename}`;
    const filePath     = path.join(uploadDir, diskFilename);

    const base64 = data.includes(',') ? data.split(',')[1] : data;
    fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));

    // Store metadata in DB (no raw base64 data — just the path)
    run(`INSERT INTO bill_files (sl,name,size,type,data,file_path,uploaded_by) VALUES (?,?,?,?,?,?,?)`,
      [sl, name, size||'', type||'', '', filePath, uploaded_by||'']);
    const id = query('SELECT last_insert_rowid() as id')[0].id;
    saveDb();

    console.log(`[Upload] SL#${sl} → ${diskFilename} (${Math.round((size||0)/1024)}KB)`);
    res.json({ ok: true, id, file_path: filePath });
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

function runAutoBackup() {
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
    fs.writeFileSync(filepath, JSON.stringify(backup));

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
  res.json(runAutoBackup());
});

// GET /api/autobackup/download/:filename — download a saved auto-backup
app.get('/api/autobackup/download/:filename', (req, res) => {
  try {
    const filename = path.basename(req.params.filename); // prevent path traversal
    if (!filename.startsWith('TQS_AutoBackup_') || !filename.endsWith('.json')) {
      return res.status(400).json({ ok: false, error: 'Invalid filename' });
    }
    const filepath = path.join(BACKUP_DIR, filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ ok: false, error: 'File not found' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.sendFile(filepath);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
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

    // ── Company defaults ──
    const coName   = S.company_name   || S.company || 'BCIM ENGINEERING PRIVATE LIMITED';
    const coWing   = S.company_wing   || '"B" Wing, Divyasree Chambers.';
    const coAddr   = S.company_addr   || "No. 11, O'Shaugnessy Road, Bangalore - 560025";
    const coGstin  = S.company_gstin  || '29AAHCB6485A1ZL';
    const coFooter = S.company_footer || coName + ', ' + coAddr;
    const formNo   = po.form_no || S.form_no || 'BCIM-PUR-F-03';

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

    // Status machine: Pending Stores → Stores Checked → QS Approved → PM Approved → MD Approved → PO Raised → Closed
    const FLOW = ['Pending Stores','Stores Checked','QS Approved','PM Approved','MD Approved','PO Raised','Closed'];
    const idx = FLOW.indexOf(current.status);

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
    } else {
      return res.status(400).json({ ok:false, error:'Unknown action' });
    }

    sets.push("updated_at=datetime('now','localtime')");
    run(`UPDATE material_indents SET ${sets.join(',')} WHERE indent_no=?`, [...params, ind]);
    saveDb();
    res.json({ ok:true, new_status: params[0] });
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

// ══════════════════════════════════════════════════════
// DASHBOARD & ANALYTICS MODULE
// ══════════════════════════════════════════════════════

// SQL expression to normalise DD-MM-YYYY or YYYY-MM-DD dates to YYYY-MM-DD for julianday()
const SQL_DATE_NORM = `
  CASE
    WHEN {col} LIKE '__-__-____'
    THEN substr({col},7,4)||'-'||substr({col},4,2)||'-'||substr({col},1,2)
    ELSE {col}
  END`;

function normDate(col) {
  return SQL_DATE_NORM.replace(/\{col\}/g, col);
}

// Helper: parse optional date-range & vendor/project filters from query string
function buildBillFilters(req) {
  const conditions = ['b.is_deleted = 0'];
  const params = [];

  // Project scoping (same pattern as /api/bills)
  if (req.projectId) {
    conditions.push('b.project_id = ?');
    params.push(req.projectId);
  }

  // Optional date range on inv_date
  if (req.query.from) { conditions.push("b.inv_date >= ?"); params.push(req.query.from); }
  if (req.query.to)   { conditions.push("b.inv_date <= ?"); params.push(req.query.to); }

  // Optional vendor filter
  if (req.query.vendor) { conditions.push("LOWER(b.vendor) = LOWER(?)"); params.push(req.query.vendor); }

  // Optional tracker_type filter (po / wo)
  if (req.query.type === 'po' || req.query.type === 'wo') {
    conditions.push('b.tracker_type = ?'); params.push(req.query.type);
  }

  // Optional payment_status filter
  if (req.query.status) { conditions.push("LOWER(COALESCE(u.payment_status,'')) = LOWER(?)"); params.push(req.query.status); }

  return { where: conditions.join(' AND '), params };
}

// ── DASHBOARD SUMMARY ──

// GET /api/dashboard/summary — all key metrics in one call
app.get('/api/dashboard/summary', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const base = pid ? 'b.is_deleted=0 AND b.project_id=?' : 'b.is_deleted=0';
    const bp   = pid ? [pid] : [];

    const totals = query(`
      SELECT
        COUNT(*) AS total_bills,
        COALESCE(SUM(b.total_amount),0) AS total_value,
        COALESCE(SUM(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN b.total_amount ELSE 0 END),0) AS paid_value,
        COALESCE(SUM(CASE WHEN COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled') THEN COALESCE(u.balance_to_pay, b.total_amount) ELSE 0 END),0) AS outstanding_amount,
        COALESCE(SUM(COALESCE(u.certified_net,0)),0) AS total_certified,
        COALESCE(SUM(b.gst_amount),0) AS total_gst,
        COUNT(CASE WHEN COALESCE(u.payment_status,'') = '' OR u.sl IS NULL THEN 1 END) AS pending_approval,
        COUNT(CASE WHEN COALESCE(u.payment_status,'') = 'Paid' THEN 1 END) AS paid_count,
        COUNT(CASE WHEN COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled') AND COALESCE(u.payment_status,'') != '' THEN 1 END) AS unpaid_count
      FROM bills b
      LEFT JOIN bill_updates u ON b.sl = u.sl
      WHERE ${base}`, bp);

    const overdue = query(`
      SELECT COUNT(*) AS overdue_bills,
             COALESCE(SUM(COALESCE(u.balance_to_pay,b.total_amount)),0) AS overdue_amount
      FROM bills b
      LEFT JOIN bill_updates u ON b.sl = u.sl
      WHERE ${base}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
        AND b.inv_date != ''
        AND julianday('now') - julianday(
              ${normDate('b.inv_date')}
            ) > 30`, bp);

    const avgPay = query(`
      SELECT AVG(
        julianday(
          ${normDate('u.payment_date')}
        ) -
        julianday(
          ${normDate('b.inv_date')}
        )
      ) AS avg_payment_days
      FROM bills b
      JOIN bill_updates u ON b.sl = u.sl
      WHERE ${base}
        AND u.payment_date != ''
        AND b.inv_date != ''`, bp);

    const stockAlerts = query(`SELECT COUNT(*) AS cnt FROM stock_items WHERE is_active=1 AND reorder_qty>0 AND current_qty<=reorder_qty`);
    const vendorCount = query(`SELECT COUNT(*) AS cnt FROM vendors WHERE is_active=1`);
    const poStats = query(`
      SELECT COUNT(*) AS po_count,
             COALESCE(SUM(po_value),0) AS po_value
      FROM purchase_orders
      WHERE ${pid ? 'project_id=?' : '1=1'}`, pid ? [pid] : []);

    res.json({
      ok: true,
      summary: {
        ...totals[0],
        ...overdue[0],
        avg_payment_days: Math.round((avgPay[0].avg_payment_days || 0) * 10) / 10,
        stock_alerts: stockAlerts[0].cnt,
        active_vendors: vendorCount[0].cnt,
        ...poStats[0],
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/dashboard/metrics — individual metric cards
app.get('/api/dashboard/metrics', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const base = pid ? 'b.is_deleted=0 AND b.project_id=?' : 'b.is_deleted=0';
    const bp   = pid ? [pid] : [];

    const bills = query(`
      SELECT
        COUNT(*) AS total_bills,
        COALESCE(SUM(b.total_amount),0) AS total_value,
        COALESCE(SUM(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN COALESCE(u.paid_amount,0) ELSE 0 END),0) AS total_paid,
        COALESCE(SUM(CASE WHEN COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled') THEN COALESCE(u.balance_to_pay,b.total_amount) ELSE 0 END),0) AS outstanding,
        COALESCE(SUM(COALESCE(u.certified_net,0)),0) AS certified,
        COALESCE(SUM(COALESCE(u.tds_deduction,0)),0) AS total_tds,
        COALESCE(SUM(COALESCE(u.advance_recovered,0)),0) AS total_advance_recovered,
        COUNT(CASE WHEN COALESCE(u.payment_status,'') = '' OR u.sl IS NULL THEN 1 END) AS pending_approval,
        COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS paid_count
      FROM bills b LEFT JOIN bill_updates u ON b.sl = u.sl WHERE ${base}`, bp);

    const overdue30 = query(`
      SELECT COUNT(*) AS cnt,
             COALESCE(SUM(COALESCE(u.balance_to_pay,b.total_amount)),0) AS amt
      FROM bills b LEFT JOIN bill_updates u ON b.sl = u.sl
      WHERE ${base}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
        AND b.inv_date != ''
        AND julianday('now') - julianday(
            ${normDate('b.inv_date')}) > 30`, bp);

    res.json({
      ok: true,
      metrics: {
        total_bills:            { value: bills[0].total_bills,     label: 'Total Bills' },
        total_value:            { value: bills[0].total_value,     label: 'Total Bill Value (₹)' },
        outstanding:            { value: bills[0].outstanding,     label: 'Outstanding Amount (₹)' },
        certified:              { value: bills[0].certified,       label: 'Total Certified (₹)' },
        total_paid:             { value: bills[0].total_paid,      label: 'Total Paid (₹)' },
        pending_approval:       { value: bills[0].pending_approval,label: 'Bills Pending Approval' },
        overdue_bills:          { value: overdue30[0].cnt,         label: 'Overdue Bills (>30 days)' },
        overdue_amount:         { value: overdue30[0].amt,         label: 'Overdue Amount (₹)' },
        total_tds:              { value: bills[0].total_tds,       label: 'Total TDS Deducted (₹)' },
        total_advance_recovered:{ value: bills[0].total_advance_recovered, label: 'Advance Recovered (₹)' },
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/dashboard/quick-stats — lightweight widget
app.get('/api/dashboard/quick-stats', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const bp  = pid ? [pid] : [];
    const pw  = pid ? 'AND b.project_id=?' : '';

    const r = query(`
      SELECT
        COUNT(*) AS total_bills,
        COALESCE(SUM(b.total_amount),0) AS total_value,
        COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS paid,
        COUNT(CASE WHEN COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled') AND COALESCE(u.payment_status,'')!='' THEN 1 END) AS pending,
        COUNT(CASE WHEN u.sl IS NULL OR COALESCE(u.payment_status,'')='' THEN 1 END) AS new_bills
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}`, bp);
    const alerts = query(`SELECT COUNT(*) AS cnt FROM stock_items WHERE is_active=1 AND reorder_qty>0 AND current_qty<=reorder_qty`);

    res.json({ ok: true, stats: { ...r[0], stock_alerts: alerts[0].cnt } });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── FINANCIAL ANALYTICS ──

// GET /api/analytics/financials — financial summaries
app.get('/api/analytics/financials', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);
    const summary = query(`
      SELECT
        COUNT(*) AS total_bills,
        COALESCE(SUM(b.basic_amount),0) AS total_basic,
        COALESCE(SUM(b.gst_amount),0) AS total_gst,
        COALESCE(SUM(b.transport_charges),0) AS total_transport,
        COALESCE(SUM(b.other_charges),0) AS total_other_charges,
        COALESCE(SUM(b.total_amount),0) AS total_invoice,
        COALESCE(SUM(COALESCE(u.qs_gross,0)),0) AS total_qs_gross,
        COALESCE(SUM(COALESCE(u.certified_net,0)),0) AS total_certified_net,
        COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS total_paid,
        COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS total_balance,
        COALESCE(SUM(COALESCE(u.tds_deduction,0)),0) AS total_tds,
        COALESCE(SUM(COALESCE(u.advance_recovered,0)),0) AS total_advance_recovered,
        COALESCE(SUM(COALESCE(u.retention_money,0)),0) AS total_retention,
        COALESCE(SUM(COALESCE(u.other_deductions,0)),0) AS total_other_deductions,
        COALESCE(SUM(b.cgst_amt),0) AS total_cgst,
        COALESCE(SUM(b.sgst_amt),0) AS total_sgst,
        COALESCE(SUM(b.igst_amt),0) AS total_igst
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}`, params);

    const poSummary = query(`
      SELECT COUNT(*) AS po_count,
             COALESCE(SUM(po_value),0) AS total_po_value,
             COUNT(CASE WHEN status='Closed' THEN 1 END) AS closed_pos,
             COUNT(CASE WHEN status='Active' THEN 1 END) AS active_pos
      FROM purchase_orders
      WHERE ${req.projectId ? 'project_id=?' : '1=1'}`,
      req.projectId ? [req.projectId] : []);

    res.json({ ok: true, financials: summary[0], po_summary: poSummary[0] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/monthly-trends — last 12 months of bill data
app.get('/api/analytics/monthly-trends', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    // Bills created per month (last 12 months)
    const trends = query(`
      SELECT
        strftime('%Y-%m', b.created_at) AS month,
        COUNT(*) AS bill_count,
        COALESCE(SUM(b.total_amount),0) AS total_value,
        COALESCE(SUM(b.basic_amount),0) AS basic_value,
        COALESCE(SUM(b.gst_amount),0) AS gst_value,
        COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS paid_value
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND b.created_at >= date('now','-12 months')
      GROUP BY month
      ORDER BY month ASC`, pp);

    // Invoice month trends (by inv_month or derived from inv_date)
    const invTrends = query(`
      SELECT
        CASE
          WHEN b.inv_date LIKE '____-__-%' THEN substr(b.inv_date,1,7)
          WHEN b.inv_date LIKE '__-__-____' THEN substr(b.inv_date,7,4)||'-'||substr(b.inv_date,4,2)
          ELSE 'Unknown'
        END AS inv_month,
        COUNT(*) AS bill_count,
        COALESCE(SUM(b.total_amount),0) AS total_value
      FROM bills b
      WHERE b.is_deleted=0 ${pw} AND b.inv_date != ''
        AND (
          (b.inv_date LIKE '____-__-%' AND b.inv_date >= date('now','-12 months'))
          OR
          (b.inv_date LIKE '__-__-____' AND
            substr(b.inv_date,7,4)||'-'||substr(b.inv_date,4,2) >= strftime('%Y-%m', date('now','-12 months')))
        )
      GROUP BY inv_month
      ORDER BY inv_month ASC`, pp);

    res.json({ ok: true, monthly_trends: trends, invoice_trends: invTrends });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/payment-status — payment status breakdown
app.get('/api/analytics/payment-status', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const breakdown = query(`
      SELECT
        CASE
          WHEN u.sl IS NULL OR COALESCE(u.payment_status,'') = '' THEN 'Not Started'
          ELSE u.payment_status
        END AS status,
        COUNT(*) AS count,
        COALESCE(SUM(b.total_amount),0) AS total_value,
        COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS paid_amount,
        COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS balance
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
      GROUP BY status
      ORDER BY count DESC`, pp);

    res.json({ ok: true, payment_status: breakdown });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/gst-summary — GST analytics
app.get('/api/analytics/gst-summary', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);
    const gst = query(`
      SELECT
        COALESCE(SUM(b.gst_amount),0) AS total_gst,
        COALESCE(SUM(b.cgst_amt),0) AS total_cgst,
        COALESCE(SUM(b.sgst_amt),0) AS total_sgst,
        COALESCE(SUM(b.igst_amt),0) AS total_igst,
        COALESCE(SUM(b.basic_amount),0) AS total_basic,
        COUNT(CASE WHEN b.cgst_amt > 0 THEN 1 END) AS cgst_bills,
        COUNT(CASE WHEN b.igst_amt > 0 THEN 1 END) AS igst_bills,
        COUNT(CASE WHEN b.gst_amount = 0 THEN 1 END) AS zero_gst_bills
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}`, params);

    // GST by vendor (top 10)
    const byVendor = query(`
      SELECT b.vendor,
             COALESCE(SUM(b.gst_amount),0) AS gst_total,
             COALESCE(SUM(b.total_amount),0) AS invoice_total,
             COUNT(*) AS bill_count
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      GROUP BY b.vendor
      ORDER BY gst_total DESC
      LIMIT 10`, params);

    res.json({ ok: true, gst_summary: gst[0], gst_by_vendor: byVendor });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── BILL ANALYTICS ──

// GET /api/analytics/bill-aging — aging report (0-30, 30-60, 60-90, 90+ days)
app.get('/api/analytics/bill-aging', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const aging = query(`
      SELECT
        CASE
          WHEN age <= 30  THEN '0-30 days'
          WHEN age <= 60  THEN '31-60 days'
          WHEN age <= 90  THEN '61-90 days'
          ELSE '90+ days'
        END AS bucket,
        COUNT(*) AS bill_count,
        COALESCE(SUM(total_amount),0) AS total_value,
        COALESCE(SUM(balance),0) AS outstanding
      FROM (
        SELECT b.total_amount,
               COALESCE(u.balance_to_pay, b.total_amount) AS balance,
               CAST(julianday('now') - julianday(
                 ${normDate('b.inv_date')}
               ) AS INTEGER) AS age
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE b.is_deleted=0 ${pw}
          AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
          AND b.inv_date != ''
      ) t
      GROUP BY bucket
      ORDER BY
        CASE bucket
          WHEN '0-30 days'  THEN 1
          WHEN '31-60 days' THEN 2
          WHEN '61-90 days' THEN 3
          ELSE 4
        END`, pp);

    // Detailed list of overdue bills (>30 days)
    const overdueList = query(`
      SELECT b.sl, b.vendor, b.inv_number, b.inv_date, b.total_amount,
             COALESCE(u.balance_to_pay, b.total_amount) AS balance,
             COALESCE(u.payment_status,'Pending') AS payment_status,
             CAST(julianday('now') - julianday(
               ${normDate('b.inv_date')}
             ) AS INTEGER) AS age_days
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
        AND b.inv_date != ''
        AND julianday('now') - julianday(
          ${normDate('b.inv_date')}) > 30
      ORDER BY age_days DESC
      LIMIT 50`, pp);

    res.json({ ok: true, aging_buckets: aging, overdue_bills: overdueList });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/top-vendors — vendor rankings by bill count & value
app.get('/api/analytics/top-vendors', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 10), 50);

    const byValue = query(`
      SELECT b.vendor,
             COUNT(*) AS bill_count,
             COALESCE(SUM(b.total_amount),0) AS total_value,
             COALESCE(SUM(b.basic_amount),0) AS basic_value,
             COALESCE(SUM(b.gst_amount),0) AS gst_value,
             COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS paid_amount,
             COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS balance,
             COALESCE(AVG(b.total_amount),0) AS avg_invoice
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      GROUP BY b.vendor
      ORDER BY total_value DESC
      LIMIT ?`, [...params, limit]);

    res.json({ ok: true, top_vendors: byValue });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/top-projects — project spending
app.get('/api/analytics/top-projects', (req, res) => {
  try {
    const rows = query(`
      SELECT p.id, p.name, p.code,
             COUNT(b.sl) AS bill_count,
             COALESCE(SUM(b.total_amount),0) AS total_value,
             COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS paid_amount,
             COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS balance
      FROM projects p
      LEFT JOIN bills b ON b.project_id=p.id AND b.is_deleted=0
      LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE p.is_active=1
      GROUP BY p.id
      ORDER BY total_value DESC`);
    res.json({ ok: true, projects: rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/processing-time — bill processing time metrics
app.get('/api/analytics/processing-time', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const times = query(`
      SELECT
        AVG(CASE WHEN u.store_handover_date!='' AND b.received_date!=''
            THEN julianday(
              ${normDate('u.store_handover_date')})
            - julianday(
              ${normDate('b.received_date')})
            END) AS avg_store_to_handover_days,
        AVG(CASE WHEN u.qs_certified_date!='' AND u.qs_received_date!=''
            THEN julianday(
              ${normDate('u.qs_certified_date')})
            - julianday(
              ${normDate('u.qs_received_date')})
            END) AS avg_qs_cert_days,
        AVG(CASE WHEN u.payment_date!='' AND b.inv_date!=''
            THEN julianday(
              ${normDate('u.payment_date')})
            - julianday(
              ${normDate('b.inv_date')})
            END) AS avg_payment_days,
        AVG(CASE WHEN u.mgmt_approval_date!='' AND u.proc_date!=''
            THEN julianday(
              ${normDate('u.mgmt_approval_date')})
            - julianday(
              ${normDate('u.proc_date')})
            END) AS avg_approval_days
      FROM bills b JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}`, pp);

    const r = times[0];
    res.json({
      ok: true,
      processing_times: {
        avg_store_to_handover_days: Math.round((r.avg_store_to_handover_days || 0) * 10) / 10,
        avg_qs_cert_days:           Math.round((r.avg_qs_cert_days || 0) * 10) / 10,
        avg_payment_days:           Math.round((r.avg_payment_days || 0) * 10) / 10,
        avg_approval_days:          Math.round((r.avg_approval_days || 0) * 10) / 10,
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── VENDOR ANALYTICS ──

// GET /api/analytics/vendor-performance — vendor scorecard
app.get('/api/analytics/vendor-performance', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);

    const perf = query(`
      SELECT b.vendor,
             COUNT(*) AS total_bills,
             COALESCE(SUM(b.total_amount),0) AS total_spend,
             COALESCE(AVG(b.total_amount),0) AS avg_invoice,
             COUNT(CASE WHEN COALESCE(u.shortage_flag,0)=1 THEN 1 END) AS shortage_count,
             COUNT(CASE WHEN COALESCE(u.inspection_status,'')='Rejected' THEN 1 END) AS rejection_count,
             COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS paid_bills,
             COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS total_paid,
             COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS total_balance,
             COALESCE(SUM(b.gst_amount),0) AS total_gst
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      GROUP BY b.vendor
      ORDER BY total_spend DESC
      LIMIT ?`, [...params, limit]);

    // Compute on-time rate
    const result = perf.map(v => ({
      ...v,
      on_time_rate: v.total_bills > 0
        ? Math.round(((v.total_bills - v.shortage_count - v.rejection_count) / v.total_bills) * 100)
        : 100,
      payment_rate: v.total_bills > 0
        ? Math.round((v.paid_bills / v.total_bills) * 100)
        : 0,
    }));

    res.json({ ok: true, vendor_performance: result });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/vendor/:id/stats — individual vendor stats
app.get('/api/analytics/vendor/:id/stats', (req, res) => {
  try {
    const vendorId = parseInt(req.params.id);
    const vendor = query(`SELECT * FROM vendors WHERE id=?`, [vendorId]);
    if (!vendor.length) return res.status(404).json({ ok: false, error: 'Vendor not found' });

    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const stats = query(`
      SELECT
        COUNT(*) AS total_bills,
        COALESCE(SUM(b.total_amount),0) AS total_spend,
        COALESCE(SUM(b.basic_amount),0) AS total_basic,
        COALESCE(SUM(b.gst_amount),0) AS total_gst,
        COALESCE(AVG(b.total_amount),0) AS avg_invoice,
        COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS total_paid,
        COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS total_balance,
        COALESCE(SUM(COALESCE(u.tds_deduction,0)),0) AS total_tds,
        COUNT(CASE WHEN COALESCE(u.shortage_flag,0)=1 THEN 1 END) AS shortages,
        COUNT(CASE WHEN COALESCE(u.inspection_status,'')='Rejected' THEN 1 END) AS rejections,
        COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS paid_count
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 AND LOWER(b.vendor)=LOWER(?) ${pw}`,
      [vendor[0].name, ...pp]);

    const monthlyTrend = query(`
      SELECT strftime('%Y-%m', b.created_at) AS month,
             COUNT(*) AS bill_count,
             COALESCE(SUM(b.total_amount),0) AS value
      FROM bills b
      WHERE b.is_deleted=0 AND LOWER(b.vendor)=LOWER(?) ${pw}
        AND b.created_at >= date('now','-12 months')
      GROUP BY month ORDER BY month ASC`,
      [vendor[0].name, ...pp]);

    res.json({
      ok: true,
      vendor: vendor[0],
      stats: stats[0],
      monthly_trend: monthlyTrend,
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── APPROVAL ANALYTICS ──

// GET /api/analytics/approval-metrics — approval statistics
app.get('/api/analytics/approval-metrics', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const stages = query(`
      SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN u.sl IS NULL THEN 1 END) AS at_entry,
        COUNT(CASE WHEN u.sl IS NOT NULL AND COALESCE(u.store_handover_date,'')='' THEN 1 END) AS at_stores,
        COUNT(CASE WHEN COALESCE(u.store_handover_date,'')!='' AND COALESCE(u.qs_received_date,'')='' THEN 1 END) AS at_doc_ctrl,
        COUNT(CASE WHEN COALESCE(u.qs_received_date,'')!='' AND COALESCE(u.qs_certified_date,'')='' THEN 1 END) AS at_qs,
        COUNT(CASE WHEN COALESCE(u.qs_certified_date,'')!='' AND COALESCE(u.proc_date,'')='' THEN 1 END) AS at_procurement,
        COUNT(CASE WHEN COALESCE(u.proc_date,'')!='' AND COALESCE(u.mgmt_approval_date,'')='' THEN 1 END) AS awaiting_mgmt,
        COUNT(CASE WHEN COALESCE(u.mgmt_approval_date,'')!='' AND COALESCE(u.accts_jv_date,'')='' THEN 1 END) AS at_accounts,
        COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS completed
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}`, pp);

    const approval_rate = stages[0].total > 0
      ? Math.round((stages[0].completed / stages[0].total) * 100)
      : 0;

    res.json({ ok: true, approval_stages: stages[0], approval_rate });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/approval-bottlenecks — workflow bottleneck identification
app.get('/api/analytics/approval-bottlenecks', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    // Bills stuck at each stage for > 7 days
    const stuck = query(`
      SELECT
        'Stores Handover' AS stage,
        COUNT(*) AS stuck_count,
        AVG(julianday('now') - julianday(b.created_at)) AS avg_wait_days
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND u.sl IS NOT NULL
        AND COALESCE(u.store_handover_date,'')=''
        AND julianday('now') - julianday(b.created_at) > 7
      UNION ALL
      SELECT
        'QS Certification' AS stage,
        COUNT(*) AS stuck_count,
        AVG(julianday('now') - julianday(
          ${normDate('u.qs_received_date')})) AS avg_wait_days
      FROM bills b JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.qs_received_date,'')!=''
        AND COALESCE(u.qs_certified_date,'')=''
        AND julianday('now') - julianday(
          ${normDate('u.qs_received_date')}) > 7
      UNION ALL
      SELECT
        'Management Approval' AS stage,
        COUNT(*) AS stuck_count,
        AVG(julianday('now') - julianday(
          ${normDate('u.proc_date')})) AS avg_wait_days
      FROM bills b JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.proc_date,'')!=''
        AND COALESCE(u.mgmt_approval_date,'')=''
        AND julianday('now') - julianday(
          ${normDate('u.proc_date')}) > 7`, [...pp, ...pp, ...pp]);

    res.json({
      ok: true,
      bottlenecks: stuck.map(s => ({
        ...s,
        avg_wait_days: Math.round((s.avg_wait_days || 0) * 10) / 10
      }))
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/pending-approvals — pending items by stage
app.get('/api/analytics/pending-approvals', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const page    = Math.max(1, parseInt(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.per_page) || 50));
    const offset  = (page - 1) * perPage;

    const pending = query(`
      SELECT b.sl, b.vendor, b.inv_number, b.inv_date, b.total_amount,
             b.tracker_type,
             CASE
               WHEN u.sl IS NULL THEN 'Entry'
               WHEN COALESCE(u.store_handover_date,'')='' THEN 'Stores'
               WHEN COALESCE(u.qs_received_date,'')='' THEN 'Doc Control'
               WHEN COALESCE(u.qs_certified_date,'')='' THEN 'QS Certification'
               WHEN COALESCE(u.proc_date,'')='' THEN 'Procurement'
               WHEN COALESCE(u.mgmt_approval_date,'')='' THEN 'Mgmt Approval'
               WHEN COALESCE(u.accts_jv_date,'')='' THEN 'Accounts'
               ELSE 'Payment Pending'
             END AS pending_stage,
             CAST(julianday('now') - julianday(b.created_at) AS INTEGER) AS age_days
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
      ORDER BY age_days DESC
      LIMIT ? OFFSET ?`, [...pp, perPage, offset]);

    const total = query(`
      SELECT COUNT(*) AS cnt FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')`, pp);

    res.json({
      ok: true,
      pending_approvals: pending,
      pagination: { page, per_page: perPage, total: total[0].cnt }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── CASH FLOW ANALYTICS ──

// GET /api/analytics/cash-flow — projected cash outflow (next 30/60/90 days)
app.get('/api/analytics/cash-flow', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    // Already paid (last 30/60/90 days)
    const paid = query(`
      SELECT
        SUM(CASE WHEN julianday('now') - julianday(
          ${normDate('u.payment_date')}) <= 30 THEN COALESCE(u.paid_amount,0) ELSE 0 END) AS paid_30,
        SUM(CASE WHEN julianday('now') - julianday(
          ${normDate('u.payment_date')}) <= 60 THEN COALESCE(u.paid_amount,0) ELSE 0 END) AS paid_60,
        SUM(CASE WHEN julianday('now') - julianday(
          ${normDate('u.payment_date')}) <= 90 THEN COALESCE(u.paid_amount,0) ELSE 0 END) AS paid_90
      FROM bills b JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw} AND u.payment_date != ''`, pp);

    // Outstanding balance by age bucket (projected outflow)
    const outstanding = query(`
      SELECT
        SUM(CASE WHEN age <= 30 THEN balance ELSE 0 END)  AS due_30,
        SUM(CASE WHEN age <= 60 THEN balance ELSE 0 END)  AS due_60,
        SUM(CASE WHEN age <= 90 THEN balance ELSE 0 END)  AS due_90,
        SUM(balance) AS total_outstanding
      FROM (
        SELECT COALESCE(u.balance_to_pay, b.total_amount) AS balance,
               CAST(julianday('now') - julianday(
                 ${normDate('b.inv_date')}) AS INTEGER) AS age
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE b.is_deleted=0 ${pw}
          AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
          AND b.inv_date != ''
      ) t`, pp);

    // Advance recoveries summary
    const advances = query(`
      SELECT COALESCE(SUM(COALESCE(u.advance_recovered,0)),0) AS total_advance_recovered
      FROM bills b JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}`, pp);

    res.json({
      ok: true,
      cash_flow: {
        paid_last_30_days: paid[0].paid_30 || 0,
        paid_last_60_days: paid[0].paid_60 || 0,
        paid_last_90_days: paid[0].paid_90 || 0,
        outstanding_due_30: outstanding[0].due_30 || 0,
        outstanding_due_60: outstanding[0].due_60 || 0,
        outstanding_due_90: outstanding[0].due_90 || 0,
        total_outstanding:  outstanding[0].total_outstanding || 0,
        total_advance_recovered: advances[0].total_advance_recovered || 0,
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/payment-calendar — bills with due dates
app.get('/api/analytics/payment-calendar', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    // Unpaid bills sorted by invoice age
    const calendar = query(`
      SELECT b.sl, b.vendor, b.inv_number, b.inv_date, b.total_amount,
             COALESCE(u.balance_to_pay, b.total_amount) AS balance,
             COALESCE(u.payment_status,'Pending') AS payment_status,
             COALESCE(u.payment_cert,'') AS payment_cert,
             CAST(julianday('now') - julianday(
               ${normDate('b.inv_date')}) AS INTEGER) AS age_days
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
        AND b.inv_date != ''
      ORDER BY age_days DESC
      LIMIT 100`, pp);

    res.json({ ok: true, payment_calendar: calendar });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── PO & INVENTORY ANALYTICS ──

// GET /api/analytics/po-utilization — PO utilization rate
app.get('/api/analytics/po-utilization', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND po.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const util = query(`
      SELECT po.po_number, po.vendor, po.po_value, po.status,
             COALESCE(SUM(b.total_amount),0) AS billed_value,
             COALESCE(SUM(g.grn_value),0) AS grn_value,
             po.po_value - COALESCE(SUM(b.total_amount),0) AS balance_po
      FROM purchase_orders po
      LEFT JOIN bills b ON b.po_number=po.po_number AND b.is_deleted=0
      LEFT JOIN grn_entries g ON g.po_number=po.po_number
      WHERE 1=1 ${pw}
      GROUP BY po.po_number
      ORDER BY po.po_value DESC
      LIMIT 50`, pp);

    const summary = query(`
      SELECT
        COUNT(*) AS total_pos,
        COALESCE(SUM(po.po_value),0) AS total_po_value,
        COALESCE(SUM(COALESCE(bv.billed,0)),0) AS total_billed,
        COALESCE(SUM(po.po_value - COALESCE(bv.billed,0)),0) AS total_balance
      FROM purchase_orders po
      LEFT JOIN (
        SELECT po_number, SUM(total_amount) AS billed
        FROM bills WHERE is_deleted=0
        GROUP BY po_number
      ) bv ON bv.po_number=po.po_number
      WHERE 1=1 ${pw}`, pp);

    res.json({ ok: true, po_utilization: util, summary: summary[0] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/analytics/stock-overview — stock levels & reorder alerts
app.get('/api/analytics/stock-overview', (req, res) => {
  try {
    const items = query(`
      SELECT item_code, item_name, category, unit,
             current_qty, current_value, reorder_qty, last_rate,
             CASE WHEN reorder_qty>0 AND current_qty<=reorder_qty THEN 1 ELSE 0 END AS needs_reorder
      FROM stock_items WHERE is_active=1
      ORDER BY needs_reorder DESC, category ASC, item_name ASC`);

    const summary = query(`
      SELECT
        COUNT(*) AS total_items,
        COUNT(CASE WHEN reorder_qty>0 AND current_qty<=reorder_qty THEN 1 END) AS reorder_alerts,
        COALESCE(SUM(current_value),0) AS total_stock_value,
        COUNT(DISTINCT category) AS categories
      FROM stock_items WHERE is_active=1`);

    res.json({ ok: true, stock_overview: items, summary: summary[0] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── REPORTS GENERATION ──

// GET /api/reports/bill-summary — bill summary report (JSON, ready for export)
app.get('/api/reports/bill-summary', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);

    const bills = query(`
      SELECT b.sl, b.vendor, b.po_number, b.inv_number, b.inv_date,
             b.basic_amount, b.gst_amount, b.total_amount, b.tracker_type,
             b.created_at,
             COALESCE(u.payment_status,'Pending') AS payment_status,
             COALESCE(u.certified_net,0) AS certified_net,
             COALESCE(u.paid_amount,0) AS paid_amount,
             COALESCE(u.balance_to_pay,0) AS balance_to_pay,
             COALESCE(u.payment_date,'') AS payment_date,
             COALESCE(u.qs_certified_date,'') AS qs_certified_date,
             COALESCE(u.tds_deduction,0) AS tds_deduction,
             COALESCE(u.advance_recovered,0) AS advance_recovered
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      ORDER BY CAST(b.sl AS REAL) ASC`, params);

    const totals = {
      total_bills:    bills.length,
      total_basic:    bills.reduce((s, b) => s + (b.basic_amount || 0), 0),
      total_gst:      bills.reduce((s, b) => s + (b.gst_amount || 0), 0),
      total_invoice:  bills.reduce((s, b) => s + (b.total_amount || 0), 0),
      total_certified:bills.reduce((s, b) => s + (b.certified_net || 0), 0),
      total_paid:     bills.reduce((s, b) => s + (b.paid_amount || 0), 0),
      total_balance:  bills.reduce((s, b) => s + (b.balance_to_pay || 0), 0),
      total_tds:      bills.reduce((s, b) => s + (b.tds_deduction || 0), 0),
    };

    res.json({ ok: true, report: { bills, totals, generated_at: new Date().toISOString() } });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/reports/vendor-performance — vendor performance report
app.get('/api/reports/vendor-performance', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);

    const vendors = query(`
      SELECT b.vendor,
             COUNT(*) AS total_bills,
             COALESCE(SUM(b.total_amount),0) AS total_spend,
             COALESCE(AVG(b.total_amount),0) AS avg_invoice,
             COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS total_paid,
             COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS total_balance,
             COALESCE(SUM(COALESCE(u.tds_deduction,0)),0) AS total_tds,
             COUNT(CASE WHEN COALESCE(u.shortage_flag,0)=1 THEN 1 END) AS shortages,
             COUNT(CASE WHEN COALESCE(u.inspection_status,'')='Rejected' THEN 1 END) AS rejections,
             COUNT(CASE WHEN COALESCE(u.payment_status,'')='Paid' THEN 1 END) AS paid_count,
             COALESCE(SUM(b.gst_amount),0) AS total_gst
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      GROUP BY b.vendor
      ORDER BY total_spend DESC`, params);

    res.json({
      ok: true,
      report: {
        vendors: vendors.map(v => ({
          ...v,
          payment_rate: v.total_bills > 0 ? Math.round((v.paid_count / v.total_bills) * 100) : 0,
        })),
        generated_at: new Date().toISOString(),
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/reports/cash-flow-forecast — cash flow forecast report
app.get('/api/reports/cash-flow-forecast', (req, res) => {
  try {
    const pid = req.projectId || 0;
    const pw  = pid ? 'AND b.project_id=?' : '';
    const pp  = pid ? [pid] : [];

    const outstanding = query(`
      SELECT b.sl, b.vendor, b.inv_number, b.inv_date,
             b.total_amount,
             COALESCE(u.balance_to_pay, b.total_amount) AS balance,
             COALESCE(u.certified_net, 0) AS certified,
             COALESCE(u.payment_status,'Pending') AS payment_status,
             CAST(julianday('now') - julianday(
               ${normDate('b.inv_date')}) AS INTEGER) AS age_days
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE b.is_deleted=0 ${pw}
        AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
        AND b.inv_date != ''
      ORDER BY age_days DESC`, pp);

    const buckets = { due_0_30: 0, due_31_60: 0, due_61_90: 0, due_90_plus: 0 };
    outstanding.forEach(b => {
      const age = b.age_days || 0;
      if (age <= 30)       buckets.due_0_30   += b.balance;
      else if (age <= 60)  buckets.due_31_60  += b.balance;
      else if (age <= 90)  buckets.due_61_90  += b.balance;
      else                 buckets.due_90_plus += b.balance;
    });

    res.json({
      ok: true,
      report: {
        forecast_buckets: buckets,
        total_outstanding: outstanding.reduce((s, b) => s + (b.balance || 0), 0),
        outstanding_bills: outstanding,
        generated_at: new Date().toISOString(),
      }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/reports/compliance — compliance report (GST, TDS)
app.get('/api/reports/compliance', (req, res) => {
  try {
    const { where, params } = buildBillFilters(req);

    const gst = query(`
      SELECT b.vendor, b.inv_number, b.inv_date,
             b.basic_amount, b.gst_amount, b.total_amount,
             b.cgst_amt, b.sgst_amt, b.igst_amt,
             b.cgst_pct, b.sgst_pct, b.igst_pct,
             COALESCE(u.tds_deduction,0) AS tds_deduction,
             COALESCE(u.payment_status,'Pending') AS payment_status
      FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
      WHERE ${where}
      ORDER BY CAST(b.sl AS REAL) ASC`, params);

    const totals = {
      total_bills:   gst.length,
      total_basic:   gst.reduce((s, b) => s + (b.basic_amount || 0), 0),
      total_cgst:    gst.reduce((s, b) => s + (b.cgst_amt || 0), 0),
      total_sgst:    gst.reduce((s, b) => s + (b.sgst_amt || 0), 0),
      total_igst:    gst.reduce((s, b) => s + (b.igst_amt || 0), 0),
      total_gst:     gst.reduce((s, b) => s + (b.gst_amount || 0), 0),
      total_tds:     gst.reduce((s, b) => s + (b.tds_deduction || 0), 0),
    };

    res.json({
      ok: true,
      report: { bills: gst, totals, generated_at: new Date().toISOString() }
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// GET /api/reports/export/:type — export report data as JSON (CSV/PDF handled on frontend)
app.get('/api/reports/export/:type', (req, res) => {
  try {
    const type = req.params.type;
    const { where, params } = buildBillFilters(req);
    const allowed = ['bills', 'vendors', 'compliance', 'cash-flow'];
    if (!allowed.includes(type)) {
      return res.status(400).json({ ok: false, error: 'Invalid export type. Allowed: ' + allowed.join(', ') });
    }

    let data;
    if (type === 'bills') {
      data = query(`
        SELECT b.sl, b.vendor, b.po_number, b.inv_number, b.inv_date,
               b.basic_amount, b.gst_amount, b.total_amount, b.tracker_type,
               b.created_at,
               COALESCE(u.payment_status,'Pending') AS payment_status,
               COALESCE(u.certified_net,0) AS certified_net,
               COALESCE(u.paid_amount,0) AS paid_amount,
               COALESCE(u.balance_to_pay,0) AS balance_to_pay,
               COALESCE(u.tds_deduction,0) AS tds_deduction
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE ${where}
        ORDER BY CAST(b.sl AS REAL) ASC`, params);
    } else if (type === 'vendors') {
      data = query(`
        SELECT b.vendor,
               COUNT(*) AS bill_count,
               COALESCE(SUM(b.total_amount),0) AS total_spend,
               COALESCE(SUM(COALESCE(u.paid_amount,0)),0) AS paid,
               COALESCE(SUM(COALESCE(u.balance_to_pay,0)),0) AS balance
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE ${where}
        GROUP BY b.vendor ORDER BY total_spend DESC`, params);
    } else if (type === 'compliance') {
      data = query(`
        SELECT b.vendor, b.inv_number, b.inv_date, b.basic_amount,
               b.cgst_amt, b.sgst_amt, b.igst_amt, b.gst_amount,
               COALESCE(u.tds_deduction,0) AS tds_deduction,
               COALESCE(u.payment_status,'Pending') AS payment_status
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE ${where}
        ORDER BY CAST(b.sl AS REAL) ASC`, params);
    } else if (type === 'cash-flow') {
      const pid = req.projectId || 0;
      const pw  = pid ? 'AND b.project_id=?' : '';
      const pp  = pid ? [pid] : [];
      data = query(`
        SELECT b.sl, b.vendor, b.inv_number, b.inv_date, b.total_amount,
               COALESCE(u.balance_to_pay, b.total_amount) AS balance,
               COALESCE(u.payment_status,'Pending') AS payment_status,
               CAST(julianday('now') - julianday(
                 ${normDate('b.inv_date')}) AS INTEGER) AS age_days
        FROM bills b LEFT JOIN bill_updates u ON b.sl=u.sl
        WHERE b.is_deleted=0 ${pw}
          AND COALESCE(u.payment_status,'') NOT IN ('Paid','Cancelled')
          AND b.inv_date != ''
        ORDER BY age_days DESC`, pp);
    }

    res.setHeader('Content-Type', 'application/json');
    res.json({ ok: true, type, data, count: data.length, exported_at: new Date().toISOString() });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── STOCK-ITEMS SEED ──

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
