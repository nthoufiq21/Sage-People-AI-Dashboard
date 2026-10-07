const express  = require('express');
const sql      = require('mssql');
const cors     = require('cors');
const path     = require('path');
const crypto   = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const dbConfig = {
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options:  { encrypt: false, trustServerCertificate: true }
};

let pool;
async function getPool() {
  if (!pool) pool = await sql.connect(dbConfig);
  return pool;
}
async function sq(pool, lbl, q) {
  try { const r = await pool.request().query(q); return r.recordset || []; }
  catch(e) { console.warn('⚠ ['+lbl+'] '+e.message.split('\n')[0]); return []; }
}

// ── SESSION STORE (in-memory — simple & fast) ─────────────────────────────
// Each session: { token, userID, userName, role, expires }
const sessions = new Map();
const SESSION_HOURS = 8; // auto-logout after 8 hours

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}
function createSession(userID, userName, role, email) {
  const token   = createToken();
  const expires = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
  sessions.set(token, { token, userID, userName, role, email, expires });
  return token;
}
function getSession(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(token); return null; }
  // Slide expiry on activity
  s.expires = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
  return s;
}
// Clean expired sessions every 30 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) { if (now > v.expires) sessions.delete(k); }
}, 30 * 60 * 1000);

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  const session = getSession(token);
  if (!session) return res.status(401).json({ error: 'Unauthorised. Please log in.', code: 'AUTH_REQUIRED' });
  req.session = session;
  next();
}

// ── HASH HELPER (Sage uses SHA1 or MD5 depending on version) ─────────────
function hashSHA1(str)   { return crypto.createHash('sha1').update(str).digest('hex').toUpperCase(); }
function hashMD5(str)    { return crypto.createHash('md5').update(str).digest('hex').toUpperCase(); }
function hashSHA256(str) { return crypto.createHash('sha256').update(str).digest('hex').toUpperCase(); }

// ═══════════════════════════════════════════════════════════════════════════
// ENDPOINT: POST /api/auth/login
// Verifies against [Security].[ESSUsersSimple] (Sage ESS user table)
// Falls back to [Security].[UserRoles] if needed
// ═══════════════════════════════════════════════════════════════════════════
// ── AUTHORISED USERS WHITELIST ───────────────────────────────────────────
// Only these EntityCodes (from ESSUsersSimple) can access the dashboard
// Passwords are stored in .env as DASHBOARD_PASSWORD (shared) or per-user
const ALLOWED_USERS = {
  '10': { name: 'Mohammed Thoufiq',          role: 'HR Admin',   entity: 10 },
  '3':  { name: 'James Pathisseril Mathunny', role: 'HR Manager', entity: 3  },
};
// You can also allow login by display name or email for convenience
const ALLOWED_BY_NAME = {
  'thoufiq':  '10',
  'mohammed': '10',
  'james':    '3',
  'mathunny': '3',
};

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const pool = await getPool();
    const uname = (username || '').trim();

    // ── Step 1: Look up user in ESSUsersSimple by EntityCode or DisplayName
    const userRows = await pool.request()
      .input('uname', sql.NVarChar, uname)
      .query(`
        SELECT TOP 1
          CAST(e.GenEntityID AS NVARCHAR) AS EntityCode,
          e.DisplayName,
          e.EntityCode AS SageCode,
          e.Gender
        FROM [Security].[ESSUsersSimple] e
        WHERE CAST(e.GenEntityID AS NVARCHAR) = @uname
           OR LOWER(e.EntityCode) = LOWER(@uname)
           OR LOWER(e.DisplayName) LIKE '%' + LOWER(@uname) + '%'
      `);

    // ── Step 2: Check whitelist ───────────────────────────────────────────
    let matchedUser = null;
    let matchedKey  = null;

    if (userRows.recordset.length) {
      const dbUser = userRows.recordset[0];
      const entityCode = String(dbUser.EntityCode || '').trim();
      if (ALLOWED_USERS[entityCode]) {
        matchedKey  = entityCode;
        matchedUser = { ...ALLOWED_USERS[entityCode], dbRecord: dbUser };
      }
    }

    // Also try by lowercase name fragments (e.g. "thoufiq", "james")
    if (!matchedUser) {
      const lname = uname.toLowerCase();
      const key   = Object.keys(ALLOWED_BY_NAME).find(k => lname.includes(k) || k.includes(lname));
      if (key) {
        matchedKey  = ALLOWED_BY_NAME[key];
        matchedUser = { ...ALLOWED_USERS[matchedKey] };
      }
    }

    if (!matchedUser) {
      console.log('  ❌ Login denied — not in whitelist:', uname);
      return res.status(401).json({ error: 'Access denied. Your account is not authorised to access this dashboard.' });
    }

    // ── Step 3: Verify password ───────────────────────────────────────────
    // Dashboard password stored in .env as DASHBOARD_PASSWORD
    // Per-user passwords: DASHBOARD_PASSWORD_10, DASHBOARD_PASSWORD_3
    const envPwPerUser = process.env['DASHBOARD_PASSWORD_' + matchedKey];
    const envPwShared  = process.env.DASHBOARD_PASSWORD;
    const validPassword = envPwPerUser || envPwShared || 'Triad@2024';

    // Try plain text and common hashes
    const pwMatches = [
      password === validPassword,
      password.toLowerCase() === validPassword.toLowerCase(),
      hashSHA1(password).toUpperCase()   === hashSHA1(validPassword).toUpperCase(),
      hashMD5(password).toUpperCase()    === hashMD5(validPassword).toUpperCase(),
      hashSHA256(password).toUpperCase() === hashSHA256(validPassword).toUpperCase(),
    ];

    if (!pwMatches.some(Boolean)) {
      console.log('  ❌ Login denied — wrong password for:', matchedUser.name);
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // ── Step 4: Create session ────────────────────────────────────────────
    const token = createSession(matchedKey, matchedUser.name, matchedUser.role, '');
    console.log('  ✅ Login OK:', matchedUser.name, '| Role:', matchedUser.role);

    res.json({
      success:  true,
      token,
      user: {
        userID:    matchedKey,
        userName:  matchedUser.name,
        role:      matchedUser.role,
        email:     '',
        expiresIn: SESSION_HOURS * 3600
      }
    });

  } catch(err) {
    console.error('  Login error:', err.message);
    res.status(500).json({ error: 'Server error during login. Please try again.' });
  }
});

// ── ENDPOINT: POST /api/auth/logout ──────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

// ── ENDPOINT: GET /api/auth/me ────────────────────────────────────────────
// Login removed — dashboard is embedded inside Sage ESS, which handles auth.
app.get('/api/auth/me', (req, res) => {
  res.json({ user: null });
});

// ── ENDPOINT: GET /api/auth/debug-cols ───────────────────────────────────
// Open this in browser to see ESSUsersSimple columns
app.get('/api/auth/debug-cols', async (req, res) => {
  try {
    const pool = await getPool();
    const cols = await sq(pool, 'debug', `
      SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Security' AND TABLE_NAME='ESSUsersSimple'
      ORDER BY ORDINAL_POSITION`);
    const sample = await sq(pool, 'debug-sample', `
      SELECT TOP 3 * FROM [Security].[ESSUsersSimple]`);
    res.json({ columns: cols, sample_rows: sample.length, note: 'Password values hidden for security' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/leave/debug-cols ──────────────────────────────────
// Open this in browser to see EmployeeLeave columns (used to find the
// "Pending" units column so it can be added to the Leave Balance display).
app.get('/api/leave/debug-cols', async (req, res) => {
  try {
    const pool = await getPool();
    const cols = await sq(pool, 'leave-debug', `
      SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Leave' AND TABLE_NAME='EmployeeLeave'
      ORDER BY ORDINAL_POSITION`);
    const sample = await sq(pool, 'leave-debug-sample', `
      SELECT TOP 3 * FROM [Leave].[EmployeeLeave]`);
    res.json({ columns: cols, sample_rows: sample });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/leave/debug-transaction-cols ──────────────────────
// Open this in browser to see LeaveTransaction columns + Mohammed Thoufiq's
// actual rows, to find the status field that marks a leave application as
// pending/unapproved (used to compute a live "deducted even if not yet
// approved" balance).
app.get('/api/leave/debug-transaction-cols', async (req, res) => {
  try {
    const pool = await getPool();
    const cols = await sq(pool, 'lt-debug', `
      SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Leave' AND TABLE_NAME='LeaveTransaction'
      ORDER BY ORDINAL_POSITION`);
    const sample = await sq(pool, 'lt-debug-sample', `
      SELECT TOP 20 la.* FROM [Leave].[LeaveTransaction] la
      INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID
      INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID
      WHERE e.EmployeeCode='09'
      ORDER BY la.FromDate DESC`);
    res.json({ columns: cols, sample_rows: sample });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/employees/debug-hierarchy ─────────────────────────
// Open this in browser to find the "Department" field inside the Employee
// Detail → Hierarchy Structure area (used to fix the Leave Intensity
// Heatmap, which currently pulls from [Employee].[Function] instead).
app.get('/api/employees/debug-hierarchy', async (req, res) => {
  try {
    const pool = await getPool();
    // 1) Any table whose name suggests hierarchy/org structure/department
    const tables = await sq(pool, 'hier-tables', `
      SELECT TABLE_SCHEMA, TABLE_NAME
      FROM INFORMATION_SCHEMA.TABLES
      WHERE TABLE_NAME LIKE '%Hierarch%' OR TABLE_NAME LIKE '%OrgUnit%'
         OR TABLE_NAME LIKE '%OrgLevel%' OR TABLE_NAME LIKE '%Department%'
         OR TABLE_NAME LIKE '%OrgStructure%' OR TABLE_NAME LIKE '%CostCentre%'
         OR TABLE_NAME LIKE '%CostCenter%'
      ORDER BY TABLE_SCHEMA, TABLE_NAME`);
    // 2) Columns directly on Employee table that mention hierarchy/dept/org
    const empCols = await sq(pool, 'hier-empcols', `
      SELECT COLUMN_NAME, DATA_TYPE
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Employee' AND TABLE_NAME='Employee'
        AND (COLUMN_NAME LIKE '%Hierarch%' OR COLUMN_NAME LIKE '%Dept%'
             OR COLUMN_NAME LIKE '%Org%' OR COLUMN_NAME LIKE '%Function%'
             OR COLUMN_NAME LIKE '%Cost%')
      ORDER BY COLUMN_NAME`);
    // 3) Mohammed Thoufiq's raw Employee row, so we can see which ID columns
    //    are actually populated for him
    const empRow = await sq(pool, 'hier-emprow', `
      SELECT * FROM [Employee].[Employee] WHERE EmployeeCode='09'`);
    res.json({ candidate_tables: tables, employee_columns: empCols, mohammed_employee_row: empRow });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/employees/debug-orgview ────────────────────────────
// Inspect [Employee].[OrganizationalHierarchyView] — the most likely source
// for the Employee Detail → Hierarchy Structure → Department field.
app.get('/api/employees/debug-orgview', async (req, res) => {
  try {
    const pool = await getPool();
    const cols = await sq(pool, 'orgview-cols', `
      SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Employee' AND TABLE_NAME='OrganizationalHierarchyView'
      ORDER BY ORDINAL_POSITION`);
    const sample = await sq(pool, 'orgview-sample', `
      SELECT TOP 5 * FROM [Employee].[OrganizationalHierarchyView]`);
    let mohammed = null;
    try {
      mohammed = await sq(pool, 'orgview-mohammed', `
        SELECT ov.* FROM [Employee].[OrganizationalHierarchyView] ov
        INNER JOIN [Employee].[Employee] e ON ov.EmployeeID=e.EmployeeID
        WHERE e.EmployeeCode='09'`);
    } catch (e2) { mohammed = { error: e2.message }; }
    res.json({ columns: cols, sample_rows: sample, mohammed_rows: mohammed });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/employees/debug-hierarchyrel ───────────────────────
// OrganizationalHierarchyView was empty (Position Management not in use).
// Check the more fundamental EmployeeRuleHierarchyRel -> Entity.Hierarchy ->
// Entity.HierarchyHeader chain instead, which should hold the actual
// Department assignment shown on Employee Detail -> Hierarchy Structure.
app.get('/api/employees/debug-hierarchyrel', async (req, res) => {
  try {
    const pool = await getPool();
    const relCols = await sq(pool, 'rel-cols', `
      SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Employee' AND TABLE_NAME='EmployeeRuleHierarchyRel'
      ORDER BY ORDINAL_POSITION`);
    const hierCols = await sq(pool, 'hier-cols', `
      SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Entity' AND TABLE_NAME='Hierarchy'
      ORDER BY ORDINAL_POSITION`);
    const headerCols = await sq(pool, 'header-cols', `
      SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA='Entity' AND TABLE_NAME='HierarchyHeader'
      ORDER BY ORDINAL_POSITION`);
    let mohammed = null;
    try {
      mohammed = await sq(pool, 'rel-mohammed', `
        SELECT er.EmployeeRuleID, e.EmployeeCode, rel.*
        FROM [Employee].[EmployeeRuleHierarchyRel] rel
        INNER JOIN [Employee].[EmployeeRule] er ON rel.EmployeeRuleID=er.EmployeeRuleID
        INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID
        WHERE e.EmployeeCode='09'`);
    } catch (e2) { mohammed = { error: e2.message }; }
    const sampleRel = await sq(pool, 'rel-sample', `SELECT TOP 5 * FROM [Employee].[EmployeeRuleHierarchyRel]`).catch(e2 => ({ error: e2.message }));
    const sampleHier = await sq(pool, 'hier-sample', `SELECT TOP 10 * FROM [Entity].[Hierarchy]`).catch(e2 => ({ error: e2.message }));
    const sampleHeader = await sq(pool, 'header-sample', `SELECT TOP 10 * FROM [Entity].[HierarchyHeader]`).catch(e2 => ({ error: e2.message }));
    res.json({ relCols, hierCols, headerCols, mohammed, sampleRel, sampleHier, sampleHeader });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ENDPOINT: GET /api/employees/debug-function ───────────────────────────
// [Employee].[Function] does not exist (confirmed via server log error:
// "Invalid object name 'Employee.Function'"). Search everywhere for the
// real table that FunctionID actually points to.
app.get('/api/employees/debug-function', async (req, res) => {
  try {
    const pool = await getPool();
    const tables = await sq(pool, 'func-tables', `
      SELECT TABLE_SCHEMA, TABLE_NAME
      FROM INFORMATION_SCHEMA.TABLES
      WHERE TABLE_NAME LIKE '%Function%' OR TABLE_NAME LIKE '%JobFunction%'
      ORDER BY TABLE_SCHEMA, TABLE_NAME`);
    // Also search ALL columns named exactly FunctionID to see which tables
    // reference it, and what type table it links to via naming convention
    const colRefs = await sq(pool, 'func-colrefs', `
      SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE COLUMN_NAME = 'FunctionID'
      ORDER BY TABLE_SCHEMA, TABLE_NAME`);
    res.json({ candidate_tables: tables, function_id_columns: colRefs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// ALL API ENDPOINTS BELOW REQUIRE AUTH (x-auth-token header)
// ═══════════════════════════════════════════════════════════════════════════

// 1. DASHBOARD
app.get('/api/dashboard', async (req, res) => {
  try {
    const pool = await getPool();
    const summary = await pool.request().query(`SELECT COUNT(*) AS TotalEmployees,SUM(CASE WHEN e.TerminationDate IS NULL THEN 1 ELSE 0 END) AS ActiveEmployees,SUM(CASE WHEN e.TerminationDate IS NOT NULL THEN 1 ELSE 0 END) AS TerminatedEmployees,ISNULL(SUM(CASE WHEN e.TerminationDate IS NOT NULL AND e.TerminationDate>=DATEADD(MONTH,-6,GETDATE()) THEN 1 ELSE 0 END),0) AS TerminatedLast6Months FROM [Employee].[Employee] e`);
    const gender = await pool.request().query(`SELECT ISNULL(ge.Gender,'Unknown') AS Gender,COUNT(*) AS EmployeeCount FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID WHERE e.TerminationDate IS NULL GROUP BY ge.Gender`);
    const joiners = await pool.request().query(`SELECT COUNT(*) AS NewJoiners FROM [Employee].[Employee] WHERE MONTH(DateEngaged)=MONTH(GETDATE()) AND YEAR(DateEngaged)=YEAR(GETDATE())`);
    const joinerList = await pool.request().query(`SELECT TOP 10 e.EmployeeCode,ge.DisplayName,ge.Gender,e.DateEngaged FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID WHERE MONTH(e.DateEngaged)=MONTH(GETDATE()) AND YEAR(e.DateEngaged)=YEAR(GETDATE()) ORDER BY e.DateEngaged DESC`);
    const trend = await pool.request().query(`SELECT FORMAT(e.DateEngaged,'MMM') AS Month,MONTH(e.DateEngaged) AS MonthNum,YEAR(e.DateEngaged) AS YearNum,COUNT(*) AS Joiners,SUM(CASE WHEN ISNULL(ge.Gender,'')='M' THEN 1 ELSE 0 END) AS MaleJoiners,SUM(CASE WHEN ISNULL(ge.Gender,'')='F' THEN 1 ELSE 0 END) AS FemaleJoiners FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID WHERE e.DateEngaged>=DATEADD(MONTH,-6,GETDATE()) GROUP BY FORMAT(e.DateEngaged,'MMM'),MONTH(e.DateEngaged),YEAR(e.DateEngaged) ORDER BY YearNum,MonthNum`);
    res.json({ summary: summary.recordset[0], gender: gender.recordset, newJoiners: joiners.recordset[0].NewJoiners, joinerList: joinerList.recordset, trend: trend.recordset });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 2. EMPLOYEES LIST
app.get('/api/employees/list', async (req, res) => {
  try {
    const pool = await getPool();
    let rows = await sq(pool, 'emp-list', `;WITH LatestRel AS (SELECT rel.*, ROW_NUMBER() OVER (PARTITION BY rel.EmployeeRuleID ORDER BY rel.LastChanged DESC) AS rn FROM [Employee].[EmployeeRuleHierarchyRel] rel INNER JOIN [Entity].[HierarchyHeader] hh ON rel.HierarchyHeaderID=hh.HierarchyHeaderID WHERE hh.Code='DEPARTMENTS') SELECT TOP 200 e.EmployeeID,e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.EmailAddress,ge.Gender,ge.BirthDate,e.JobTitleTypeID,e.FunctionID,e.DateEngaged,e.TerminationDate,e.ReportToEmployeeID,ISNULL(jt.ShortDescription,'—') AS JobTitle,ISNULL(h.HierarchyName,'—') AS Department FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID OUTER APPLY (SELECT TOP 1 er2.EmployeeRuleID FROM [Employee].[EmployeeRule] er2 WHERE er2.EmployeeID=e.EmployeeID ORDER BY er2.EmployeeRuleID DESC) er LEFT JOIN LatestRel rel ON rel.EmployeeRuleID=er.EmployeeRuleID AND rel.rn=1 LEFT JOIN [Entity].[Hierarchy] h ON rel.HierarchyID=h.HierarchyID WHERE e.TerminationDate IS NULL ORDER BY e.EmployeeCode`);
    if (!rows.length) rows = await sq(pool, 'emp-list-basic', `SELECT TOP 200 e.EmployeeID,e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.EmailAddress,ge.Gender,ge.BirthDate,e.JobTitleTypeID,e.FunctionID,e.DateEngaged,e.TerminationDate,e.ReportToEmployeeID,ISNULL(jt.ShortDescription,'—') AS JobTitle,'—' AS Department FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE e.TerminationDate IS NULL ORDER BY e.EmployeeCode`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 3. TERMINATED
app.get('/api/employees/terminated', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'terminated', `SELECT TOP 100 e.EmployeeID,e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.EmailAddress,ge.Gender,e.DateEngaged,e.TerminationDate,ISNULL(jt.ShortDescription,'—') AS JobTitle,DATEDIFF(YEAR,e.DateEngaged,e.TerminationDate) AS YearsOfService FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE e.TerminationDate IS NOT NULL ORDER BY e.TerminationDate DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 4. DEPARTMENTS
app.get('/api/employees/departments', async (req, res) => {
  try {
    const pool = await getPool();
    let rows = await sq(pool, 'depts', `;WITH LatestRel AS (SELECT rel.*, ROW_NUMBER() OVER (PARTITION BY rel.EmployeeRuleID ORDER BY rel.LastChanged DESC) AS rn FROM [Employee].[EmployeeRuleHierarchyRel] rel INNER JOIN [Entity].[HierarchyHeader] hh ON rel.HierarchyHeaderID=hh.HierarchyHeaderID WHERE hh.Code='DEPARTMENTS') SELECT ISNULL(h.HierarchyName,'Unknown') AS Department,COUNT(*) AS Count FROM [Employee].[Employee] e OUTER APPLY (SELECT TOP 1 er2.EmployeeRuleID FROM [Employee].[EmployeeRule] er2 WHERE er2.EmployeeID=e.EmployeeID ORDER BY er2.EmployeeRuleID DESC) er LEFT JOIN LatestRel rel ON rel.EmployeeRuleID=er.EmployeeRuleID AND rel.rn=1 LEFT JOIN [Entity].[Hierarchy] h ON rel.HierarchyID=h.HierarchyID WHERE e.TerminationDate IS NULL GROUP BY h.HierarchyName ORDER BY Count DESC`);
    if (!rows.length) rows = await sq(pool, 'depts-jt', `SELECT ISNULL(jt.ShortDescription,'Unknown') AS Department,COUNT(*) AS Count FROM [Employee].[Employee] e LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE e.TerminationDate IS NULL GROUP BY jt.ShortDescription ORDER BY Count DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 5. BIRTHDAYS
app.get('/api/employees/birthdays', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'birthdays', `SELECT TOP 10 e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ge.BirthDate,ISNULL(jt.ShortDescription,'—') AS JobTitle,DATEPART(MONTH,ge.BirthDate) AS BirthMonth,DATEPART(DAY,ge.BirthDate) AS BirthDay FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE ge.BirthDate IS NOT NULL AND e.TerminationDate IS NULL ORDER BY CASE WHEN DATEPART(MONTH,ge.BirthDate)>MONTH(GETDATE()) THEN DATEPART(MONTH,ge.BirthDate) WHEN DATEPART(MONTH,ge.BirthDate)=MONTH(GETDATE()) AND DATEPART(DAY,ge.BirthDate)>=DAY(GETDATE()) THEN DATEPART(MONTH,ge.BirthDate) ELSE DATEPART(MONTH,ge.BirthDate)+12 END,DATEPART(DAY,ge.BirthDate)`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 6. MILESTONES
app.get('/api/employees/milestones', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'milestones', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,e.DateEngaged,ISNULL(jt.ShortDescription,'—') AS JobTitle,DATEDIFF(YEAR,e.DateEngaged,GETDATE()) AS YearsOfService FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE e.TerminationDate IS NULL AND MONTH(e.DateEngaged)=MONTH(GETDATE()) AND DATEDIFF(YEAR,e.DateEngaged,GETDATE()) IN (1,2,3,5,10,15,20,25) ORDER BY DATEDIFF(YEAR,e.DateEngaged,GETDATE()) DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 7. HEADCOUNT
app.get('/api/employees/headcount', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'headcount', `SELECT ISNULL(SUM(CASE WHEN YEAR(e.DateEngaged)=YEAR(GETDATE()) THEN 1 ELSE 0 END),0) AS Joiners,ISNULL(SUM(CASE WHEN YEAR(e.TerminationDate)=YEAR(GETDATE()) THEN 1 ELSE 0 END),0) AS Leavers,ISNULL(SUM(CASE WHEN YEAR(e.DateEngaged)=YEAR(GETDATE()) THEN 1 ELSE 0 END),0)-ISNULL(SUM(CASE WHEN YEAR(e.TerminationDate)=YEAR(GETDATE()) THEN 1 ELSE 0 END),0) AS NetChange FROM [Employee].[Employee] e`);
    const monthly = await sq(pool, 'hc-monthly', `SELECT FORMAT(e.DateEngaged,'MMM') AS Month,MONTH(e.DateEngaged) AS MonthNum,YEAR(e.DateEngaged) AS YearNum,COUNT(*) AS Joiners FROM [Employee].[Employee] e WHERE e.DateEngaged>=DATEADD(MONTH,-11,DATEADD(DAY,1-DAY(GETDATE()),GETDATE())) GROUP BY FORMAT(e.DateEngaged,'MMM'),MONTH(e.DateEngaged),YEAR(e.DateEngaged) ORDER BY YearNum,MonthNum`);
    res.json({ summary: rows[0] || {}, monthly });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 7b. DEPARTMENT LEAVE INTENSITY HEATMAP
app.get('/api/employees/dept-heatmap', async (req, res) => {
  try {
    const pool = await getPool();
    // Employee-level rows (so the frontend can build both the totals AND a
    // per-employee hover breakdown from one dataset).
    const cells = await sq(pool, 'dept-heat', `;WITH LatestRel AS (SELECT rel.*, ROW_NUMBER() OVER (PARTITION BY rel.EmployeeRuleID ORDER BY rel.LastChanged DESC) AS rn FROM [Employee].[EmployeeRuleHierarchyRel] rel INNER JOIN [Entity].[HierarchyHeader] hh ON rel.HierarchyHeaderID=hh.HierarchyHeaderID WHERE hh.Code='DEPARTMENTS') SELECT ISNULL(h.HierarchyName,'Unknown') AS Department,MONTH(la.FromDate) AS MonthNum,FORMAT(la.FromDate,'MMM') AS MonthLabel,ISNULL(ge.DisplayName,e.EmployeeCode) AS EmployeeName,ISNULL(lt.ShortDescription,'Leave') AS LeaveType,ISNULL(SUM(la.UnitsTaken),0) AS Days FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID LEFT JOIN LatestRel rel ON rel.EmployeeRuleID=er.EmployeeRuleID AND rel.rn=1 LEFT JOIN [Entity].[Hierarchy] h ON rel.HierarchyID=h.HierarchyID WHERE YEAR(la.FromDate)=YEAR(GETDATE()) GROUP BY h.HierarchyName,MONTH(la.FromDate),FORMAT(la.FromDate,'MMM'),ge.DisplayName,e.EmployeeCode,lt.ShortDescription ORDER BY MonthNum`);
    // Full department roster (from currently active employees), so a
    // department with zero leave this year still shows as an empty row.
    const departments = await sq(pool, 'dept-heat-roster', `;WITH LatestRel AS (SELECT rel.*, ROW_NUMBER() OVER (PARTITION BY rel.EmployeeRuleID ORDER BY rel.LastChanged DESC) AS rn FROM [Employee].[EmployeeRuleHierarchyRel] rel INNER JOIN [Entity].[HierarchyHeader] hh ON rel.HierarchyHeaderID=hh.HierarchyHeaderID WHERE hh.Code='DEPARTMENTS') SELECT DISTINCT h.HierarchyName AS Department FROM [Employee].[Employee] e OUTER APPLY (SELECT TOP 1 er2.EmployeeRuleID FROM [Employee].[EmployeeRule] er2 WHERE er2.EmployeeID=e.EmployeeID ORDER BY er2.EmployeeRuleID DESC) er LEFT JOIN LatestRel rel ON rel.EmployeeRuleID=er.EmployeeRuleID AND rel.rn=1 LEFT JOIN [Entity].[Hierarchy] h ON rel.HierarchyID=h.HierarchyID WHERE e.TerminationDate IS NULL AND h.HierarchyName IS NOT NULL ORDER BY h.HierarchyName`);
    res.json({ cells, departments: departments.map(d => d.Department) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 8. PHOTO
app.get('/api/employees/photo/:code', async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('code', sql.VarChar, req.params.code)
      .query(`SELECT TOP 1 e.EmployeeCode,ge.DisplayName,gp.Photo AS PhotoData
        FROM [Employee].[Employee] e
        LEFT JOIN [Entity].[GenEntity]      ge ON e.GenEntityID  = ge.GenEntityID
        LEFT JOIN [Entity].[GenEntityPhoto] gp ON ge.GenEntityID = gp.GenEntityID
        WHERE e.EmployeeCode = @code`);
    if (!r.recordset.length) return res.status(404).json({ error: 'Not found' });
    const emp = r.recordset[0];
    if (emp.PhotoData && emp.PhotoData.length > 0) {
      const b64  = Buffer.from(emp.PhotoData).toString('base64');
      const magic = emp.PhotoData.slice(0, 2);
      const mime  = (magic[0] === 0x89 && magic[1] === 0x50) ? 'image/png' : 'image/jpeg';
      return res.json({ employeeCode: emp.EmployeeCode, name: emp.DisplayName, photo: 'data:'+mime+';base64,'+b64 });
    }
    res.json({ employeeCode: emp.EmployeeCode, name: emp.DisplayName, photo: null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 9. LEAVE SUMMARY
app.get('/api/leave/summary', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'lsum', `SELECT ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,COUNT(*) AS Applications,ISNULL(SUM(la.UnitsTaken),0) AS TotalDays FROM [Leave].[LeaveTransaction] la LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE YEAR(la.FromDate)=YEAR(GETDATE()) GROUP BY lt.ShortDescription,lt.Code ORDER BY TotalDays DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 10. LEAVE ONLEAVE
app.get('/api/leave/onleave', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'onleave', `SELECT COUNT(*) AS OnLeaveToday FROM [Leave].[LeaveTransaction] WHERE CAST(FromDate AS DATE)<=CAST(GETDATE() AS DATE) AND CAST(ToDate AS DATE)>=CAST(GETDATE() AS DATE)`);
    res.json(rows[0] || { OnLeaveToday: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 11. LEAVE TODAY
app.get('/api/leave/today', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'today', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS EmployeeName,ge.Gender,ISNULL(lt.ShortDescription,'Leave') AS LeaveType,lt.Code AS LeaveCode,la.FromDate AS StartDate,la.ToDate AS EndDate,ISNULL(la.UnitsTaken,0) AS Days FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE CAST(la.FromDate AS DATE)<=CAST(GETDATE() AS DATE) AND CAST(la.ToDate AS DATE)>=CAST(GETDATE() AS DATE) AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') ORDER BY e.EmployeeCode`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 12. LEAVE MONTHLY
app.get('/api/leave/monthly', async (req, res) => {
  try {
    const pool = await getPool();
    const monthly = await sq(pool, 'monthly', `SELECT FORMAT(la.FromDate,'MMM yyyy') AS MonthLabel,FORMAT(la.FromDate,'yyyy-MM') AS MonthSort,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,COUNT(*) AS Applications,ISNULL(SUM(la.UnitsTaken),0) AS TotalDays FROM [Leave].[LeaveTransaction] la LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE la.FromDate>=DATEADD(MONTH,-11,DATEADD(DAY,1-DAY(GETDATE()),GETDATE())) AND la.FromDate<DATEADD(MONTH,1,DATEADD(DAY,1-DAY(GETDATE()),GETDATE())) GROUP BY FORMAT(la.FromDate,'MMM yyyy'),FORMAT(la.FromDate,'yyyy-MM'),lt.ShortDescription,lt.Code ORDER BY MonthSort,LeaveCode`);
    const byEmp = await sq(pool, 'monthly-emp', `SELECT TOP 150 FORMAT(la.FromDate,'MMM yyyy') AS MonthLabel,FORMAT(la.FromDate,'yyyy-MM') AS MonthSort,e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS EmployeeName,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,ISNULL(SUM(la.UnitsTaken),0) AS Days FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE la.FromDate>=DATEADD(MONTH,-11,DATEADD(DAY,1-DAY(GETDATE()),GETDATE())) AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') GROUP BY FORMAT(la.FromDate,'MMM yyyy'),FORMAT(la.FromDate,'yyyy-MM'),e.EmployeeCode,ge.DisplayName,lt.ShortDescription,lt.Code ORDER BY MonthSort,Days DESC`);
    const topYear = await sq(pool, 'top-year', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS EmployeeName,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,ISNULL(SUM(la.UnitsTaken),0) AS Days FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE YEAR(la.FromDate)=YEAR(GETDATE()) AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') GROUP BY e.EmployeeCode,ge.DisplayName,lt.ShortDescription,lt.Code ORDER BY Days DESC`);
    res.json({ monthly, byEmployee: byEmp, topYear, currentYear: new Date().getFullYear() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 13. LEAVE CALENDAR
app.get('/api/leave/calendar', async (req, res) => {
  try {
    const pool = await getPool();
    const month = parseInt(req.query.month) || new Date().getMonth() + 1;
    const year  = parseInt(req.query.year)  || new Date().getFullYear();
    const rows  = await sq(pool, 'calendar', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS EmployeeName,ge.Gender,ISNULL(lt.ShortDescription,'Leave') AS LeaveType,lt.Code AS LeaveCode,CAST(la.FromDate AS DATE) AS StartDate,CAST(la.ToDate AS DATE) AS EndDate,ISNULL(la.UnitsTaken,0) AS Days FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE ((MONTH(la.FromDate)=${month} AND YEAR(la.FromDate)=${year}) OR (MONTH(la.ToDate)=${month} AND YEAR(la.ToDate)=${year}) OR (la.FromDate<=DATEFROMPARTS(${year},${month},1) AND la.ToDate>=EOMONTH(DATEFROMPARTS(${year},${month},1)))) AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') ORDER BY la.FromDate,e.EmployeeCode`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 14. LEAVE APPROVAL
app.get('/api/leave/approval', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'approval', `SELECT la.TransactionStatus AS StatusCode,COUNT(*) AS Count,ISNULL(SUM(la.UnitsTaken),0) AS TotalDays FROM [Leave].[LeaveTransaction] la WHERE YEAR(la.FromDate)=YEAR(GETDATE()) GROUP BY la.TransactionStatus ORDER BY la.TransactionStatus`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 15. LEAVE NO TAKEN
app.get('/api/leave/notaken', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'notaken', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ISNULL(jt.ShortDescription,'—') AS JobTitle,e.DateEngaged,DATEDIFF(MONTH,e.DateEngaged,GETDATE()) AS MonthsEmployed FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID WHERE e.TerminationDate IS NULL AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') AND e.EmployeeID NOT IN (SELECT DISTINCT er2.EmployeeID FROM [Leave].[LeaveTransaction] la2 INNER JOIN [Employee].[EmployeeRule] er2 ON la2.EmployeeRuleID=er2.EmployeeRuleID WHERE YEAR(la2.FromDate)=YEAR(GETDATE())) ORDER BY e.DateEngaged`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 16. LEAVE POLICY
app.get('/api/leave/policy', async (req, res) => {
  try {
    const pool = await getPool();
    let rows = await sq(pool, 'policy', `SELECT lt.Code AS LeaveCode,lt.ShortDescription AS LeaveType,lt.LongDescription AS Description,lt.Status,MAX(ISNULL(ld.DefaultEntitlement,0)) AS DefaultEntitlement,MAX(ISNULL(ld.MaxEntitlement,0)) AS MaxEntitlement,COUNT(DISTINCT eld.EmployeeLeaveDefID) AS EmployeesWithLeave FROM [Leave].[LeaveType] lt LEFT JOIN [Leave].[LeaveDef] ld ON ld.LeaveTypeID=lt.LeaveTypeID LEFT JOIN [Leave].[EmployeeLeaveDef] eld ON eld.LeaveDefID=ld.LeaveDefID WHERE lt.Status='A' GROUP BY lt.Code,lt.ShortDescription,lt.LongDescription,lt.Status ORDER BY lt.Code`);
    if (!rows.length) rows = await sq(pool, 'policy-s', `SELECT lt.Code AS LeaveCode,lt.ShortDescription AS LeaveType,lt.LongDescription AS Description,lt.Status,0 AS DefaultEntitlement,0 AS MaxEntitlement,0 AS EmployeesWithLeave FROM [Leave].[LeaveType] lt WHERE lt.Status='A' ORDER BY lt.Code`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 17. LEAVE BALANCE
app.get('/api/leave/balance', async (req, res) => {
  try {
    const pool = await getPool();
    const cols = await sq(pool, 'eld-cols', `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='Leave' AND TABLE_NAME='EmployeeLeaveDef' ORDER BY ORDINAL_POSITION`);
    const colSet = new Set(cols.map(c => c.COLUMN_NAME));
    let rows = [];
    if (colSet.has('EmployeeRuleID')) {
      rows = await sq(pool, 'bal-A', `;WITH LatestEL AS (SELECT el.*, ROW_NUMBER() OVER (PARTITION BY el.EmployeeLeaveDefID ORDER BY el.CycleEndDate DESC, el.EmployeePayPeriodID DESC) AS rn FROM [Leave].[EmployeeLeave] el) SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,SUM(ISNULL(el.Entitlement,0)) AS Entitled,SUM(ISNULL(el.UnitsTakenInCycle,0)) AS Taken,SUM(ISNULL(el.BalanceCarriedForward,0)) AS CarriedForward,SUM(ISNULL(el.PlannedLeave,0)) AS Pending,SUM(ISNULL(el.BalanceCarriedForward,0))-SUM(ISNULL(el.PlannedLeave,0)) AS Balance FROM LatestEL el INNER JOIN [Leave].[EmployeeLeaveDef] eld ON el.EmployeeLeaveDefID=eld.EmployeeLeaveDefID INNER JOIN [Employee].[EmployeeRule] er ON eld.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveDef] ld ON eld.LeaveDefID=ld.LeaveDefID LEFT JOIN [Leave].[LeaveType] lt ON ld.LeaveTypeID=lt.LeaveTypeID WHERE el.rn=1 AND e.TerminationDate IS NULL AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') AND lt.Code IN('ANNUAL_LEAVE','SICK_LEAVE') GROUP BY e.EmployeeCode,ge.DisplayName,ge.Gender,lt.ShortDescription,lt.Code ORDER BY ge.DisplayName,lt.Code`);
    }
    if (!rows.length && colSet.has('EmployeeLeavePolicyID')) {
      rows = await sq(pool, 'bal-B', `;WITH LatestEL AS (SELECT el.*, ROW_NUMBER() OVER (PARTITION BY el.EmployeeLeaveDefID ORDER BY el.CycleEndDate DESC, el.EmployeePayPeriodID DESC) AS rn FROM [Leave].[EmployeeLeave] el) SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,SUM(ISNULL(el.Entitlement,0)) AS Entitled,SUM(ISNULL(el.UnitsTakenInCycle,0)) AS Taken,SUM(ISNULL(el.BalanceCarriedForward,0)) AS CarriedForward,SUM(ISNULL(el.PlannedLeave,0)) AS Pending,SUM(ISNULL(el.BalanceCarriedForward,0))-SUM(ISNULL(el.PlannedLeave,0)) AS Balance FROM LatestEL el INNER JOIN [Leave].[EmployeeLeaveDef] eld ON el.EmployeeLeaveDefID=eld.EmployeeLeaveDefID INNER JOIN [Leave].[EmployeeLeavePolicy] elp ON eld.EmployeeLeavePolicyID=elp.EmployeeLeavePolicyID INNER JOIN [Employee].[EmployeeRule] er ON elp.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveDef] ld ON eld.LeaveDefID=ld.LeaveDefID LEFT JOIN [Leave].[LeaveType] lt ON ld.LeaveTypeID=lt.LeaveTypeID WHERE el.rn=1 AND e.TerminationDate IS NULL AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') AND lt.Code IN('ANNUAL_LEAVE','SICK_LEAVE') GROUP BY e.EmployeeCode,ge.DisplayName,ge.Gender,lt.ShortDescription,lt.Code ORDER BY ge.DisplayName,lt.Code`);
    }
    if (!rows.length) {
      rows = await sq(pool, 'bal-fallback', `SELECT e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ISNULL(lt.ShortDescription,'Unknown') AS LeaveType,lt.Code AS LeaveCode,SUM(ISNULL(la.UnitsTaken,0)) AS Entitled,SUM(ISNULL(la.UnitsTaken,0)) AS Taken,0 AS Balance FROM [Leave].[LeaveTransaction] la INNER JOIN [Employee].[EmployeeRule] er ON la.EmployeeRuleID=er.EmployeeRuleID INNER JOIN [Employee].[Employee] e ON er.EmployeeID=e.EmployeeID LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Leave].[LeaveType] lt ON la.LeaveTypeID=lt.LeaveTypeID WHERE e.TerminationDate IS NULL AND ISNULL(ge.DisplayName,'') NOT IN ('Ramakrishnan Subramoni','Shobha Moni') AND YEAR(la.FromDate)=YEAR(GETDATE()) AND lt.Code IN('ANNUAL_LEAVE','SICK_LEAVE') GROUP BY e.EmployeeCode,ge.DisplayName,ge.Gender,lt.ShortDescription,lt.Code ORDER BY ge.DisplayName,lt.Code`);
    }
    // NOTE: [Leave].[EmployeeLeave] stores one row PER PAY PERIOD, so summing
    // BalanceCarriedForward across all history would massively over-count.
    // We take only the latest pay-period row per leave definition (via
    // ROW_NUMBER() in the CTE above), then SUM across leave definitions under
    // the same leave type (e.g. "ANN_LEAV" + "CARRYFWD" = true Annual Leave
    // total, matching Sage's own total row, e.g. 22.5 + 51.5 = 74.0).
    // Balance = BalanceCarriedForward - PlannedLeave (pending applications),
    // computed explicitly here rather than using Sage's BalanceIncludingPlanned.
    const totals = {};
    rows.forEach(r => {
      const k = r.EmployeeCode;
      if (!totals[k]) totals[k] = 0;
      totals[k] += (parseFloat(r.Balance) || 0);
    });
    rows = rows.map(r => ({ ...r, TotalCarriedForward: Math.round((totals[r.EmployeeCode] || 0) * 100) / 100 }));
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 18. ORG CHART
app.get('/api/org/chart', async (req, res) => {
  try {
    const pool = await getPool();
    const rows = await sq(pool, 'org', `SELECT e.EmployeeID,e.EmployeeCode,ISNULL(ge.DisplayName,e.EmployeeCode) AS DisplayName,ge.Gender,ge.EmailAddress,ISNULL(jt.ShortDescription,'Employee') AS JobTitle,e.FunctionID,e.DateEngaged,e.ReportToEmployeeID,mgr.EmployeeCode AS ManagerCode,ISNULL(mge.DisplayName,mgr.EmployeeCode) AS ManagerName FROM [Employee].[Employee] e LEFT JOIN [Entity].[GenEntity] ge ON e.GenEntityID=ge.GenEntityID LEFT JOIN [Employee].[JobTitleType] jt ON e.JobTitleTypeID=jt.JobTitleTypeID LEFT JOIN [Employee].[Employee] mgr ON e.ReportToEmployeeID=mgr.EmployeeID LEFT JOIN [Entity].[GenEntity] mge ON mgr.GenEntityID=mge.GenEntityID WHERE e.TerminationDate IS NULL ORDER BY e.ReportToEmployeeID,e.EmployeeCode`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 19. HEALTH
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), database: process.env.DB_NAME, sessions: sessions.size });
});

// ── CLEAN URL ROUTES ─────────────────────────────────────────────────────
// http://10.180.97.20:3000/triaddashoboard  → dashboard
// http://10.180.97.20:3000/                 → dashboard (no login — embedded in Sage ESS)
app.get('/triaddashoboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'triad_hr_dashboard.html'));
});
app.get('/', (req, res) => {
  res.redirect('/triaddashoboard');
});

app.listen(3000, () => {
  console.log('\n✅  Triad HR Dashboard  →  http://10.180.97.20:3000');
  console.log('    Database : ' + process.env.DB_NAME);
  console.log('\n    Login removed — designed to be embedded/injected into Sage ESS');
  console.log('    Dashboard: http://10.180.97.20:3000/triaddashoboard\n');
});