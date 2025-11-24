import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Twilio from "twilio";
import { google } from "googleapis";
import fs from "fs";
import path from "path";
import ExcelJS from 'exceljs';
import * as XLSX from "xlsx";

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev_secret_change_me') {
  console.warn('WARNING: JWT_SECRET is not set or uses the development default. Replace it in .env with a strong secret.');
}
const signAdminToken = (admin) =>
  jwt.sign({ sub: admin.id, role: 'admin', username: admin.username }, JWT_SECRET, { expiresIn: '7d' });


const signCustomerToken = (cust) =>
  jwt.sign({ sub: cust.id, role: 'customer', email: cust.email }, JWT_SECRET, { expiresIn: '7d' });

const app = express();

// --- middleware ---
app.use(express.json());

// Allowlist origin (env or default to Vite dev)
const ALLOWED_ORIGINS = [
  'https://raiganjtask.netlify.app',
  'http://enquiry.raiganjcabletv.com'
];

app.use(
  cors({
    origin: (origin, cb) => {
      // allow requests with no origin (Postman, server-to-server)
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS policy: origin not allowed'));
    },
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);
// Optional: generic preflight fallback (safe with Express 5)
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- db pool ---
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
});
const client = Twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const FROM = process.env.TWILIO_WHATSAPP_FROM;

/**
 * Convert ISO string or Date into MySQL DATETIME string "YYYY-MM-DD HH:MM:SS" (UTC)
 * Returns null for falsy or invalid input.
 *
 * If you prefer server-local time for storage, set useLocalTime = true.
 */
// helper: convert ISO -> JS Date adjusted for timezone so MySQL DATETIME stores correct local value
function toMySqlDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  // adjust to remove client timezone offset so stored DATETIME matches the provided ISO local time
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000);
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = auth.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid Token" });
  }
}





// --- work: generic endpoints (add these before app.listen) ---

/**
 * Helper to normalize DB row into frontend-friendly shape
 * (keeps same keys your React expects: id, name/title, description, start_date, etc.)
 */
// --- work: generic endpoints (robust admin column handling) ---

/**
 * Helper to normalize DB row into frontend-friendly shape
 * (keeps same keys your React expects: id, name/title, description, start_date, etc.)
 */
function normalizeRowForFrontend(w, adminMap = {}) {
  const title = w.title || w.name || null;
  const assignById = w.assign_by ?? w.assign_id ?? null;
  const employeeId = w.employee_id ?? w.employee ?? null;

  return {
    id: w.id,
    name: w.name ?? title,
    title,
    description: w.description ?? w.address ?? "",
    working_type: w.working_type ?? w.priority ?? null,
    contact_number: w.contact_number ?? w.contact ?? null,
    start_date: w.start_date ? new Date(w.start_date).toISOString().slice(0, 19).replace("T", " ") : null,
    end_date: w.end_date ? new Date(w.end_date).toISOString().slice(0, 19).replace("T", " ") : null,
    status: w.status ?? null,
    priority: w.priority ?? w.working_type ?? null,
    customer_id: w.customer_id ?? null,
    employee_id: employeeId,
    assign_by: assignById,
    assign_by_name: assignById ? (adminMap[String(assignById)] ?? `#${assignById}`) : null,
    created_at: w.created_at ? new Date(w.created_at).toISOString().slice(0, 19).replace("T", " ") : null,
    address: w.address ?? null,
    _raw: w
  };
}

/** GET /work - all rows (debug / fallback) */
app.get('/work', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM `work` ORDER BY id DESC LIMIT 1000');

    // fetch admins; be permissive about available columns
    const [admins] = await pool.query('SELECT id, username FROM admin');
    const adminMap = {};
    admins.forEach(a => {
      if (a && a.id !== undefined) {
        // prefer fullname, then username, then fallback id
        adminMap[String(a.id)] = a.username ?? `#${a.id}`;
      }
    });

    const out = rows.map(r => normalizeRowForFrontend(r, adminMap));
    res.json(out);
  } catch (err) {
    console.error('GET /work failed:', err?.message || err);
    res.status(500).json({ error: 'Failed to load work', detail: err?.message || String(err) });
  }
});

/** GET /work/unassigned - rows where employee_id IS NULL AND assign_by IS NULL */
app.get('/work/unassigned', async (req, res) => {
  try {
    const sql = `
      SELECT w.*
      FROM work w
      WHERE (w.employee_id IS NULL OR w.employee_id = 0)
        AND (w.assign_by IS NULL OR w.assign_by = 0)
      ORDER BY w.start_date DESC, w.id DESC
      LIMIT 1000
    `;
    const [rows] = await pool.query(sql);

    // permissive admin map (only use columns we know exist)
    const [admins] = await pool.query('SELECT id, username FROM admin');
    const adminMap = {};
    admins.forEach(a => {
      if (a && a.id !== undefined) adminMap[String(a.id)] = a.username ?? `#${a.id}`;
    });

    const out = rows.map(r => normalizeRowForFrontend(r, adminMap));
    res.json(out);
  } catch (err) {
    console.error('GET /work/unassigned failed:', err?.message || err);
    res.status(500).json({ error: 'Failed to load unassigned work', detail: err?.message || String(err) });
  }
});

/**
 * PATCH /work/:id
 * Accepts same fields as /employees/:empId/work/:workId route but works on generic work id.
 */
app.patch('/work/:id', async (req, res) => {
  try {
    const workId = Number(req.params.id);
    if (!workId) return res.status(400).json({ error: 'invalid work id' });

    const updates = [];
    const params = [];

    const {
      name,
      assign_by,
      assign_by_id,
      assign_id,
      employee_id,
      assignee_id,
      assign_id_new,
      customer_id,
      title,
      working_type,
      description,
      contact_number,
      status,
      priority,
      start_date,
      end_date,
    } = req.body;

    const push = (col, val) => { updates.push(`${col} = ?`); params.push(val); };

    if (name !== undefined) push('name', name);
    if (assign_by !== undefined) push('assign_by', assign_by);
    if (assign_by_id !== undefined) push('assign_by', assign_by_id);
    if (assign_id !== undefined) push('assign_by', assign_id);
    if (employee_id !== undefined) push('employee_id', employee_id);
    if (assignee_id !== undefined) push('employee_id', assignee_id);
    if (assign_id_new !== undefined) push('employee_id', assign_id_new);
    if (customer_id !== undefined) push('customer_id', customer_id);

    if (title !== undefined) {
      const titleVal = title && String(title).trim() ? String(title).trim() : null;
      push('title', titleVal);
    }

    if (working_type !== undefined) push('working_type', working_type);
    if (description !== undefined) push('description', description);
    if (contact_number !== undefined) push('contact_number', contact_number);

    if (status !== undefined) {
      const allowedStatus = new Set(['Pending', 'Completed', 'hold', 'process']);
      if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });
      push('status', status);
    }

    if (priority !== undefined) {
      const allowedPriority = new Set(['P0','P1','P2']);
      if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });
      push('priority', priority);
    }

    if (start_date !== undefined) {
      const v = toMySqlDate(start_date);
      push('start_date', v);
    }

    if (end_date !== undefined) {
      const v = toMySqlDate(end_date);
      push('end_date', v);
    }

    if (!updates.length) return res.status(400).json({ error: 'no fields to update' });

    params.push(workId);
    const sql = `UPDATE work SET ${updates.join(', ')} WHERE id = ?`;
    await pool.query(sql, params);

    const [rows] = await pool.query('SELECT * FROM work WHERE id = ?', [workId]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });

    const [admins] = await pool.query('SELECT id, username FROM admin');
    const adminMap = {};
    admins.forEach(a => {
      if (a && a.id !== undefined) adminMap[String(a.id)] =a.username ?? `#${a.id}`;
    });

    const row = normalizeRowForFrontend(rows[0], adminMap);
    res.json(row);
  } catch (err) {
    console.error('PATCH /work/:id failed:', err?.message || err);
    res.status(500).json({ error: 'Update work failed', detail: err?.message || String(err) });
  }
});



////////////////////////////////////////////////////////////////////////////////////////////////
app.post('/reports/work-to-sheet', async (req, res) => {
  try {
    // 1) Query work rows with assignee and admin username
    const sql = `
      SELECT w.*, e.name AS assignee_name, a.username AS assign_by_name
      FROM work w
      LEFT JOIN employee e ON e.id = w.employee_id
      LEFT JOIN admin a ON a.id = w.assign_by
      ORDER BY w.start_date DESC, w.id DESC
    `;
    const [rows] = await pool.query(sql);

    // 2) Local date formatter (same as before)
    const formatDateTime = (raw) => {
      if (!raw) return "-";
      const d = new Date(raw);
      if (Number.isNaN(d.getTime())) return "-";
      return d.toLocaleString('en-US', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', hour12: true
      });
    };

    // 3) Build workbook & worksheet
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Your API';
    workbook.created = new Date();

    const sheet = workbook.addWorksheet('work');

    // Header
    const header = [
      "Name", "Assign", "Assign by", "Date & time", "Status", "Problem", "Contact", "Address"
    ];
    sheet.addRow(header);

    // Add data rows
    rows.forEach((w) => {
      sheet.addRow([
        w.name ?? "-",
        w.assignee_name ?? "-",
        w.assign_by_name ?? (w.assign_by ? `#${w.assign_by}` : "-"),
        formatDateTime(w.start_date),
        w.status ?? "-",
        w.working_type ?? "-",
        w.contact_number ?? "-",
        w.description ?? w.address ?? "-"
      ]);
    });

    // Style header row (bold) and freeze it
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.alignment = { vertical: 'middle', horizontal: 'center' };
    sheet.views = [{ state: 'frozen', ySplit: 1 }];

    // Auto-width columns (simple heuristic)
    sheet.columns = sheet.columns.map(col => {
      const maxLength = col.values.reduce((acc, v) => {
        const l = v ? String(v).length : 0;
        return Math.max(acc, l);
      }, 10);
      return { ...col, width: Math.min(Math.max(maxLength + 2, 12), 60) }; // clamp width
    });

    // 4) Stream workbook to response as attachment
    const filename = `work-report-${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // write to response stream
    await workbook.xlsx.write(res);
    // ensure response ends
    res.end();
  } catch (err) {
    console.error('reports/work-to-sheet (xlsx) failed:', err);
    return res.status(500).json({ ok: false, error: err?.message || String(err) });
  }
});

























// --- routes ---
// Send WhatsApp text via Twilio
app.post("/send-text", async (req, res) => {
  try {
    // defaults
    const rawTo = (req.body && req.body.to) || "7679426794";
    const bodyText = (req.body && req.body.body) || "Hello from raiganj cable tv!";

    // normalize recipient
    const normalizeToWhatsApp = (value) => {
      if (!value) return null;
      let v = String(value).trim();
      if (v.startsWith("whatsapp:")) return v;
      if (v.startsWith("+")) return `whatsapp:${v}`;
      if (/^\d{11,15}$/.test(v)) return `whatsapp:+${v}`;
      if (/^\d{10}$/.test(v)) return `whatsapp:+91${v}`;
      return `whatsapp:${v}`;
    };
    const to = normalizeToWhatsApp(rawTo);
    if (!to || !/^whatsapp:\+\d{10,15}$/.test(to)) {
      return res.status(400).json({ ok: false, error: "invalid recipient format after normalization", to });
    }

    if (!FROM || !FROM.startsWith("whatsapp:")) {
      console.warn("TWILIO_WHATSAPP_FROM missing or invalid. Current FROM:", FROM);
      return res.status(500).json({ ok: false, error: "server misconfigured: TWILIO_WHATSAPP_FROM must be set and start with 'whatsapp:'" });
    }

    // Prefer explicit env var TWILIO_STATUS_CALLBACK if valid HTTPS; else skip.
    let statusCallbackToUse = null;
    const envCallback = (process.env.TWILIO_STATUS_CALLBACK || "").trim();

    if (envCallback) {
      try {
        const u = new URL(envCallback);
        if (u.protocol !== "https:") {
          console.warn("TWILIO_STATUS_CALLBACK exists but is not https. Ignoring:", envCallback);
        } else {
          statusCallbackToUse = envCallback;
        }
      } catch (e) {
        console.warn("TWILIO_STATUS_CALLBACK is invalid URL. Ignoring:", envCallback);
      }
    }

    // If no valid env callback, don't construct a localhost http callback (Twilio will reject).
    // (Optional) if you want to derive from request, only do so when request protocol and host form https public host.
    // For local dev we intentionally skip derived callbacks to avoid Twilio error 21609.

    const msgOptions = { from: FROM, to, body: bodyText };
    if (statusCallbackToUse) {
      msgOptions.statusCallback = statusCallbackToUse;
    } else {
      console.log("No valid public https statusCallback available — skipping statusCallback.");
    }

    console.log("Sending WhatsApp message ->", { to, smsFrom: FROM, statusCallback: statusCallbackToUse || null });

    const msg = await client.messages.create(msgOptions);

    return res.json({ ok: true, sid: msg.sid, to, body: bodyText });
  } catch (err) {
    console.error("send-text error:", err);
    const msg = err?.message || String(err);
    return res.status(500).json({ ok: false, error: msg });
  }
});
// Health check





app.get('/health', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    return res.json({ status: rows?.[0]?.ok === 1 ? 'connection is ok' : 'unexpected result' });
  } catch (err) {
    console.error('DB health check failed:', err?.message);
    return res.status(500).json({ status: 'connection failed', error: err?.message });
  }
});

// List employees
app.get('/employees', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM `employee` ORDER BY id DESC LIMIT 50');
    res.json(rows);
  } catch (err) {
    console.error('Query failed:', err?.message);
    res.status(500).json({ error: 'Query failed', detail: err?.message });
  }
});

// NEW: Get one employee by id (frontend falls back to this)
app.get('/employees/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'invalid employee id' });
    const [rows] = await pool.query('SELECT * FROM `employee` WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Fetch employee failed:', err?.message);
    res.status(500).json({ error: 'Fetch employee failed', detail: err?.message });
  }
});

// Create employee (uses your exact field names)
app.post('/employees', async (req, res) => {
  try {
    const { name, destination, mobile_number, adress } = req.body;
    if (!name || !destination) return res.status(400).json({ error: 'name and destination are required' });

    const [result] = await pool.query(
      'INSERT INTO `employee` (`name`, `destination`, `mobile_number`, `adress`) VALUES (?,?,?,?)',
      [name, destination, mobile_number || null, adress || null]
    );
    const [rows] = await pool.query('SELECT * FROM `employee` WHERE id = ?', [result.insertId]);
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Insert failed:', err?.message);
    res.status(500).json({ error: 'Insert failed', detail: err?.message });
  }
});

// --- "work" endpoints for the UI ---

// Add work item for employee (full fields) — title optional now, dates formatted correctly
app.post('/employees/:id/work', async (req, res) => {
  try {
    const empId = Number(req.params.id);
    if (!empId) return res.status(400).json({ error: 'invalid employee id' });

    // Accept payload keys that match the table
    const {
      name = null,
      assign_by = null,
      customer_id = null,
      title = null,
      working_type = 'internet issue',
      contact_number = null,
      description = null,
      start_date = null, // expect ISO string or null (optional)
      end_date = null,
      status = 'Pending',
      priority = 'P0',
    } = req.body;

    // title is optional: if blank treat as null
    const titleValue = title && String(title).trim() ? String(title).trim() : null;

    // validate enums
    const allowedStatus = new Set(['Pending', 'Completed', 'hold', 'process']);
    if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });

    const allowedPriority = new Set(['P0','P1','P2']);
    if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });

    // convert ISO -> JS Date (or null)
    // start_dt will be either a JS Date object or null
    const start_dt = toMySqlDate(start_date);
    const end_dt = toMySqlDate(end_date);

    /*
      Use COALESCE(?, NOW()) for start_date:
      - If start_dt is null (client omitted it) the DB will set start_date = NOW()
      - If client provided valid start_date, that value will be used
    */
    const [result] = await pool.query(
      `INSERT INTO work
        (name, assign_by, employee_id, customer_id, title, working_type,
         contact_number, description, start_date, end_date, status, priority)
       VALUES (?,?,?,?,?,?,?,?,COALESCE(?, NOW()),?,?,?)`,
      [
        name ? String(name).slice(0,30) : null,
        assign_by !== null ? Number(assign_by) : null,
        empId,
        customer_id !== null ? Number(customer_id) : null,
        titleValue,
        working_type,
        contact_number || null,
        description || null,
        start_dt,   // will be JS Date or null -> COALESCE handles null
        end_dt,     // JS Date or null
        status,
        priority
      ]
    );

    const [rows] = await pool.query('SELECT * FROM work WHERE id = ?', [result.insertId]);
    return res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Add work failed:', err?.message || err);
    return res.status(500).json({ error: 'Add work failed', detail: err?.message });
  }
});


// List work items for one employee
app.get('/employees/:id/work', async (req, res) => {
  try {
    const empId = Number(req.params.id);
    if (!empId) return res.status(400).json({ error: 'invalid employee id' });
    const [rows] = await pool.query('SELECT * FROM `work` WHERE `employee_id` = ? ORDER BY id DESC', [empId]);
    res.json(rows);
  } catch (err) {
    console.error('Fetch work failed:', err?.message);
    res.status(500).json({ error: 'Fetch work failed', detail: err?.message });
  }
});

// Update any fields of a work item — uses same toMySqlDate helper for consistency
app.patch('/employees/:empId/work/:workId', async (req, res) => {
  try {
    const workId = Number(req.params.workId);
    if (!workId) return res.status(400).json({ error: 'invalid work id' });

    const updates = [];
    const params = [];

    const {
      name,
      assign_by,
      customer_id,
      title,
      working_type,
      description,
      contact_number,
      status,
      priority,
      start_date,
      end_date,
    } = req.body;

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (assign_by !== undefined) { updates.push('assign_by = ?'); params.push(assign_by); }
    if (customer_id !== undefined) { updates.push('customer_id = ?'); params.push(customer_id); }
    if (title !== undefined) { 
      const titleVal = title && String(title).trim() ? String(title).trim() : null;
      updates.push('title = ?'); params.push(titleVal); 
    }
    if (working_type !== undefined) { updates.push('working_type = ?'); params.push(working_type); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (contact_number !== undefined) { updates.push('contact_number = ?'); params.push(contact_number); }

    if (status !== undefined) {
      const allowedStatus = new Set(['Pending', 'Completed', 'hold', 'process']);
      if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });
      updates.push('status = ?'); params.push(status);
    }

    if (priority !== undefined) {
      const allowedPriority = new Set(['P0','P1','P2']);
      if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });
      updates.push('priority = ?'); params.push(priority);
    }

    if (start_date !== undefined) {
      const v = toMySqlDate(start_date);
      updates.push('start_date = ?'); params.push(v);
    }

    if (end_date !== undefined) {
      const v = toMySqlDate(end_date);
      updates.push('end_date = ?'); params.push(v);
    }

    if (!updates.length) return res.status(400).json({ error: 'no fields to update' });

    params.push(workId);
    await pool.query(`UPDATE work SET ${updates.join(', ')} WHERE id = ?`, params);

    const [rows] = await pool.query('SELECT * FROM work WHERE id = ?', [workId]);
    res.json(rows[0]);
  } catch (err) {
    console.error('Update work failed:', err?.message || err);
    res.status(500).json({ error: 'Update work failed', detail: err?.message });
  }
});


// ---------- CUSTOMER AUTH ----------

// POST /customers  (signup)
app.post('/customers', async (req, res) => {
  try {
    const { name, email, password, mobile, location } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email, password required' });
    }

    const [exists] = await pool.query('SELECT id FROM customers WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const [ins] = await pool.query(
      'INSERT INTO customers (name, email, password_hash, mobile, location) VALUES (?,?,?,?,?)',
      [name, email, hash, mobile || null, location || null]
    );

    const [rows] = await pool.query(
      'SELECT id, name, email, mobile, location, created_at FROM customers WHERE id = ?',
      [ins.insertId]
    );
    const user = rows[0];
    const token = signCustomerToken(user);
    return res.status(201).json({ user, token });
  } catch (err) {
    console.error('Signup failed:', err.message);
    return res.status(500).json({ error: 'Signup failed' });
  }
});

// POST /customers/login  (email+password)
app.post('/customers/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const [rows] = await pool.query('SELECT * FROM customers WHERE email = ?', [email]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const safe = {
      id: user.id,
      name: user.name,
      email: user.email,
      mobile: user.mobile,
      location: user.location,
      created_at: user.created_at,
    };
    const token = signCustomerToken(user);
    return res.json({ user: safe, token });
  } catch (err) {
    console.error('Login failed:', err.message);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// GET /customers/:id  (basic profile)
app.get('/customers/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'invalid id' });
    const [rows] = await pool.query(
      'SELECT id, name, email, mobile, location, created_at FROM customers WHERE id = ?',
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Fetch failed' });
  }
});
// customer create 
// POST /customer  → Add new customer
app.post('/customer', async (req, res) => {
  try {
    const { name, mobile, plan_type, address, secondary_mobile } = req.body;

    if (!name || !mobile) {
      return res.status(400).json({ error: "name and mobile are required" });
    }

    const [insert] = await pool.query(
      `INSERT INTO customer (name, mobile, plan_type, address, secondary_mobile)
       VALUES (?, ?, ?, ?, ?)`,
      [name, mobile, plan_type || null, address || null, secondary_mobile || null]
    );

    const [rows] = await pool.query('SELECT * FROM customer WHERE id = ?', [
      insert.insertId,
    ]);

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Add customer failed:", err.message);
    res.status(500).json({ error: "Add customer failed", detail: err.message });
  }
});
// customer list 
// GET /customer  → list all
// GET /customer  → list all or filter by phone/mobile
app.get('/customer', async (req, res) => {
  try {
    const { phone } = req.query;

    // If no phone query, return full list (old behavior)
    if (!phone) {
      const [rows] = await pool.query(
        `SELECT * FROM customer ORDER BY id DESC`
      );
      return res.json(rows);
    }

    // ---- If ?phone= is present, FILTER ----
    // Normalize: keep only digits, then last 10 digits
    let normalized = String(phone).replace(/\D/g, '');
    if (normalized.length > 10) {
      normalized = normalized.slice(-10);
    }

    if (!normalized || normalized.length !== 10) {
      return res.status(400).json({ error: 'invalid phone format' });
    }

    // Try match against mobile or secondary_mobile
    const [rows] = await pool.query(
      `SELECT * FROM customer
       WHERE mobile = ? OR secondary_mobile = ?
       ORDER BY id DESC`,
      [normalized, normalized]
    );

    return res.json(rows);
  } catch (err) {
    console.error("Fetch customers failed:", err.message);
    res.status(500).json({ error: "Fetch customers failed", detail: err.message });
  }
});

//update customer
// PATCH /customer/:id  → update customer
app.patch('/customer/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid customer id" });

    const { name, mobile, plan_type, address, secondary_mobile } = req.body;

    const updates = [];
    const params = [];

    if (name !== undefined) {
      updates.push("name = ?");
      params.push(name);
    }

    if (mobile !== undefined) {
      updates.push("mobile = ?");
      params.push(mobile);
    }

    if (plan_type !== undefined) {
      updates.push("plan_type = ?");
      params.push(plan_type);
    }

    if (address !== undefined) {
      updates.push("address = ?");
      params.push(address);
    }

    if (secondary_mobile !== undefined) {
      updates.push("secondary_mobile = ?");
      params.push(secondary_mobile);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: "no fields to update" });
    }

    params.push(id);

    await pool.query(
      `UPDATE customer SET ${updates.join(", ")} WHERE id = ?`,
      params
    );

    const [rows] = await pool.query("SELECT * FROM customer WHERE id = ?", [id]);

    return res.json(rows[0]);
  } catch (err) {
    console.error("Update customer failed:", err.message);
    return res.status(500).json({ error: "update failed", detail: err.message });
  }
});





app.get('/adminall', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM admin ORDER BY id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("Fetch admin failed:", err.message);
    res.status(500).json({ error: "Fetch admin failed" });
  }
});







// Create new admin
app.post('/admin', async (req, res) => {
  try {
    const { username, password, mobile_number } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }

    // unique username
    const [exists] = await pool.query('SELECT id FROM admin WHERE username = ?', [username]);
    if (exists.length) return res.status(409).json({ error: 'username already exists' });

    const hash = await bcrypt.hash(password, 10);

    // Try to insert into password_hash first; fall back to password column if needed.
    try {
      const [ins] = await pool.query(
        'INSERT INTO admin (username, password_hash, mobile_number) VALUES (?,?,?)',
        [username, hash, mobile_number || null]
      );
      const [rows] = await pool.query('SELECT id, username, mobile_number, created_at FROM admin WHERE id = ?', [ins.insertId]);
      const admin = rows[0];
      const token = signAdminToken(admin);
      return res.status(201).json({ admin, token });
    } catch (insertErr) {
      // If insertion into password_hash fails (column missing), try legacy `password` column
      try {
        const [ins2] = await pool.query(
          'INSERT INTO admin (username, password, mobile_number) VALUES (?,?,?)',
          [username, hash, mobile_number || null]
        );
        const [rows2] = await pool.query('SELECT id, username, mobile_number, created_at FROM admin WHERE id = ?', [ins2.insertId]);
        const admin = rows2[0];
        const token = signAdminToken(admin);
        return res.status(201).json({ admin, token });
      } catch (err2) {
        console.error('Create admin failed (both insert attempts):', insertErr?.message || insertErr, err2?.message || err2);
        return res.status(500).json({ error: 'Create admin failed', detail: insertErr?.message || err2?.message || String(insertErr) });
      }
    }
  } catch (err) {
    console.error('Create admin failed:', err?.message || err);
    return res.status(500).json({ error: 'Create admin failed', detail: err?.message });
  }
});

// ---------- Admin login (accepts password_hash OR password) ----------
app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }

    const [rows] = await pool.query('SELECT * FROM admin WHERE username = ?', [username]);
    const admin = rows[0];
    if (!admin) return res.status(401).json({ error: 'invalid credentials' });

    // Accept either column, prefer password_hash
    const storedHash = admin.password_hash ?? admin.password ?? null;
    if (!storedHash) {
      console.error(`Admin record missing stored password hash for username=${username}`, admin);
      return res.status(500).json({ error: 'server misconfigured: no password stored for user' });
    }

    const ok = await bcrypt.compare(password, storedHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const safe = {
      id: admin.id,
      username: admin.username,
      mobile_number: admin.mobile_number,
      created_at: admin.created_at,
    };
    const token = signAdminToken(admin);
    return res.json({ admin: safe, token });
  } catch (err) {
    console.error('Admin login failed:', err?.message || err);
    return res.status(500).json({ error: 'Admin login failed', detail: err?.message });
  }
});


// --- start ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
