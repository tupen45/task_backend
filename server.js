import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Twilio from "twilio";

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
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';
app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
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

// Add work item for employee (full fields)
// Add work item for employee (full fields) — corrected to match the work table
app.post('/employees/:id/work', async (req, res) => {
  try {
    const empId = Number(req.params.id);
    if (!empId) return res.status(400).json({ error: 'invalid employee id' });

    // Accept payload keys that match the table
    const {
      name = null,
      assign_by = null,
      customer_id = null,
      title,
      working_type = 'internet issue', // set a sensible default if desired
      contact_number = null,
      description = null,
      start_date = null,   // expect ISO string or null
      end_date = null,
      status = 'Pending',
      priority = 'P0',
    } = req.body;

    if (!title || !title.trim()) return res.status(400).json({ error: 'title is required' });

    // ensure status matches table enum
    const allowedStatus = new Set(['Pending', 'Completed', 'hold', 'process']);
    if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });

    const allowedPriority = new Set(['P0','P1','P2']);
    if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });

    // convert ISO -> JS Date (mysql2 accepts JS Date for DATETIME)
    const toMySqlDate = (iso) => {
      if (!iso) return null;
      const d = new Date(iso);
      if (isNaN(d)) return null;
      // convert to local time without timezone offset so MySQL stores correct datetime
      return new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    };

    const start_dt = toMySqlDate(start_date);
    const end_dt = toMySqlDate(end_date);

    // Now insert all expected columns (12 columns, id auto)
    const [result] = await pool.query(
      `INSERT INTO work
        (name, assign_by, employee_id, customer_id, title, working_type,
         contact_number, description, start_date, end_date, status, priority)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        name ? String(name).slice(0,30) : null,
        assign_by !== null ? Number(assign_by) : null,
        empId,
        customer_id !== null ? Number(customer_id) : null,
        title.trim(),
        working_type,
        contact_number || null,
        description || null,
        start_dt,
        end_dt,
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

// Update any fields of a work item
// Update any fields of a work item — align allowed status/priority and date names
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
    if (title !== undefined) { updates.push('title = ?'); params.push(title); }
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
      const d = start_date ? new Date(start_date) : null;
      const v = d ? new Date(d.getTime() - d.getTimezoneOffset() * 60000) : null;
      updates.push('start_date = ?'); params.push(v);
    }

    if (end_date !== undefined) {
      const d = end_date ? new Date(end_date) : null;
      const v = d ? new Date(d.getTime() - d.getTimezoneOffset() * 60000) : null;
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
app.get('/customer', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM customer ORDER BY id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("Fetch customers failed:", err.message);
    res.status(500).json({ error: "Fetch customers failed" });
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
