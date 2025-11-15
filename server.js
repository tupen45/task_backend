import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const signCustomerToken = (cust) =>
  jwt.sign({ sub: cust.id, role: 'customer', email: cust.email }, JWT_SECRET, { expiresIn: '7d' });

const app = express();

// --- middleware ---
app.use(express.json());

// Allowlist origin (env or default to Vite dev)
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173/';
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

// --- routes ---

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
app.post('/employees/:id/work', async (req, res) => {
  try {
    const empId = Number(req.params.id);
    if (!empId) return res.status(400).json({ error: 'invalid employee id' });

    const {
      title,
      address,
      startDate = null, // ISO string from frontend
      endDate = null,   // ISO string from frontend
      status = 'Pending',
      priority = 'P0',
      contact_number ,
    } = req.body;

    if (!title || !title.trim()) return res.status(400).json({ error: 'title is required' });

    const allowedStatus = new Set(['Pending','In Progress','Completed','Deployed','Deferred']);
    if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });

    const allowedPriority = new Set(['P0','P1','P2']);
    if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });

    // Convert ISO -> MySQL DATETIME (strip TZ offset)
    const toMySqlDate = (iso) => {
      if (!iso) return null;
      const d = new Date(iso);
      if (isNaN(d)) return null;
      return new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    };

    const start_dt = toMySqlDate(startDate);
    const end_dt = toMySqlDate(endDate);

    // FIX: 8 columns -> 8 placeholders
    const [result] = await pool.query(
      `INSERT INTO work (employee_id, title, contact_number, description, start_date, end_date, status, priority)
       VALUES (?,?,?,?,?,?,?,?)`,
      [empId, title.trim(), contact_number, address, start_dt, end_dt, status, priority]
    );

    const [rows] = await pool.query('SELECT * FROM work WHERE id = ?', [result.insertId]);
    return res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Add work failed:', err?.message);
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
app.patch('/employees/:empId/work/:workId', async (req, res) => {
  try {
    const workId = Number(req.params.workId);
    if (!workId) return res.status(400).json({ error: 'invalid work id' });

    const updates = [];
    const params = [];

    const { title, description, status, priority, startDate, endDate, contact_number } = req.body;

    if (title !== undefined) { updates.push('title = ?'); params.push(title); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (contact_number !== undefined) { updates.push('contact_number = ?'); params.push(contact_number); }
    if (status !== undefined) {
      const allowedStatus = new Set(['Pending','In Progress','Completed','Deployed','Deferred']);
      if (!allowedStatus.has(status)) return res.status(400).json({ error: 'invalid status value' });
      updates.push('status = ?'); params.push(status);
    }
    if (priority !== undefined) {
      const allowedPriority = new Set(['P0','P1','P2']);
      if (!allowedPriority.has(priority)) return res.status(400).json({ error: 'invalid priority value' });
      updates.push('priority = ?'); params.push(priority);
    }
    if (startDate !== undefined) {
      const d = startDate ? new Date(startDate) : null;
      const v = d ? new Date(d.getTime() - d.getTimezoneOffset() * 60000) : null;
      updates.push('start_date = ?'); params.push(v);
    }
    if (endDate !== undefined) {
      const d = endDate ? new Date(endDate) : null;
      const v = d ? new Date(d.getTime() - d.getTimezoneOffset() * 60000) : null;
      updates.push('end_date = ?'); params.push(v);
    }

    if (!updates.length) return res.status(400).json({ error: 'no fields to update' });

    params.push(workId);
    await pool.query(`UPDATE work SET ${updates.join(', ')} WHERE id = ?`, params);

    const [rows] = await pool.query('SELECT * FROM work WHERE id = ?', [workId]);
    res.json(rows[0]);
  } catch (err) {
    console.error('Update work failed:', err?.message);
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

// --- start ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
