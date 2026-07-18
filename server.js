require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const ORDER_TIMEOUT_MS = 15 * 60 * 1000;
const POLL_INTERVAL_MS = 5000;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Check your .env file.');
  process.exit(1);
}

const SERVICE_CATALOG = {
  google: { label: 'Google / Gmail', wholesalePrice: 0.30 },
  amazon: { label: 'Amazon', wholesalePrice: 0.35 },
  whatsapp: { label: 'WhatsApp', wholesalePrice: 0.55 },
  facebook: { label: 'Facebook', wholesalePrice: 0.25 },
  discord: { label: 'Discord', wholesalePrice: 0.20 },
  telegram: { label: 'Telegram', wholesalePrice: 0.40 },
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function initSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        balance       NUMERIC(10,2) NOT NULL DEFAULT 0.00,
        is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id                SERIAL PRIMARY KEY,
        user_id           INTEGER NOT NULL REFERENCES users(id),
        service           TEXT NOT NULL,
        phone_number      TEXT,
        provider_order_id TEXT,
        sms_code          TEXT,
        retail_price      NUMERIC(10,2) NOT NULL,
        status            TEXT NOT NULL DEFAULT 'pending',
        created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at        TIMESTAMPTZ NOT NULL,
        completed_at      TIMESTAMPTZ
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);

    await client.query(
      `INSERT INTO settings (key, value)
       VALUES ('retail_markup_percentage', $1)
       ON CONFLICT (key) DO NOTHING`,
      [process.env.RETAIL_MARKUP_PERCENTAGE || '35']
    );

    await client.query('COMMIT');
    console.log('[db] schema ready');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[db] schema init failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

async function getMarkupPercentage() {
  const result = await pool.query(
    `SELECT value FROM settings WHERE key = 'retail_markup_percentage'`
  );
  return parseFloat(result.rows[0]?.value ?? '35');
}

const providerClient = axios.create({
  baseURL: process.env.PROVIDER_BASE_URL,
  timeout: 10000,
  headers: {
    Authorization: `Bearer ${process.env.PROVIDER_API_KEY}`,
  },
});

async function requestNumberFromProvider(service) {
  const { data } = await providerClient.post('/numbers/request', { service });
  return {
    phoneNumber: data.phone_number,
    providerOrderId: data.order_id,
  };
}

async function checkProviderSmsStatus(providerOrderId) {
  const { data } = await providerClient.get(`/numbers/status/${providerOrderId}`);
  return {
    received: data.status === 'received',
    code: data.code || null,
  };
}

async function cancelNumberOnProvider(providerOrderId) {
  try {
    await providerClient.post(`/numbers/cancel/${providerOrderId}`);
  } catch (err) {
    console.warn(`[provider] cancel failed for ${providerOrderId}:`, err.message);
  }
}

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: process.env.CLIENT_ORIGIN || '*' },
});

app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json());
app.use(express.static('public'));

function emitToUser(userId, event, payload) {
  io.to(`user:${userId}`).emit(event, payload);
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing auth token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  next();
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash) VALUES ($1, $2)
       RETURNING id, email, balance, is_admin`,
      [email.toLowerCase().trim(), passwordHash]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, isAdmin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    console.error('[auth/register] error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [
      email?.toLowerCase().trim(),
    ]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, isAdmin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, balance: user.balance, isAdmin: user.is_admin },
    });
  } catch (err) {
    console.error('[auth/login] error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/services', requireAuth, async (req, res) => {
  try {
    const markup = await getMarkupPercentage();
    const catalog = Object.entries(SERVICE_CATALOG).map(([key, val]) => ({
      key,
      label: val.label,
      price: Number((val.wholesalePrice * (1 + markup / 100)).toFixed(2)),
    }));
    res.json({ services: catalog });
  } catch (err) {
    console.error('[services] error:', err);
    res.status(500).json({ error: 'Failed to load service catalog' });
  }
});

app.post('/api/verifications/request', requireAuth, async (req, res) => {
  const { service } = req.body;
  const userId = req.user.id;

  const serviceDef = SERVICE_CATALOG[service];
  if (!serviceDef) {
    return res.status(400).json({ error: `Unsupported service: ${service}` });
  }

  const client = await pool.connect();
  let retailPrice;
  let order;

  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      `SELECT id, balance FROM users WHERE id = $1 FOR UPDATE`,
      [userId]
    );
    const user = userResult.rows[0];
    if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

    const markup = await getMarkupPercentage();
    retailPrice = Number((serviceDef.wholesalePrice * (1 + markup / 100)).toFixed(2));

    if (Number(user.balance) < retailPrice) {
      await client.query('ROLLBACK');
      return res.status(402).json({
        error: 'Insufficient balance',
        required: retailPrice,
        balance: Number(user.balance),
      });
    }

    await client.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [
      retailPrice,
      userId,
    ]);

    let phoneNumber, providerOrderId;
    try {
      ({ phoneNumber, providerOrderId } = await requestNumberFromProvider(service));
    } catch (providerErr) {
      await client.query('ROLLBACK');
      console.error('[verifications/request] provider error:', providerErr.message);
      return res.status(502).json({ error: 'Provider is unable to allocate a number right now' });
    }

    const expiresAt = new Date(Date.now() + ORDER_TIMEOUT_MS);
    const insertResult = await client.query(
      `INSERT INTO orders
         (user_id, service, phone_number, provider_order_id, retail_price, status, expires_at)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6)
       RETURNING *`,
      [userId, service, phoneNumber, providerOrderId, retailPrice, expiresAt]
    );
    order = insertResult.rows[0];

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[verifications/request] error:', err);
    return res.status(err.status || 500).json({ error: err.message || 'Request failed' });
  } finally {
    client.release();
  }

  emitToUser(userId, 'order:created', order);
  startPollingLoop(order);

  res.status(201).json({ order });
});

app.post('/api/verifications/cancel/:orderId', requireAuth, async (req, res) => {
  const { orderId } = req.params;
  const userId = req.user.id;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const orderResult = await client.query(
      `SELECT * FROM orders WHERE id = $1 AND user_id = $2 FOR UPDATE`,
      [orderId, userId]
    );
    const order = orderResult.rows[0];

    if (!order) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }
    if (order.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `Order already ${order.status}` });
    }

    await client.query(`UPDATE orders SET status = 'cancelled' WHERE id = $1`, [orderId]);
    await client.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [
      order.retail_price,
      userId,
    ]);

    await client.query('COMMIT');

    activePolls.delete(order.id);
    cancelNumberOnProvider(order.provider_order_id);
    emitToUser(userId, 'order:cancelled', { orderId: order.id, refunded: order.retail_price });

    res.json({ message: 'Order cancelled and refunded' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[verifications/cancel] error:', err);
    res.status(500).json({ error: 'Cancellation failed' });
  } finally {
    client.release();
  }
});

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({ orders: result.rows });
  } catch (err) {
    console.error('[orders] error:', err);
    res.status(500).json({ error: 'Failed to load orders' });
  }
});

app.get('/api/wallet', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT balance FROM users WHERE id = $1`, [req.user.id]);
    res.json({ balance: Number(result.rows[0]?.balance ?? 0) });
  } catch (err) {
    console.error('[wallet] error:', err);
    res.status(500).json({ error: 'Failed to load wallet' });
  }
});

const activePolls = new Map();

function startPollingLoop(order) {
  const { id: orderId, user_id: userId, provider_order_id: providerOrderId } = order;
  const expiresAtMs = new Date(order.expires_at).getTime();

  const intervalId = setInterval(async () => {
    try {
      const { received, code } = await checkProviderSmsStatus(providerOrderId);

      if (received && code) {
        stopPollingLoop(orderId);
        await pool.query(
          `UPDATE orders
             SET status = 'completed', sms_code = $1, completed_at = NOW()
           WHERE id = $2 AND status = 'pending'`,
          [code, orderId]
        );
        emitToUser(userId, 'sms:received', { orderId, code });
        return;
      }

      if (Date.now() >= expiresAtMs) {
        await expireOrder(orderId, userId, providerOrderId);
      }
    } catch (err) {
      console.warn(`[poll] order ${orderId} check failed:`, err.message);
    }
  }, POLL_INTERVAL_MS);

  const timeoutId = setTimeout(() => {
    expireOrder(orderId, userId, providerOrderId);
  }, Math.max(expiresAtMs - Date.now(), 0));

  activePolls.set(orderId, { intervalId, timeoutId });
}

function stopPollingLoop(orderId) {
  const handles = activePolls.get(orderId);
  if (handles) {
    clearInterval(handles.intervalId);
    clearTimeout(handles.timeoutId);
    activePolls.delete(orderId);
  }
}

async function expireOrder(orderId, userId, providerOrderId) {
  stopPollingLoop(orderId);
  try {
    const result = await pool.query(
      `UPDATE orders SET status = 'expired' WHERE id = $1 AND status = 'pending' RETURNING retail_price`,
      [orderId]
    );
    if (result.rowCount === 0) return;

    const refund = result.rows[0].retail_price;
    await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [refund, userId]);
    cancelNumberOnProvider(providerOrderId);
    emitToUser(userId, 'order:expired', { orderId, refunded: refund });
  } catch (err) {
    console.error(`[expireOrder] failed for order ${orderId}:`, err);
  }
}

app.post('/api/admin/markup', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { percentage } = req.body;
    if (typeof percentage !== 'number' || percentage < 0) {
      return res.status(400).json({ error: 'percentage must be a non-negative number' });
    }
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ('retail_markup_percentage', $1)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [String(percentage)]
    );
    res.json({ message: 'Markup updated', percentage });
  } catch (err) {
    console.error('[admin/markup] error:', err);
    res.status(500).json({ error: 'Failed to update markup' });
  }
});

app.post('/api/admin/topup', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { userId, amount } = req.body;
    if (!userId || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ error: 'userId and a positive amount are required' });
    }
    const result = await pool.query(
      `UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING id, email, balance`,
      [amount, userId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });

    emitToUser(userId, 'wallet:updated', { balance: Number(result.rows[0].balance) });
    res.json({ message: 'Balance topped up', user: result.rows[0] });
  } catch (err) {
    console.error('[admin/topup] error:', err);
    res.status(500).json({ error: 'Failed to top up balance' });
  }
});

app.get('/api/admin/revenue', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [revenueResult, usersResult, ordersResult] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(retail_price), 0) AS total
           FROM orders WHERE status = 'completed'`
      ),
      pool.query(`SELECT COUNT(*) AS total FROM users`),
      pool.query(`SELECT status, COUNT(*) AS count FROM orders GROUP BY status`),
    ]);

    res.json({
      totalRevenue: Number(revenueResult.rows[0].total),
      totalUsers: Number(usersResult.rows[0].total),
      ordersByStatus: ordersResult.rows,
    });
  } catch (err) {
    console.error('[admin/revenue] error:', err);
    res.status(500).json({ error: 'Failed to load revenue metrics' });
  }
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, balance, is_admin, created_at FROM users ORDER BY created_at DESC LIMIT 100`
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error('[admin/users] error:', err);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Missing auth token'));
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    next(new Error('Invalid auth token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  socket.join(`user:${userId}`);
  console.log(`[socket] user ${userId} connected (${socket.id})`);

  socket.on('disconnect', () => {
    console.log(`[socket] user ${userId} disconnected (${socket.id})`);
  });
});

app.use((err, req, res, next) => {
  console.error('[unhandled error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function start() {
  try {
    await initSchema();
    httpServer.listen(PORT, () => {
      console.log(`[server] listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('[server] failed to start:', err);
    process.exit(1);
  }
}

start();