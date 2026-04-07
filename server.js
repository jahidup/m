const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ========== ADMIN CREDENTIALS (4-field) ==========
const ADMIN_CONFIG = {
  USERNAME: "Shahid_Ansari",
  PASSWORD: "Tracker@3739",
  PIN: "2744",
  SECURITY_KEY: "NULL_PROTOCOL"
};

// ========== JWT SECRET ==========
const JWT_SECRET = 'null_protocol_super_secret_2025';

// ========== SQLite Database Setup ==========
const db = new sqlite3.Database('./database.sqlite');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    credits INTEGER DEFAULT 10,
    is_blocked INTEGER DEFAULT 0,
    created_at TEXT
  )`);

  // Search logs table
  db.run(`CREATE TABLE IF NOT EXISTS search_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    api_type TEXT,
    query TEXT,
    timestamp TEXT,
    response TEXT
  )`);

  // API Configurations table (dynamic APIs)
  db.run(`CREATE TABLE IF NOT EXISTS api_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT UNIQUE,
    url TEXT,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT
  )`);

  // Insert default APIs if table is empty
  db.get(`SELECT COUNT(*) as count FROM api_configs`, (err, row) => {
    if (err) return;
    if (row.count === 0) {
      const defaultApis = [
        { type: 'phone', url: 'https://ayaanmods.site/number.php?key=annonymous&number={query}', description: 'Phone number lookup' },
        { type: 'aadhaar', url: 'https://users-xinfo-admin.vercel.app/api?key=7demo&type=aadhar&term={query}', description: 'Aadhaar number lookup' },
        { type: 'ration', url: 'https://number8899.vercel.app/?type=family&aadhar={query}', description: 'Ration card details' },
        { type: 'vehicle', url: 'https://vehicle-info-aco-api.vercel.app/info?vehicle={query}', description: 'Vehicle registration details' },
        { type: 'vehicle_chalan', url: 'https://api.b77bf911.workers.dev/vehicle?registration={query}', description: 'Vehicle challan info' },
        { type: 'vehicle_pro', url: 'https://users-xinfo-admin.vercel.app/api?key=7demo&type=vehicle&term={query}', description: 'Advanced vehicle info' },
        { type: 'ifsc', url: 'https://ab-ifscinfoapi.vercel.app/info?ifsc={query}', description: 'IFSC code details' },
        { type: 'email', url: 'https://abbas-apis.vercel.app/api/email?mail={query}', description: 'Email lookup' },
        { type: 'pincode', url: 'https://api.postalpincode.in/pincode/{query}', description: 'Pincode details' },
        { type: 'gst', url: 'https://api.b77bf911.workers.dev/gst?number={query}', description: 'GST number lookup' },
        { type: 'tg_to_num', url: 'https://rootx-tg-num-multi.satyamrajsingh562.workers.dev/3/{query}?key=root', description: 'Telegram ID to number' },
        { type: 'ip_info', url: 'https://abbas-apis.vercel.app/api/ip?ip={query}', description: 'IP address info' },
        { type: 'ff_info', url: 'https://abbas-apis.vercel.app/api/ff-info?uid={query}', description: 'Free Fire player info' },
        { type: 'ff_ban', url: 'https://abbas-apis.vercel.app/api/ff-ban?uid={query}', description: 'Free Fire ban status' },
        { type: 'tg_info_pro', url: 'https://tg-to-num-six.vercel.app/?key=rootxsuryansh&q={query}', description: 'Telegram advanced info' },
        { type: 'tg_info', url: 'https://api.b77bf911.workers.dev/telegram?user={query}', description: 'Telegram basic info' },
        { type: 'insta_info', url: 'https://mkhossain.alwaysdata.net/instanum.php?username={query}', description: 'Instagram profile info' },
        { type: 'github_info', url: 'https://abbas-apis.vercel.app/api/github?username={query}', description: 'GitHub user info' }
      ];
      const stmt = db.prepare(`INSERT INTO api_configs (type, url, description, enabled, created_at) VALUES (?, ?, ?, 1, datetime('now'))`);
      defaultApis.forEach(api => {
        stmt.run(api.type, api.url, api.description);
      });
      stmt.finalize();
    }
  });
});

// ========== Helper: Verify Token (for users) ==========
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== NORMAL USER LOGIN (2 fields) ==========
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked. Contact admin.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: 'user' }, JWT_SECRET);
    res.json({ token, username: user.username, credits: user.credits, role: 'user' });
  });
});

// ========== ADMIN LOGIN (4 fields) ==========
app.post('/api/admin/login', (req, res) => {
  const { username, password, pin, securityKey } = req.body;
  if (username === ADMIN_CONFIG.USERNAME &&
      password === ADMIN_CONFIG.PASSWORD &&
      pin === ADMIN_CONFIG.PIN &&
      securityKey === ADMIN_CONFIG.SECURITY_KEY) {
    const token = jwt.sign({ username: ADMIN_CONFIG.USERNAME, role: 'admin' }, JWT_SECRET);
    res.json({ success: true, token, role: 'admin' });
  } else {
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ========== GET USER INFO (credits, status) ==========
app.get('/api/me', verifyToken, (req, res) => {
  db.get(`SELECT id, username, credits, is_blocked FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json({ credits: user.credits, is_blocked: user.is_blocked });
  });
});

// ========== GET AVAILABLE API TYPES (for user dropdown) ==========
app.get('/api/api-types', verifyToken, (req, res) => {
  db.all(`SELECT type, description FROM api_configs WHERE enabled = 1 ORDER BY type`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ========== SEARCH API (deducts credit) ==========
app.post('/api/search', verifyToken, async (req, res) => {
  const { apiType, query } = req.body;
  const userId = req.user.id;

  // First check user credits and block status
  db.get(`SELECT credits, is_blocked FROM users WHERE id = ?`, [userId], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    if (user.credits < 1) return res.status(402).json({ error: 'Insufficient credits. Contact admin.' });

    // Get API configuration from database
    db.get(`SELECT url FROM api_configs WHERE type = ? AND enabled = 1`, [apiType], async (err, apiConfig) => {
      if (err || !apiConfig) {
        return res.status(400).json({ error: 'API type not found or disabled' });
      }

      // Replace {query} placeholder in URL
      let apiUrl = apiConfig.url.replace('{query}', encodeURIComponent(query));
      
      // Deduct credit
      db.run(`UPDATE users SET credits = credits - 1 WHERE id = ?`, [userId]);

      let result = {};
      try {
        const response = await axios.get(apiUrl, { timeout: 15000 });
        result = response.data;
      } catch (error) {
        result = { error: 'API failed', message: error.message };
      }

      // Add branding
      result.developer = 'Shahid Ansari';
      result.powered_by = 'NULL PROTOCOL';

      // Log search
      db.run(`INSERT INTO search_logs (user_id, api_type, query, timestamp, response) VALUES (?, ?, ?, datetime('now'), ?)`,
        [userId, apiType, query, JSON.stringify(result)]);

      // Return updated credits
      db.get(`SELECT credits FROM users WHERE id = ?`, [userId], (err, updated) => {
        res.json({ success: true, credits_left: updated ? updated.credits : user.credits - 1, data: result });
      });
    });
  });
});

// ========== ADMIN APIs (require admin token) ==========
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Dashboard stats
app.get('/admin/stats', verifyAdmin, (req, res) => {
  db.get(`SELECT COUNT(*) as totalUsers, SUM(credits) as totalCredits FROM users`, (err, userStats) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as totalSearches FROM search_logs`, (err, searchStats) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({
        totalUsers: userStats.totalUsers || 0,
        totalCredits: userStats.totalCredits || 0,
        totalSearches: searchStats.totalSearches || 0
      });
    });
  });
});

// Get all users (with search)
app.get('/admin/users', verifyAdmin, (req, res) => {
  const search = req.query.search || '';
  let query = `SELECT id, username, credits, is_blocked, created_at FROM users`;
  let params = [];
  if (search) {
    query += ` WHERE username LIKE ?`;
    params.push(`%${search}%`);
  }
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Create new user
app.post('/admin/user', verifyAdmin, (req, res) => {
  const { username, password, credits, is_blocked } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, credits, is_blocked, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
    [username, hashed, credits || 10, is_blocked ? 1 : 0], function(err) {
      if (err) return res.status(400).json({ error: 'Username already exists' });
      res.json({ success: true, id: this.lastID });
    });
});

// Update user (credits, block status)
app.put('/admin/user/:id', verifyAdmin, (req, res) => {
  const { credits, is_blocked } = req.body;
  db.run(`UPDATE users SET credits = ?, is_blocked = ? WHERE id = ?`, [credits, is_blocked ? 1 : 0, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Bulk update credits (add credits to all users)
app.post('/admin/bulk-credits', verifyAdmin, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Valid amount required' });
  db.run(`UPDATE users SET credits = credits + ?`, [amount], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: `Added ${amount} credits to all users` });
  });
});

// Delete user
app.delete('/admin/user/:id', verifyAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true });
  });
});

// Get search logs (all or by user)
app.get('/admin/logs', verifyAdmin, (req, res) => {
  const userId = req.query.userId;
  let query = `
    SELECT l.id, l.user_id, u.username, l.api_type, l.query, l.timestamp, l.response 
    FROM search_logs l
    LEFT JOIN users u ON l.user_id = u.id
  `;
  let params = [];
  if (userId) {
    query += ` WHERE l.user_id = ?`;
    params.push(userId);
  }
  query += ` ORDER BY l.timestamp DESC LIMIT 200`;
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ========== API CONFIGURATION MANAGEMENT ==========
// Get all API configs
app.get('/admin/api-configs', verifyAdmin, (req, res) => {
  db.all(`SELECT * FROM api_configs ORDER BY type`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add new API config
app.post('/admin/api-configs', verifyAdmin, (req, res) => {
  const { type, url, description, enabled } = req.body;
  if (!type || !url) return res.status(400).json({ error: 'Type and URL required' });
  db.run(`INSERT INTO api_configs (type, url, description, enabled, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
    [type, url, description || '', enabled ? 1 : 0], function(err) {
      if (err) return res.status(400).json({ error: 'API type already exists' });
      res.json({ success: true, id: this.lastID });
    });
});

// Update API config
app.put('/admin/api-configs/:id', verifyAdmin, (req, res) => {
  const { type, url, description, enabled } = req.body;
  db.run(`UPDATE api_configs SET type = ?, url = ?, description = ?, enabled = ? WHERE id = ?`,
    [type, url, description || '', enabled ? 1 : 0, req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

// Delete API config
app.delete('/admin/api-configs/:id', verifyAdmin, (req, res) => {
  db.run(`DELETE FROM api_configs WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Test API endpoint
app.post('/admin/test-api', verifyAdmin, async (req, res) => {
  const { url, query } = req.body;
  let testUrl = url.replace('{query}', encodeURIComponent(query || 'test'));
  try {
    const response = await axios.get(testUrl, { timeout: 10000 });
    res.json({ success: true, data: response.data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ========== Serve frontend ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
