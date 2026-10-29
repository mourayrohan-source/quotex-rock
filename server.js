/**
 * Quotex Premium / ROCK STAR - License Server
 * Features:
 *  - One license key = one device only
 *  - Time limited keys: 10min, 30min, 1hour, 1day, 1month, lifetime
 *  - Admin panel to generate / revoke keys
 *  - Simple JSON storage (no DB needed)
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3847;

// ============== CONFIG ==============
// Change this password before deploying!
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ROCKSTAR@2026';

// Data file
const DATA_FILE = path.join(__dirname, 'licenses.json');

// ============== STORAGE ==============
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Error loading licenses.json', e);
  }
  return { licenses: {}, adminLog: [] };
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

let db = loadData();

// ============== HELPERS ==============
function generateKey(prefix = 'ROCK') {
  // Format: ROCK-XXXX-XXXX-XXXX
  const part = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${prefix}-${part()}-${part()}-${part()}`;
}

function durationToMs(duration) {
  const map = {
    '10m': 10 * 60 * 1000,
    '30m': 30 * 60 * 1000,
    '1h': 60 * 60 * 1000,
    '1d': 24 * 60 * 60 * 1000,
    '1month': 30 * 24 * 60 * 60 * 1000,
    'lifetime': 100 * 365 * 24 * 60 * 60 * 1000 // ~100 years
  };
  return map[duration] || map['1d'];
}

function isExpired(license) {
  if (!license.expiresAt) return false;
  return Date.now() > license.expiresAt;
}

function cleanExpired() {
  let changed = false;
  for (const key of Object.keys(db.licenses)) {
    if (isExpired(db.licenses[key]) && db.licenses[key].status !== 'expired') {
      db.licenses[key].status = 'expired';
      changed = true;
    }
  }
  if (changed) saveData(db);
}

// ============== MIDDLEWARE ==============
app.use(cors({ origin: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple admin auth middleware
function requireAdmin(req, res, next) {
  const pwd = req.headers['x-admin-password'] || req.body.adminPassword || req.query.adminPassword;
  if (pwd !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Invalid admin password' });
  }
  next();
}

// ============== PUBLIC API ==============

/**
 * POST /api/validate
 * Body: { key: string, fingerprint: string, deviceInfo?: object }
 * 
 * Logic:
 * 1. Key must exist and not expired / revoked
 * 2. If key has no fingerprint yet → bind it to this device
 * 3. If key already has fingerprint → only same fingerprint is allowed
 */
app.post('/api/validate', (req, res) => {
  cleanExpired();

  const { key, fingerprint, deviceInfo } = req.body || {};

  if (!key || typeof key !== 'string' || key.trim().length < 4) {
    return res.json({ valid: false, message: 'Invalid license key' });
  }
  if (!fingerprint || typeof fingerprint !== 'string' || fingerprint.length < 8) {
    return res.json({ valid: false, message: 'Invalid device fingerprint' });
  }

  const normalizedKey = key.trim().toUpperCase();
  const license = db.licenses[normalizedKey];

  if (!license) {
    return res.json({ valid: false, message: 'License key not found' });
  }

  if (license.status === 'revoked') {
    return res.json({ valid: false, message: 'License has been revoked' });
  }

  if (isExpired(license)) {
    license.status = 'expired';
    saveData(db);
    return res.json({ valid: false, message: 'License has expired' });
  }

  // First activation → bind to this device
  if (!license.fingerprint) {
    license.fingerprint = fingerprint;
    license.activatedAt = Date.now();
    license.lastUsedAt = Date.now();
    license.deviceInfo = deviceInfo || {};
    license.status = 'active';
    saveData(db);

    return res.json({
      valid: true,
      message: 'License activated successfully on this device',
      data: {
        name: license.name || 'User',
        userName: license.name || 'User',
        licenseKey: normalizedKey,
        fingerprint: fingerprint,
        expiresAt: license.expiresAt,
        duration: license.duration,
        licenseValidated: true,
        timestamp: Date.now()
      }
    });
  }

  // Already bound → check fingerprint
  if (license.fingerprint !== fingerprint) {
    // Log attempted theft
    db.adminLog = db.adminLog || [];
    db.adminLog.push({
      type: 'device_mismatch',
      key: normalizedKey,
      expected: license.fingerprint,
      got: fingerprint,
      time: Date.now()
    });
    if (db.adminLog.length > 200) db.adminLog = db.adminLog.slice(-200);
    saveData(db);

    return res.json({
      valid: false,
      message: 'This license is already activated on another device. One key = One device only.'
    });
  }

  // Same device → allow
  license.lastUsedAt = Date.now();
  if (deviceInfo) license.deviceInfo = { ...license.deviceInfo, ...deviceInfo };
  saveData(db);

  return res.json({
    valid: true,
    message: 'License valid',
    data: {
      name: license.name || 'User',
      userName: license.name || 'User',
      licenseKey: normalizedKey,
      fingerprint: fingerprint,
      expiresAt: license.expiresAt,
      duration: license.duration,
      licenseValidated: true,
      timestamp: Date.now()
    }
  });
});

/**
 * POST /api/heartbeat
 * Optional periodic check
 */
app.post('/api/heartbeat', (req, res) => {
  const { key, fingerprint } = req.body || {};
  if (!key || !fingerprint) return res.json({ valid: false });

  const license = db.licenses[key.trim().toUpperCase()];
  if (!license || license.status === 'revoked' || isExpired(license)) {
    return res.json({ valid: false, message: 'License invalid or expired' });
  }
  if (license.fingerprint && license.fingerprint !== fingerprint) {
    return res.json({ valid: false, message: 'Device mismatch' });
  }

  license.lastUsedAt = Date.now();
  saveData(db);
  return res.json({ valid: true });
});

// ============== ADMIN API ==============

/**
 * POST /api/admin/generate
 * Body: { duration: '10m'|'30m'|'1h'|'1d'|'1month'|'lifetime', name?: string, count?: number, prefix?: string }
 */
app.post('/api/admin/generate', requireAdmin, (req, res) => {
  const { duration = '1d', name = '', count = 1, prefix = 'ROCK' } = req.body || {};

  const allowed = ['10m', '30m', '1h', '1d', '1month', 'lifetime'];
  if (!allowed.includes(duration)) {
    return res.status(400).json({ success: false, message: 'Invalid duration. Use: 10m, 30m, 1h, 1d, 1month, lifetime' });
  }

  const generated = [];
  const now = Date.now();
  const ms = durationToMs(duration);

  for (let i = 0; i < Math.min(count, 50); i++) {
    let key;
    do {
      key = generateKey(prefix);
    } while (db.licenses[key]);

    db.licenses[key] = {
      key,
      name: name || '',
      duration,
      createdAt: now,
      expiresAt: duration === 'lifetime' ? null : now + ms,
      fingerprint: null,          // bound on first use
      activatedAt: null,
      lastUsedAt: null,
      status: 'unused',
      deviceInfo: {}
    };
    generated.push(key);
  }

  saveData(db);

  res.json({
    success: true,
    message: `Generated ${generated.length} key(s)`,
    keys: generated,
    duration,
    expiresInMs: ms
  });
});

/**
 * POST /api/admin/revoke
 * Body: { key: string }
 */
app.post('/api/admin/revoke', requireAdmin, (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!db.licenses[key]) {
    return res.json({ success: false, message: 'Key not found' });
  }
  db.licenses[key].status = 'revoked';
  db.licenses[key].fingerprint = null; // free the device binding
  saveData(db);
  res.json({ success: true, message: 'License revoked' });
});

/**
 * POST /api/admin/unbind
 * Unbind device so key can be used on a new device (still respects expiry)
 */
app.post('/api/admin/unbind', requireAdmin, (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!db.licenses[key]) {
    return res.json({ success: false, message: 'Key not found' });
  }
  db.licenses[key].fingerprint = null;
  db.licenses[key].activatedAt = null;
  db.licenses[key].status = db.licenses[key].status === 'revoked' ? 'revoked' : 'unused';
  saveData(db);
  res.json({ success: true, message: 'Device unbound. Key can be activated on a new device.' });
});

/**
 * GET /api/admin/list
 */
app.get('/api/admin/list', requireAdmin, (req, res) => {
  cleanExpired();
  const list = Object.values(db.licenses).map(l => ({
    key: l.key,
    name: l.name,
    duration: l.duration,
    status: l.status,
    createdAt: l.createdAt,
    expiresAt: l.expiresAt,
    activatedAt: l.activatedAt,
    lastUsedAt: l.lastUsedAt,
    hasDevice: !!l.fingerprint,
    fingerprint: l.fingerprint ? l.fingerprint.slice(0, 12) + '...' : null
  }));
  // newest first
  list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json({ success: true, licenses: list, total: list.length });
});

/**
 * GET /api/admin/stats
 */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  cleanExpired();
  const all = Object.values(db.licenses);
  const stats = {
    total: all.length,
    unused: all.filter(l => l.status === 'unused').length,
    active: all.filter(l => l.status === 'active' && !isExpired(l)).length,
    expired: all.filter(l => isExpired(l) || l.status === 'expired').length,
    revoked: all.filter(l => l.status === 'revoked').length
  };
  res.json({ success: true, stats });
});

// ============== ADMIN UI ==============
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ============== START ==============
app.listen(PORT, () => {
  console.log(`\n🚀 Quotex License Server running on http://localhost:${PORT}`);
  console.log(`📋 Admin panel: http://localhost:${PORT}`);
  console.log(`🔑 Admin password: ${ADMIN_PASSWORD}`);
  console.log(`⚠️  Change ADMIN_PASSWORD env var before production!\n`);
});
