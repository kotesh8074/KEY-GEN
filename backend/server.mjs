import { createServer } from 'node:http';
import { createHash, createPrivateKey, randomUUID, sign, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const LICENSES_FILE = join(directory, 'issued-licenses.json');
const MAX_BODY_BYTES = 4096;

async function loadSavedLicenses() {
  try {
    const raw = await readFile(LICENSES_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Error reading saved licenses:', error);
    return [];
  }
}

async function saveIssuedLicenseRecord(record) {
  try {
    const list = await loadSavedLicenses();
    // Keep unique by activationKey / licenseId
    const filtered = list.filter(item => item.activationKey !== record.activationKey);
    filtered.unshift(record);
    // Keep the latest 500 records
    const trimmed = filtered.slice(0, 500);
    await writeFile(LICENSES_FILE, JSON.stringify(trimmed, null, 2), 'utf8');
    return trimmed;
  } catch (error) {
    console.error('Error saving license record:', error);
    return [];
  }
}

async function deleteSavedLicenseRecord(licenseId) {
  try {
    const list = await loadSavedLicenses();
    const filtered = list.filter(item => item.licenseId !== licenseId && item.activationKey !== licenseId);
    await writeFile(LICENSES_FILE, JSON.stringify(filtered, null, 2), 'utf8');
    return filtered;
  } catch (error) {
    console.error('Error deleting license record:', error);
    return [];
  }
}

function json(response, status, body) {
  response.writeHead(status, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
}

function html(response, status, content, type) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  response.end(content);
}

function constantTimeEqual(left, right) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function parsePrivateKey(keyInput) {
  const clean = (keyInput || '').trim().replace(/^["']|["']$/g, '');
  if (clean.includes('-----BEGIN')) {
    return createPrivateKey(clean);
  }
  try {
    const decoded = Buffer.from(clean, 'base64').toString('utf8');
    if (decoded.includes('-----BEGIN')) {
      return createPrivateKey(decoded);
    }
  } catch {}
  return createPrivateKey(clean);
}

function createTicket(licenseId, deviceId, expiresAt, issuedTo, contact, issuedAt, licenseType, privateKey) {
  const timeUrl = '';
  const payload = `${licenseId}|${deviceId}|${expiresAt}|${timeUrl}|${issuedTo}|${contact}|${issuedAt}|${licenseType}`;
  return {
    licenseId,
    deviceId,
    expiresAt,
    timeUrl,
    issuedTo,
    contact,
    issuedAt,
    licenseType,
    signature: sign(
      'RSA-SHA256',
      Buffer.from(payload),
      privateKey
    ).toString('base64')
  };
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw Object.assign(new Error('Request body is too large.'), { status: 413 });
    }
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    return body;
  } catch {
    throw Object.assign(new Error('Request must be a JSON object.'), { status: 400 });
  }
}

async function handleRequest(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    response.end();
    return;
  }

  if (request.method === 'GET' && url.pathname === '/health') {
    json(response, 200, { available: true });
    return;
  }

  if (request.method === 'GET' && ['/', '/admin', '/admin/'].includes(url.pathname)) {
    const content = await readFile(join(directory, 'public', 'admin.html'));
    html(response, 200, content, 'text/html; charset=utf-8');
    return;
  }

  if (!['/api/licenses', '/api/licenses/deactivate'].includes(url.pathname)) {
    json(response, 404, { error: 'Not found.' });
    return;
  }

  const adminToken = process.env.LICENSE_ADMIN_TOKEN;
  if (!adminToken) {
    json(response, 500, {
      error: 'LICENSE_ADMIN_TOKEN is not set in Render environment variables. Please add LICENSE_ADMIN_TOKEN in your Render dashboard.'
    });
    return;
  }

  const authHeader = request.headers.authorization || '';
  const suppliedToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!constantTimeEqual(suppliedToken, adminToken)) {
    json(response, 401, { error: 'Admin token is incorrect.' });
    return;
  }

  if (request.method === 'GET') {
    const records = await loadSavedLicenses();
    json(response, 200, { licenses: records });
    return;
  }

  if (request.method === 'DELETE') {
    const id = url.searchParams.get('id');
    if (!id) {
      json(response, 400, { error: 'License ID is required.' });
      return;
    }
    const updated = await deleteSavedLicenseRecord(id);
    json(response, 200, { success: true, licenses: updated });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/licenses/deactivate') {
    const body = await readJson(request);
    const key = body.id || body.activationKey || body.licenseId;
    if (!key) {
      json(response, 400, { error: 'Key is required to deactivate.' });
      return;
    }
    const records = await loadSavedLicenses();
    const updated = records.map(item => {
      if (item.activationKey === key || item.licenseId === key) {
        return {
          ...item,
          isDeactivated: true,
          deactivatedAt: new Date().toISOString()
        };
      }
      return item;
    });
    await writeFile(LICENSES_STORAGE_PATH, JSON.stringify(updated, null, 2), 'utf8');
    json(response, 200, { success: true, licenses: updated });
    return;
  }

  if (request.method !== 'POST') {
    json(response, 405, { error: 'Method not allowed.' });
    return;
  }

  let privateKeyRaw = process.env.LICENSE_PRIVATE_KEY_BASE64;
  if (!privateKeyRaw) {
    try {
      privateKeyRaw = (await readFile(join(directory, 'license-private-key.txt'), 'utf8')).trim();
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  if (!privateKeyRaw) {
    json(response, 503, {
      error: 'LICENSE_PRIVATE_KEY_BASE64 is not set in Render environment variables. Copy the contents of backend/license-private-key.txt to your Render environment variables.'
    });
    return;
  }

  let privateKey;
  try {
    privateKey = parsePrivateKey(privateKeyRaw);
  } catch (keyError) {
    console.error('Private key loading error:', keyError);
    json(response, 500, {
      error: `Server private key configuration error: ${keyError.message}`
    });
    return;
  }

  const body = await readJson(request);
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
  const issuedTo = typeof body.issuedTo === 'string' ? body.issuedTo.trim() : '';
  const contact = typeof body.contact === 'string' ? body.contact.trim() : '';
  const licenseType = body.licenseType;
  const expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt : '';
  const expiryDate = new Date(`${expiresAt}T00:00:00.000Z`);
  if (!deviceId || deviceId.length > 128) {
    json(response, 400, { error: 'Enter a valid device ID.' });
    return;
  }
  if (!issuedTo || issuedTo.length > 120) {
    json(response, 400, { error: 'Enter the name of the person or organization receiving this license.' });
    return;
  }
  if (contact.length > 120) {
    json(response, 400, { error: 'Contact details must be 120 characters or fewer.' });
    return;
  }
  if (!['new', 'renewal', 'deactivate'].includes(licenseType)) {
    json(response, 400, { error: 'Choose new activation, renewal, or deactivation.' });
    return;
  }

  const isDeactivation = licenseType === 'deactivate';
  if (!isDeactivation) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expiresAt)
      || Number.isNaN(expiryDate.getTime())
      || expiryDate.toISOString().slice(0, 10) !== expiresAt
      || expiresAt <= new Date().toISOString().slice(0, 10)) {
      json(response, 400, { error: 'Choose a valid expiry date in the future.' });
      return;
    }
  } else {
    expiresAt = new Date().toISOString().slice(0, 10);
  }

  const licenseId = randomUUID();
  const issuedAt = new Date().toISOString();
  
  // Calculate exact days for 25-digit key
  let safeDays;
  if (isDeactivation) {
    safeDays = 0;
  } else if (body.customDays && Number(body.customDays) > 0) {
    safeDays = Math.min(9999, Math.round(Number(body.customDays)));
  } else {
    const nowMs = Date.now();
    const expiryMs = expiryDate.getTime();
    safeDays = Math.max(1, Math.min(9999, Math.round((expiryMs - nowMs) / (1000 * 60 * 60 * 24))));
  }

  // Exact days header: '8' + 4-digit days (0 to 9999) + 15 random digits
  const header = `8${String(safeDays).padStart(4, '0')}`;
  let random15 = '';
  while (random15.length < 15) {
    const chunk = String(Math.floor(100000000 + Math.random() * 900000000));
    random15 += chunk;
  }
  random15 = random15.slice(0, 15);
  const payload20 = header + random15;

  // 5-digit algorithmic checksum
  let h1 = 5381;
  let h2 = 0;
  for (let i = 0; i < payload20.length; i++) {
    const code = payload20.charCodeAt(i);
    h1 = (((h1 << 5) + h1) + code) & 0x7FFFFFFF;
    h2 = (h2 * 31 + code * (i + 1) * 7) & 0x7FFFFFFF;
  }
  const checksumVal = Math.abs((h1 % 1000) * 100 + (h2 % 100)) % 100000;
  const checksum5 = String(checksumVal).padStart(5, '0');
  const full25 = payload20 + checksum5;

  // Format 25 digits as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
  const parts = [];
  for (let i = 0; i < full25.length; i += 5) {
    parts.push(full25.slice(i, i + 5));
  }
  const formatted25Key = parts.join('-');

  const ticket = createTicket(
    formatted25Key,
    deviceId,
    expiresAt,
    issuedTo,
    contact,
    issuedAt,
    licenseType,
    privateKey
  );
  const legacyKey = `LAB1-${Buffer.from(JSON.stringify(ticket)).toString('base64url')}`;

  const record = {
    licenseId: formatted25Key,
    activationKey: formatted25Key,
    legacyKey,
    key25Digit: formatted25Key,
    deviceId,
    issuedTo,
    contact,
    issuedAt,
    expiresAt,
    licenseType,
    days: safeDays,
    isDeactivated: isDeactivation
  };

  await saveIssuedLicenseRecord(record);
  json(response, 201, record);
}

const server = createServer((request, response) => {
  handleRequest(request, response).catch(error => {
    console.error('License service request failed:', error);
    if (!response.headersSent) {
      json(response, error.status || 500, {
        error: error.status
          ? error.message
          : 'Could not create the activation key.'
      });
    } else {
      response.destroy(error);
    }
  });
});

const port = Number(process.env.PORT || 3000);
// Render injects PORT (e.g. 10000). Always bind to 0.0.0.0 in cloud hosting (Render/Heroku/Railway) so public requests are routed.
const host = process.env.HOST || (process.env.PORT || process.env.RENDER || process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');
server.listen(port, host, () => {
  console.log(`Offline license generator listening at http://${host}:${port}.`);
});
