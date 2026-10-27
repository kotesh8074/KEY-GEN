import { createServer } from 'node:http';
import { createHash, createPrivateKey, randomUUID, sign, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const MAX_BODY_BYTES = 4096;

function json(response, status, body) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
}

function html(response, status, content, type) {
  const source = content.toString('utf8');
  const scriptHashes = [...source.matchAll(/<script>([\s\S]*?)<\/script>/gi)]
    .map(([, script]) => `'sha256-${createHash('sha256').update(script).digest('base64')}'`)
    .join(' ');
  const styleHashes = [...source.matchAll(/<style>([\s\S]*?)<\/style>/gi)]
    .map(([, style]) => `'sha256-${createHash('sha256').update(style).digest('base64')}'`)
    .join(' ');
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'self'; script-src 'self' ${scriptHashes}; style-src 'self' ${styleHashes}; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
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

  if (request.method === 'GET' && url.pathname === '/health') {
    json(response, 200, { available: true });
    return;
  }

  if (request.method === 'GET' && ['/', '/admin', '/admin/'].includes(url.pathname)) {
    const content = await readFile(join(directory, 'public', 'admin.html'));
    html(response, 200, content, 'text/html; charset=utf-8');
    return;
  }

  if (request.method !== 'POST' || url.pathname !== '/api/licenses') {
    json(response, 404, { error: 'Not found.' });
    return;
  }

  const adminToken = process.env.LICENSE_ADMIN_TOKEN;
  const authHeader = request.headers.authorization || '';
  const suppliedToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!adminToken || !constantTimeEqual(suppliedToken, adminToken)) {
    json(response, 401, { error: 'Admin token is incorrect.' });
    return;
  }

  let privateKeyBase64 = process.env.LICENSE_PRIVATE_KEY_BASE64;
  if (!privateKeyBase64) {
    try {
      privateKeyBase64 = (await readFile(join(directory, 'license-private-key.txt'), 'utf8')).trim();
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  if (!privateKeyBase64) {
    json(response, 503, { error: 'License signing is not configured on the server.' });
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
  if (!['new', 'renewal'].includes(licenseType)) {
    json(response, 400, { error: 'Choose new activation or renewal.' });
    return;
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(expiresAt)
    || Number.isNaN(expiryDate.getTime())
    || expiryDate.toISOString().slice(0, 10) !== expiresAt
    || expiresAt <= new Date().toISOString().slice(0, 10)) {
    json(response, 400, { error: 'Choose a valid expiry date in the future.' });
    return;
  }

  const licenseId = randomUUID();
  const issuedAt = new Date().toISOString();
  
  // Calculate days until expiry for 25-digit key
  const nowMs = Date.now();
  const expiryMs = expiryDate.getTime();
  const diffDays = Math.max(1, Math.round((expiryMs - nowMs) / (1000 * 60 * 60 * 24)));

  // Generate standard 25-digit key matching app verification logic
  let durationCode = '36';
  if (diffDays > 3000) durationCode = '99';
  else if (diffDays > 500) durationCode = '73';
  else if (diffDays <= 180) durationCode = '18';

  let random18 = '';
  while (random18.length < 18) {
    const chunk = String(Math.floor(100000000 + Math.random() * 900000000));
    random18 += chunk;
  }
  random18 = random18.slice(0, 18);
  const payload20 = durationCode + random18;

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
    createPrivateKey(Buffer.from(privateKeyBase64, 'base64').toString('utf8'))
  );
  const legacyKey = `LAB1-${Buffer.from(JSON.stringify(ticket)).toString('base64url')}`;

  json(response, 201, {
    activationKey: formatted25Key,
    legacyKey,
    key25Digit: formatted25Key,
    licenseId: formatted25Key,
    deviceId,
    issuedTo,
    contact,
    issuedAt,
    expiresAt,
    licenseType
  });
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
const host = process.env.HOST || (process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');
server.listen(port, host, () => {
  console.log(`Offline license generator listening at http://${host}:${port}.`);
});
