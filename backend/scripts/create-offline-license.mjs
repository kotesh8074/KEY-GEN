import { createPrivateKey, randomUUID, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const [deviceId, expiresAt, issuedTo = 'Local administrator', contact = '', licenseTypeArg = 'new'] = process.argv.slice(2);
const licenseType = licenseTypeArg;
const recipient = issuedTo.trim();
const recipientContact = contact.trim();
if (!deviceId || deviceId.length > 128 || !recipient || recipient.length > 120
  || recipientContact.length > 120 || !['new', 'renewal'].includes(licenseType)
  || !/^\d{4}-\d{2}-\d{2}$/.test(expiresAt || '')) {
  console.error('Usage: node backend/scripts/create-offline-license.mjs <device-id> <YYYY-MM-DD> [issued-to] [contact] [new|renewal]');
  process.exitCode = 1;
} else {
  const expiryDate = new Date(`${expiresAt}T00:00:00.000Z`);
  if (Number.isNaN(expiryDate.getTime())
    || expiryDate.toISOString().slice(0, 10) !== expiresAt
    || expiresAt <= new Date().toISOString().slice(0, 10)) {
    throw new Error('Expiry date must be a valid future date.');
  }

  const scriptDirectory = dirname(fileURLToPath(import.meta.url));
  const privateKeyPath = join(scriptDirectory, '..', 'license-private-key.txt');
  const privateKeyBase64 = (await readFile(privateKeyPath, 'utf8')).trim();
  if (!privateKeyBase64) throw new Error('The license signing private key file is empty.');
  const privateKey = createPrivateKey(Buffer.from(privateKeyBase64, 'base64').toString('utf8'));
  const licenseId = randomUUID();
  const timeUrl = '';
  const issuedAt = new Date().toISOString();
  const payload = `${licenseId}|${deviceId}|${expiresAt}|${timeUrl}|${recipient}|${recipientContact}|${issuedAt}|${licenseType}`;
  const ticket = {
    licenseId,
    deviceId,
    expiresAt,
    timeUrl,
    issuedTo: recipient,
    contact: recipientContact,
    issuedAt,
    licenseType,
    signature: sign(
      'RSA-SHA256',
      Buffer.from(payload),
      privateKey
    ).toString('base64')
  };

  // Compute 25-digit offline key
  const diffDays = Math.max(1, Math.round((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
  let durationCode = '36';
  if (diffDays > 3000) durationCode = '99';
  else if (diffDays > 500) durationCode = '73';
  else if (diffDays <= 180) durationCode = '18';

  let random18 = '';
  while (random18.length < 18) {
    random18 += String(Math.floor(100000000 + Math.random() * 900000000));
  }
  random18 = random18.slice(0, 18);
  const payload20 = durationCode + random18;

  let h1 = 5381, h2 = 0;
  for (let i = 0; i < payload20.length; i++) {
    const code = payload20.charCodeAt(i);
    h1 = (((h1 << 5) + h1) + code) & 0x7FFFFFFF;
    h2 = (h2 * 31 + code * (i + 1) * 7) & 0x7FFFFFFF;
  }
  const checksum5 = String(Math.abs((h1 % 1000) * 100 + (h2 % 100)) % 100000).padStart(5, '0');
  const full25 = payload20 + checksum5;
  const parts = [];
  for (let i = 0; i < full25.length; i += 5) parts.push(full25.slice(i, i + 5));
  const key25 = parts.join('-');

  console.log(`25-Digit Key: ${key25}`);
  console.log(`Legacy Key: LAB1-${Buffer.from(JSON.stringify(ticket)).toString('base64url')}`);
}
