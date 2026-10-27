import { generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 3072,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const backendDirectory = join(scriptDirectory, '..');
const projectDirectory = join(backendDirectory, '..');
const privateKeyPath = join(backendDirectory, 'license-private-key.txt');
const envPath = join(projectDirectory, '.env.local');
const publicKeyLine = `VITE_LICENSE_PUBLIC_KEY_BASE64=${Buffer.from(publicKey, 'utf8').toString('base64')}`;

let envContent = '';
try {
  envContent = await readFile(envPath, 'utf8');
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const envLines = envContent.split(/\r?\n/);
const publicKeyIndex = envLines.findIndex(line => line.startsWith('VITE_LICENSE_PUBLIC_KEY_BASE64='));
if (publicKeyIndex >= 0) {
  envLines[publicKeyIndex] = publicKeyLine;
} else {
  if (envLines.length && envLines[envLines.length - 1] === '') envLines.pop();
  envLines.push(publicKeyLine);
}

await writeFile(envPath, `${envLines.join('\n')}\n`, 'utf8');
await writeFile(privateKeyPath, Buffer.from(privateKey, 'utf8').toString('base64'), { encoding: 'utf8', mode: 0o600 });

console.log('Setup complete.');
console.log('Public key saved to the project .env.local file.');
console.log(`Private key saved here: ${privateKeyPath}`);
console.log('Keep the private key secret. Use create-offline-license.mjs to issue signed offline licenses.');
