import fs from 'node:fs';
import { genKeyPair, signQr } from '../src/crypto.js';
import { KeyRegistry } from '../src/store.js';

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const url = arg('url'); const ttl = +arg('ttl', 300); const keyFile = arg('keys', 'keys/issuer.json');
if (!url) { console.error('usage: npm run issue -- --url https://example.com/path [--ttl 300] [--keys keys/issuer.json]'); process.exit(1); }

let key;
if (fs.existsSync(keyFile)) key = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
else {
  key = genKeyPair();
  fs.writeFileSync(keyFile, JSON.stringify(key), { mode: 0o600 });
  new KeyRegistry('trust/trusted-keys.json').add(key.kid, key.pub, 'issuer created by cli');
  console.error(`New issuer ${key.kid}: private key in ${keyFile} (never commit), public key added to trust/trusted-keys.json`);
}
const text = signQr(key, url, ttl);
console.log(text);
try {
  const QR = (await import('qrcode')).default;
  await QR.toFile('qr.png', text, { errorCorrectionLevel: 'M', margin: 2, width: 512 });
  console.error('Wrote qr.png');
} catch { console.error('Install the optional "qrcode" package to also write qr.png'); }
