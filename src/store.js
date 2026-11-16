import fs from 'node:fs';
import path from 'node:path';

// Single-process replay store. consume() is atomic because Node runs it synchronously.
// For multiple instances, implement the same interface on Redis (SET key NX EXAT exp) or SQL (unique key).
export class NonceStore {
  constructor(file = null) {
    this.file = file; this.nonces = new Map();
    if (file && fs.existsSync(file)) {
      try { for (const [n, e] of Object.entries(JSON.parse(fs.readFileSync(file, 'utf8')))) this.nonces.set(n, e); } catch {}
    }
  }
  consume(nonce, exp) {
    this.purge();
    if (this.nonces.has(nonce)) return false;
    this.nonces.set(nonce, exp); this.save(); return true;
  }
  purge() { const now = Date.now() / 1000; for (const [n, e] of this.nonces) if (e < now) this.nonces.delete(n); }
  save() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.nonces)));
    fs.renameSync(tmp, this.file);
  }
}

// Trusted issuer keys with revocation: { kid: { jwk, revoked, note } }
export class KeyRegistry {
  constructor(file = null) {
    this.file = file; this.keys = {};
    if (file && fs.existsSync(file)) this.keys = JSON.parse(fs.readFileSync(file, 'utf8'));
  }
  add(kid, jwk, note = '') { this.keys[kid] = { jwk, revoked: false, note }; this.save(); }
  revoke(kid) { if (!this.keys[kid]) return false; this.keys[kid].revoked = true; this.save(); return true; }
  get(kid) { return this.keys[kid]; }
  save() { if (this.file) fs.writeFileSync(this.file, JSON.stringify(this.keys, null, 2)); }
}
