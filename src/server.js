import http from 'node:http';
import { KeyRegistry, NonceStore } from './store.js';
import { verifyQr } from './verify.js';
import { resolveFinal } from './resolve.js';

export function createServer({ registry, store, adminToken = '', resolve = false, allow = [] }) {
  return http.createServer(async (req, res) => {
    const send = (c, o) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    const body = () => new Promise((ok, no) => {
      let d = ''; req.on('data', (c) => { d += c; if (d.length > 8192) { no(new Error('too large')); req.destroy(); } });
      req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch (e) { no(e); } });
    });
    try {
      if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true });
      if (req.method === 'GET' && req.url === '/keys') {
        return send(200, Object.fromEntries(Object.entries(registry.keys).map(([k, v]) => [k, { revoked: v.revoked, note: v.note }])));
      }
      if (req.method === 'POST' && req.url === '/verify') {
        const { qr, landing } = await body();
        let land = landing || '';
        if (!land && resolve && String(qr).startsWith('QRT1.')) {
          try {
            const p = JSON.parse(Buffer.from(qr.split('.')[1], 'base64url').toString());
            land = await resolveFinal(p.url);
          } catch { land = 'https://resolve-failed.invalid/'; }
        }
        return send(200, verifyQr(qr, { registry, store, allow, landing: land }));
      }
      if (req.method === 'POST' && req.url === '/admin/revoke') {
        if (!adminToken || req.headers.authorization !== `Bearer ${adminToken}`) return send(401, { error: 'unauthorized' });
        const { kid } = await body();
        return send(registry.revoke(kid) ? 200 : 404, { kid, revoked: registry.get(kid)?.revoked ?? false });
      }
      send(404, { error: 'not found' });
    } catch (e) { send(400, { error: String(e.message || e) }); }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = process.env.PORT || 8787;
  createServer({
    registry: new KeyRegistry('trust/trusted-keys.json'),
    store: new NonceStore('data/nonces.json'),
    adminToken: process.env.ADMIN_TOKEN || '',
    resolve: process.env.RESOLVE === '1',
    allow: (process.env.ALLOW || '').split(',').filter(Boolean),
  }).listen(port, () => console.log(`qr-trust verifier on :${port}`));
}
