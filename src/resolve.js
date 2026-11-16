import dns from 'node:dns/promises';
import net from 'node:net';

const PRIVATE = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1$|fc|fd|fe80)/i;
async function safeHost(host) {
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  return addrs.every((a) => !PRIVATE.test(a.address));
}

// Follows redirects manually (max 5 hops), refuses private addresses (SSRF guard). Returns final URL.
// Caveat: DNS rebinding between check and fetch is not fully prevented; run in an isolated, egress-restricted sandbox.
export async function resolveFinal(start, maxHops = 5) {
  let url = start;
  for (let i = 0; i < maxHops; i++) {
    const u = new URL(url);
    if (!['https:', 'http:'].includes(u.protocol) || !(await safeHost(u.hostname))) throw new Error('blocked target');
    const r = await fetch(url, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const loc = r.headers.get('location');
    if (r.status < 300 || r.status >= 400 || !loc) return url;
    url = new URL(loc, url).toString();
  }
  throw new Error('too many redirects');
}
