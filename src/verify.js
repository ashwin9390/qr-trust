import { verifySig, unb64u } from './crypto.js';
import { urlPolicy, inBinding } from './policy.js';

const res = (verdict, reason, checks, dest = '') => ({ verdict, reason, checks, dest });

// verdicts: TRUSTED | REVIEW | UNVERIFIED | SUSPICIOUS | BLOCKED
export function verifyQr(raw, { registry, store, allow = [], landing = '' }) {
  raw = String(raw || '').trim();
  if (!raw.startsWith('QRT1.')) {
    const q = urlPolicy(raw, allow);
    const checks = [['note', 'No signature, origin cannot be proven'], ...q.checks];
    if (q.block || q.score >= 60) return res('BLOCKED', `Unsigned and risky (score ${q.score}/100)`, checks, raw);
    if (q.score > 25) return res('SUSPICIOUS', `Unsigned with warning signs (score ${q.score}/100)`, checks, raw);
    return res('UNVERIFIED', `Unsigned; anyone could have printed it (score ${q.score}/100)`, checks, raw);
  }
  const [, pB64, sB64] = raw.split('.');
  let p;
  try { p = JSON.parse(unb64u(pB64).toString('utf8')); } catch { return res('BLOCKED', 'Malformed envelope', [['fail', 'Cannot parse payload']]); }
  const dest = p.url || '';
  const k = registry.get(p.kid);
  if (!k) return res('BLOCKED', 'Issuer not in trust list', [['fail', `Unknown issuer ${p.kid}`]], dest);
  if (k.revoked) return res('BLOCKED', 'Issuer key has been revoked', [['fail', `Issuer ${p.kid} revoked`]], dest);
  const checks = [['pass', `Issuer ${p.kid} is trusted`]];
  if (!verifySig(k.jwk, pB64, sB64)) return res('BLOCKED', 'Signature invalid: forged or altered', [...checks, ['fail', 'Signature invalid']], dest);
  checks.push(['pass', 'Signature valid, content intact']);
  if (p.exp < Date.now() / 1000) return res('BLOCKED', 'Code has expired', [...checks, ['fail', 'Expired']], dest);
  checks.push(['pass', 'Not expired']);

  let u; try { u = new URL(p.url); } catch { return res('BLOCKED', 'Signed URL is invalid', [...checks, ['fail', 'Bad URL']], dest); }
  if (!inBinding(u, p)) return res('BLOCKED', 'URL outside signed origin/path', [...checks, ['fail', 'Binding mismatch']], dest);
  checks.push(['pass', `URL matches signed origin ${p.origin}`]);
  if (landing) {
    let l; try { l = new URL(landing); } catch { l = null; }
    if (!l || !inBinding(l, p)) return res('BLOCKED', 'Landing page differs from signed origin: possible hijack or open redirect', [...checks, ['fail', `Landing ${landing} not signed`]], dest);
    checks.push(['pass', 'Landing page matches signed origin/path']);
  }
  const q = urlPolicy(p.url);
  if (q.block) return res('BLOCKED', 'Signed, but destination scheme is dangerous', [...checks, ...q.checks], dest);
  // Replay check last, so rejected attempts never burn a valid code's nonce
  if (!store.consume(p.n, p.exp)) return res('BLOCKED', 'Code already used: possible replay', [...checks, ['fail', 'Nonce already consumed']], dest);
  checks.push(['pass', 'First use of this code']);
  const hard = q.checks.some((c) => c[0] === 'fail');
  return hard
    ? res('REVIEW', 'Signature good but URL has red flags; check with the issuer', [...checks, ...q.checks], dest)
    : res('TRUSTED', 'Verified issuer, intact content, within validity', [...checks, ...q.checks], dest);
}
