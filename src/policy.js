const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy'];

// Heuristic URL checks. Returns { checks: [[status, text]], score 0-100, block }
export function urlPolicy(raw, allow = []) {
  let u;
  try { u = new URL(raw); } catch { return { checks: [['fail', 'Not a valid URL']], score: 100, block: true }; }
  const checks = []; let score = 0; let block = false;
  if (u.protocol === 'https:') checks.push(['pass', 'Uses https']);
  else if (u.protocol === 'http:') { checks.push(['note', 'Plain http, not encrypted']); score += 30; }
  else { checks.push(['fail', `Dangerous scheme: ${u.protocol}`]); score += 100; block = true; }
  if (!block) {
    const h = u.hostname;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) { checks.push(['fail', 'Raw IP address as host']); score += 40; }
    if (h.includes('xn--') || /[^\x00-\x7f]/.test(raw)) { checks.push(['fail', 'Punycode or non-ASCII host']); score += 40; }
    if (SHORTENERS.includes(h)) { checks.push(['note', 'URL shortener hides destination']); score += 30; }
    if (u.username || raw.includes('@')) { checks.push(['fail', 'Credentials in URL']); score += 40; }
    if (h.split('.').length > 4) { checks.push(['note', 'Deep subdomain chain']); score += 15; }
    if (allow.length) {
      const ok = allow.some((d) => h === d || h.endsWith('.' + d));
      checks.push(ok ? ['pass', 'Domain on allowlist'] : ['note', 'Domain not on allowlist']);
      if (!ok) score += 25;
    }
  }
  return { checks, score: Math.min(score, 100), block };
}

// origin must match exactly; path must equal or sit under the signed path (whole segments)
export const inBinding = (u, p) =>
  u.origin === p.origin &&
  (u.pathname === p.path || u.pathname.startsWith(p.path.replace(/\/$/, '') + '/'));
