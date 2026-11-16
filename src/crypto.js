import crypto from 'node:crypto';
export const b64u = (b) => Buffer.from(b).toString('base64url');
export const unb64u = (s) => Buffer.from(s, 'base64url');
const P1363 = 'ieee-p1363'; // raw r||s, same as WebCrypto

export const kidOf = (jwk) =>
  b64u(crypto.createHash('sha256').update(jwk.x + jwk.y).digest()).slice(0, 8);

export function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' });
  return { kid: kidOf(pub), pub, priv: privateKey.export({ format: 'jwk' }) };
}

// QR text: QRT1.<payload>.<signature>; payload binds url + origin + path + expiry + nonce
export function signQr({ priv, kid }, url, ttl = 300) {
  const u = new URL(url);
  const payload = {
    v: 1, kid, url, origin: u.origin, path: u.pathname,
    exp: Math.floor(Date.now() / 1000) + ttl, n: b64u(crypto.randomBytes(8)),
  };
  const pb = Buffer.from(JSON.stringify(payload));
  const key = crypto.createPrivateKey({ key: priv, format: 'jwk' });
  const sig = crypto.sign('sha256', pb, { key, dsaEncoding: P1363 });
  return `QRT1.${b64u(pb)}.${b64u(sig)}`;
}

export function verifySig(pubJwk, payloadB64, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: pubJwk, format: 'jwk' });
    return crypto.verify('sha256', unb64u(payloadB64), { key, dsaEncoding: P1363 }, unb64u(sigB64));
  } catch { return false; }
}
