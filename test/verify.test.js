import test from 'node:test';
import assert from 'node:assert/strict';
import { genKeyPair, signQr, b64u } from '../src/crypto.js';
import { KeyRegistry, NonceStore } from '../src/store.js';
import { verifyQr } from '../src/verify.js';

const setup = () => {
  const issuer = genKeyPair(); const registry = new KeyRegistry(); registry.add(issuer.kid, issuer.pub);
  return { issuer, registry, store: new NonceStore() };
};
const URL1 = 'https://example.com/check';

test('valid code is TRUSTED, second use is blocked as replay', () => {
  const { issuer, registry, store } = setup(); const qr = signQr(issuer, URL1);
  assert.equal(verifyQr(qr, { registry, store }).verdict, 'TRUSTED');
  assert.equal(verifyQr(qr, { registry, store }).verdict, 'BLOCKED');
});
test('forged signature with real kid is BLOCKED', () => {
  const { issuer, registry, store } = setup(); const rogue = genKeyPair();
  const qr = signQr({ priv: rogue.priv, kid: issuer.kid }, URL1);
  assert.match(verifyQr(qr, { registry, store }).reason, /Signature invalid/);
});
test('tampered URL is BLOCKED', () => {
  const { issuer, registry, store } = setup(); const [a, b, c] = signQr(issuer, URL1).split('.');
  const p = JSON.parse(Buffer.from(b, 'base64url')); p.url = 'https://evil.example.net/login';
  assert.equal(verifyQr([a, b64u(JSON.stringify(p)), c].join('.'), { registry, store }).verdict, 'BLOCKED');
});
test('expired code is BLOCKED', () => {
  const { issuer, registry, store } = setup();
  assert.match(verifyQr(signQr(issuer, URL1, -5), { registry, store }).reason, /expired/);
});
test('revoked issuer is BLOCKED', () => {
  const { issuer, registry, store } = setup(); const qr = signQr(issuer, URL1); registry.revoke(issuer.kid);
  assert.match(verifyQr(qr, { registry, store }).reason, /revoked/);
});
test('hijacked landing page is BLOCKED and does not burn the nonce', () => {
  const { issuer, registry, store } = setup(); const qr = signQr(issuer, URL1);
  assert.match(verifyQr(qr, { registry, store, landing: 'https://evil.example.net/check' }).reason, /hijack/);
  assert.equal(verifyQr(qr, { registry, store, landing: 'https://example.com/check' }).verdict, 'TRUSTED');
});
test('sibling path is outside the binding', () => {
  const { issuer, registry, store } = setup();
  assert.equal(verifyQr(signQr(issuer, URL1), { registry, store, landing: 'https://example.com/check-evil' }).verdict, 'BLOCKED');
});
test('signed javascript: URL is BLOCKED', () => {
  const { issuer, registry, store } = setup();
  assert.equal(verifyQr(signQr(issuer, 'javascript:alert(1)'), { registry, store }).verdict, 'BLOCKED');
});
test('unsigned codes are never TRUSTED', () => {
  const { registry, store } = setup();
  assert.equal(verifyQr('https://example.com/check', { registry, store }).verdict, 'UNVERIFIED');
  assert.equal(verifyQr('https://examp1e.xn--com/x', { registry, store }).verdict, 'SUSPICIOUS');
  assert.equal(verifyQr('http://paypal.com@evil.example.net/login', { registry, store }).verdict, 'BLOCKED');
});
