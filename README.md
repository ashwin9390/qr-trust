# qr-trust

Proof of concept for deciding whether a QR code can be trusted **before anything acts on it**.
A QR code is only text. This project signs that text, then verifies it on a server that also tracks replays and revoked issuers.

## What it checks

| Check | Stops |
|---|---|
| ECDSA P-256 signature from a trusted issuer | forged or altered codes, sticker swaps |
| Expiry | old codes reused later |
| Origin and path binding (signed into the payload) | open redirects, hijacked destinations |
| Landing-page check against the binding | redirect chains that end somewhere unsigned |
| Server-side one-time nonce store | replay of a photographed code |
| Key revocation | compromised issuer keys |
| URL policy (scheme, IP host, punycode, shorteners, credentials, allowlist) | unsigned lookalikes, `javascript:` payloads |

Verdicts: `TRUSTED`, `REVIEW`, `UNVERIFIED`, `SUSPICIOUS`, `BLOCKED`. Unsigned codes can never be `TRUSTED`.

## Quick start (Node 18+)

```bash
npm install          # optional: only needed for qr.png output
npm test             # 9 tests
npm run issue -- --url https://example.com/check --ttl 300
npm start            # verifier on :8787
```

`issue` creates `keys/issuer.json` (private, git-ignored) the first time and registers the public key in `trust/trusted-keys.json`.

```bash
curl -s localhost:8787/verify -H 'content-type: application/json' \
  -d '{"qr":"QRT1.…"}'
```

Send the same code twice to see the replay block. Pass `"landing":"https://other.site/"` to test a hijacked destination.

## API

- `POST /verify` with `{ qr, landing? }` returns `{ verdict, reason, checks, dest }`
- `GET /keys` lists issuer IDs and revocation state
- `POST /admin/revoke` with `{ kid }` and `Authorization: Bearer $ADMIN_TOKEN`
- `GET /health`

Environment: `PORT`, `ADMIN_TOKEN`, `ALLOW` (comma-separated domains for unsigned codes), `RESOLVE=1` (server follows redirects itself).

## Web demo

`web/index.html` is a single-file browser version (issue, attack lab, verify, threat model). Open it directly; keys live only for the session.

## Known limits

- The stock phone camera does not verify signatures. Users need a verifying scanner or an in-app scanner.
- `NonceStore` is file-backed and single-process. For several instances, implement the same `consume()` on Redis (`SET NX EXAT`) or a SQL unique key.
- `RESOLVE=1` has an SSRF guard and a hop cap, but DNS rebinding is not fully prevented. Run it in an egress-restricted sandbox.
- No rate limiting, TLS or auth on `/verify`. Put it behind a gateway.
- Issuer keys sit in a JSON file. Use an HSM or KMS in production.
- Trust enrollment (how a key gets into the registry) is the weakest link and is manual here.

## Publish to GitHub

```bash
git init && git add . && git commit -m "Initial commit: qr-trust PoC"
git branch -M main
git remote add origin https://github.com/ashwin9390/qr-trust.git
git push -u origin main
```

## License

MIT
