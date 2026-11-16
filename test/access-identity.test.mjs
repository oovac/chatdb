import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { ACCESS_ISSUER, ACCESS_AUDIENCE, verifyAccessIdentity, accessUserId } from '../lib/access-identity.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };
const fakeFetch = async () => ({ ok: true, json: async () => ({ keys: [publicJwk] }) });
const b64 = (x) => Buffer.from(JSON.stringify(x)).toString('base64url');
const makeToken = (overrides = {}, key = privateKey) => {
  const now = Math.floor(Date.now() / 1000);
  const header = b64({ alg: 'RS256', kid: 'test-key' });
  const payload = b64({ iss: ACCESS_ISSUER, aud: [ACCESS_AUDIENCE], sub: 'owner-subject', email: 'owner@example.com', iat: now - 10, exp: now + 600, ...overrides });
  const data = header + '.' + payload;
  return data + '.' + sign('RSA-SHA256', Buffer.from(data), key).toString('base64url');
};
const request = (token) => new Headers(token ? { 'cf-access-jwt-assertion': token } : {});

test('authenticates a properly signed JWT with audience, issuer and unexpired claims', async () => {
  const identity = await verifyAccessIdentity(request(makeToken()), { fetchImpl: fakeFetch });
  assert.deepEqual(identity, { sub: 'owner-subject', email: 'owner@example.com' });
});
test('fails closed on missing, malformed or tampered tokens', async () => {
  assert.equal(await verifyAccessIdentity(request(), { fetchImpl: fakeFetch }), null);
  assert.equal(await verifyAccessIdentity(request('invalid'), { fetchImpl: fakeFetch }), null);
  const token = makeToken();
  const parts = token.split('.');
  parts[1] = b64({ iss: ACCESS_ISSUER, aud: ACCESS_AUDIENCE, sub: 'attacker', exp: Date.now()/1000 + 3600 });
  assert.equal(await verifyAccessIdentity(request(parts.join('.')), { fetchImpl: fakeFetch }), null);
});
test('rejects wrong audience and wrong issuer', async () => {
  assert.equal(await verifyAccessIdentity(request(makeToken({ aud: ['other-app'] })), { fetchImpl: fakeFetch }), null);
  assert.equal(await verifyAccessIdentity(request(makeToken({ iss: 'https://evil.invalid' })), { fetchImpl: fakeFetch }), null);
});
test('rejects expired and not-yet-valid assertions', async () => {
  const time = Math.floor(Date.now() / 1000);
  assert.equal(await verifyAccessIdentity(request(makeToken({ exp: time - 1 })), { fetchImpl: fakeFetch }), null);
  assert.equal(await verifyAccessIdentity(request(makeToken({ nbf: time + 200 })), { fetchImpl: fakeFetch }), null);
});
test('rejects valid payload signed by an untrusted private key', async () => {
  const another = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.equal(await verifyAccessIdentity(request(makeToken({}, another.privateKey)), { fetchImpl: fakeFetch }), null);
});
test('stable IDs differ by subject, and are independent of email', async () => {
  const a = await accessUserId('stable-sub');
  assert.match(a, /^cf:[a-f0-9]{64}$/);
  assert.equal(a, await accessUserId('stable-sub'));
  assert.notEqual(a, await accessUserId('another-sub'));
});
