// Verify Cloudflare Access application JWTs. No request header is trusted as identity
// until the RS256 signature, issuer, audience and time claims all pass.
const ISSUER = 'https://amida.cloudflareaccess.com';
const AUDIENCE = 'f3ab938db36f57a94b3b4655c0837130675e1db6f780149903976a3e9be98bbc';
const JWKS_URL = ISSUER + '/cdn-cgi/access/certs';
let cachedKeys;
let cacheUntil = 0;

export const ACCESS_ISSUER = ISSUER;
export const ACCESS_AUDIENCE = AUDIENCE;

function b64urlBytes(input) {
  if (typeof input !== 'string' || !/^[A-Za-z0-9_-]+$/.test(input)) throw new Error('invalid base64url');
  const data = atob(input.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(data, (c) => c.charCodeAt(0));
}

function decodeJson(input) {
  return JSON.parse(new TextDecoder().decode(b64urlBytes(input)));
}

async function getKeys(fetchImpl, refresh = false) {
  const canCache = fetchImpl === fetch;
  if (canCache && !refresh && cachedKeys && Date.now() < cacheUntil) return cachedKeys;
  const response = await fetchImpl(JWKS_URL, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error('Cloudflare Access JWKS unavailable');
  const body = await response.json();
  if (!Array.isArray(body.keys)) throw new Error('Invalid Access JWKS');
  if (canCache) {
    cachedKeys = body.keys;
    cacheUntil = Date.now() + 15 * 60_000;
  }
  return body.keys;
}

async function verifyWithKeys(keyList, kid, signature, input) {
  const jwk = keyList.find(k => k.kid === kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256'));
  if (!jwk) return false;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature, new TextEncoder().encode(input));
}

export async function verifyAccessIdentity(headers, { fetchImpl = fetch, now = Date.now() } = {}) {
  try {
    const token = headers.get('cf-access-jwt-assertion');
    if (!token || token.length > 16000) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = decodeJson(encodedHeader);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) return null;
    const payload = decodeJson(encodedPayload);
    const nowSeconds = Math.floor(now / 1000);
    if (payload.iss !== ISSUER ||
        !(Array.isArray(payload.aud) ? payload.aud.includes(AUDIENCE) : payload.aud === AUDIENCE) ||
        typeof payload.exp !== 'number' || nowSeconds >= payload.exp ||
        (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || nowSeconds < payload.nbf)) ||
        typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 512) return null;
    const signedContent = encodedHeader + '.' + encodedPayload;
    const signature = b64urlBytes(encodedSignature);
    let keys = await getKeys(fetchImpl);
    let verified = await verifyWithKeys(keys, header.kid, signature, signedContent);
    if (!verified && fetchImpl === fetch && !keys.some(k => k.kid === header.kid)) {
      keys = await getKeys(fetchImpl, true); // Account for Cloudflare key rotation.
      verified = await verifyWithKeys(keys, header.kid, signature, signedContent);
    }
    if (!verified) return null;
    return {
      sub: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : undefined,
    };
  } catch {
    return null; // Fail closed on malformed JWT, DNS/JWKS errors, or invalid signatures.
  }
}

export async function accessUserId(sub) {
  const bytes = new TextEncoder().encode(ISSUER + ':' + sub);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return 'cf:' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
}
