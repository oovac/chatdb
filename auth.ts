// Cloudflare Access is the sole interactive identity provider for this deployment.
// The app verifies its signed application JWT itself and never trusts email headers.
import { headers } from 'next/headers';
import { eq } from 'drizzle-orm';
import { db } from './lib/db';
import { getCfEnv } from './lib/cf-env';
import { users } from './lib/schema';
import { verifyAccessIdentity, accessUserId } from './lib/access-identity.mjs';

export async function auth() {
  const identity = await verifyAccessIdentity(await headers());
  if (!identity) return null;

  // Never join accounts by email: Access sub is the stable security principal.
  const id = await accessUserId(identity.sub);
  try {
    const env = await getCfEnv();
    const database = db(env.DB);
    const [existing] = await database.select({ id: users.id }).from(users).where(eq(users.id, id)).limit(1);
    if (!existing) {
      await database.insert(users).values({
        id,
        githubId: id, // Legacy required column; distinct Access namespace, not a GitHub ID.
        username: identity.email ?? 'Cloudflare Access user',
        createdAt: Date.now(),
      }).onConflictDoNothing();
    }
  } catch (error) {
    console.error('[access-auth] Could not ensure authenticated user in database', error);
    return null; // Do not expose private data when DB is unavailable.
  }

  return { user: { id, name: identity.email ?? 'Cloudflare Access user', email: identity.email ?? null } };
}
