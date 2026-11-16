export const ACCESS_ISSUER: string;
export const ACCESS_AUDIENCE: string;
export type AccessIdentity = { sub: string; email?: string };
export function verifyAccessIdentity(
  headers: Pick<Headers, 'get'>,
  options?: { fetchImpl?: typeof fetch; now?: number }
): Promise<AccessIdentity | null>;
export function accessUserId(sub: string): Promise<string>;
