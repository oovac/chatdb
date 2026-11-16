import { NextResponse, type NextRequest } from 'next/server';
import { verifyAccessIdentity } from './lib/access-identity.mjs';

const BEARER_OR_PROTOCOL_PATHS = [
  '/api/ingest', '/mcp', '/.well-known/', '/oauth/', '/api/auth',
];
const STATIC_PATHS = ['/_next/', '/favicon', '/manifest.json', '/sw.js', '/icons/'];

export default async function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  if (BEARER_OR_PROTOCOL_PATHS.some(p => path.startsWith(p)) ||
      STATIC_PATHS.some(p => path.startsWith(p)) ||
      path === '/login' ||
      path === '/api/signout') {
    // Bearer endpoints authenticate independently. Cloudflare Access remains
    // the external gate for every path; this is not a bypass of Cloudflare.
    return NextResponse.next();
  }

  const identity = await verifyAccessIdentity(req.headers);
  if (!identity) {
    if (path.startsWith('/api/')) return NextResponse.json({ error: 'Access authentication required' }, { status: 401 });
    const url = new URL('/login', req.url);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|favicon.svg|sw\\.js|manifest\\.json|icons/).*)'],
};
