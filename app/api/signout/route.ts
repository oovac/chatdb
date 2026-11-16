import { NextResponse } from 'next/server';

// Access sessions, not legacy NextAuth cookies, are authoritative.
// Do not invalidate only a local cookie: that would silently log the user back in.
export async function POST(request: Request) {
  const logout = new URL('/cdn-cgi/access/logout', request.url);
  return NextResponse.redirect(logout, 303);
}
