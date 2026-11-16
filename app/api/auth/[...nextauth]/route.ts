// GitHub/NextAuth OAuth is intentionally disabled in Cloudflare Access mode.
// Do not expose a second, unconfigured identity provider.
export async function GET() {
  return Response.json({ error: 'Use Cloudflare Access for sign-in.' }, { status: 410 });
}
export const POST = GET;
