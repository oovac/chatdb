import { redirect } from 'next/navigation';
import { auth } from '@/auth';

export default async function LoginPage() {
  // Cloudflare Access handles the interactive sign-in before traffic reaches us.
  const session = await auth();
  if (session?.user?.id) redirect('/chats');

  return (
    <main className="min-h-screen bg-surface-elevated flex items-center justify-center p-6">
      <div className="bg-white rounded-2xl shadow-xl border border-black/10 p-8 max-w-md w-full">
        <h1 className="text-xl font-bold text-label-primary">ChatDB</h1>
        <p className="text-sm text-label-secondary mt-3">
          Sign in through Cloudflare Access to open your private conversation archive.
          No separate GitHub OAuth application is needed.
        </p>
        <a href="/cdn-cgi/access/login" className="mt-6 block rounded-xl bg-label-primary text-white text-center font-semibold p-3">
          Sign in with Cloudflare Access
        </a>
        <p className="text-xs text-label-tertiary mt-4">
          If you already passed Access, retry after checking the application configuration.
        </p>
      </div>
    </main>
  );
}
