import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // The token is stored in localStorage, so we can't access it in middleware
  // Instead, we'll let the client-side components handle authentication
  // This middleware will only handle API route protection

  const { pathname } = request.nextUrl;

  // Allow API auth routes to pass through
  if (pathname.startsWith('/api/auth')) {
    return NextResponse.next();
  }

  // For API task routes, we'll let the backend handle authentication
  if (pathname.startsWith('/api/tasks')) {
    return NextResponse.next();
  }

  // For all other routes (UI), let the client-side logic handle authentication
  return NextResponse.next();
}

// Specify the paths for which this middleware should run
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};