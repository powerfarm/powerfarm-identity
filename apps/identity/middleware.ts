import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import {
  PENDING_AUTHORIZATION_COOKIE,
  pendingAuthorizationCookie,
  resumeAuthorizationId,
} from "./lib/auth-flow.mjs";

export async function middleware(request: NextRequest) {
  let response = NextResponse.next({ request });
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (items) => {
          for (const { name, value } of items) request.cookies.set(name, value);
          response = NextResponse.next({ request });
          for (const { name, value, options } of items) {
            response.cookies.set(name, value, options);
          }
        },
      },
    },
  );

  await supabase.auth.getClaims();

  const { pathname, protocol, searchParams } = request.nextUrl;
  if (pathname === "/login") {
    const pending = resumeAuthorizationId(searchParams.get("authorization_id"));
    if (pending) {
      const cookie = pendingAuthorizationCookie(pending, { secure: protocol === "https:" });
      response.cookies.set(cookie.name, cookie.value, cookie.options);
    }
  } else if (pathname === "/oauth/consent") {
    // Consent carries the id itself; the pending copy only has to outlive sign-in.
    response.cookies.delete(PENDING_AUTHORIZATION_COOKIE);
  }
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
