import { NextResponse, type NextRequest } from "next/server";
import {
  authorizationRoute,
  PENDING_AUTHORIZATION_COOKIE,
  resumeAuthorizationId,
} from "../../../lib/auth-flow.mjs";
import { getSupabaseServerClient } from "../../../lib/supabase-server";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const authorizationId = resumeAuthorizationId(
    request.nextUrl.searchParams.get("authorization_id"),
    request.cookies.get(PENDING_AUTHORIZATION_COOKIE)?.value,
  );
  const login = new URL("/login", request.url);

  if (!code) {
    login.searchParams.set("result", "expired");
    return NextResponse.redirect(login);
  }

  const supabase = await getSupabaseServerClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    login.searchParams.set("result", "expired");
    return NextResponse.redirect(login);
  }

  login.searchParams.set("setup", "passkey");
  const continuation = new URL(authorizationRoute(authorizationId), request.url);
  const opaqueAuthorizationId = continuation.searchParams.get("authorization_id");
  if (opaqueAuthorizationId) login.searchParams.set("authorization_id", opaqueAuthorizationId);
  return NextResponse.redirect(login);
}
