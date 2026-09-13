import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { IdentityLoginHost } from "../../components/IdentityLoginHost";
import {
  authorizationRoute,
  PENDING_AUTHORIZATION_COOKIE,
  resumeAuthorizationId,
} from "../../lib/auth-flow.mjs";

type LoginPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function one(value: string | string[] | undefined) {
  return typeof value === "string" ? value : undefined;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const query = await searchParams;
  const authorizationId = resumeAuthorizationId(
    one(query.authorization_id),
    (await cookies()).get(PENDING_AUTHORIZATION_COOKIE)?.value,
  );
  const setupPasskey = one(query.setup) === "passkey";
  const result = one(query.result);

  // A finished sign-in that still owes an OAuth request continues to consent, not a dead end.
  if (result === "complete" && authorizationId) redirect(authorizationRoute(authorizationId));

  return (
    <IdentityLoginHost
      authorizationId={authorizationId}
      setupPasskey={setupPasskey}
      result={result === "expired" || result === "complete" ? result : undefined}
    />
  );
}
