export function buildCallbackUrl(baseUrl, authorizationId) {
  const callback = new URL("/auth/callback", baseUrl);
  if (authorizationId) callback.searchParams.set("authorization_id", authorizationId);
  return callback.toString();
}

export function authorizationRoute(authorizationId) {
  if (!authorizationId) return "/";
  const query = new URLSearchParams({ authorization_id: authorizationId });
  return `/oauth/consent?${query}`;
}

// The opaque OAuth request id must survive sign-in even when a hop drops the query
// (a magic link redirected to the Site URL, a new tab, a passkey detour).
export const PENDING_AUTHORIZATION_COOKIE = "pf_pending_authorization";

function present(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= 512 ? trimmed : undefined;
}

export function resumeAuthorizationId(fromQuery, fromCookie) {
  return present(fromQuery) ?? present(fromCookie);
}

/**
 * @param {string} authorizationId
 * @param {{ secure: boolean }} options
 * @returns {{ name: string, value: string, options: { httpOnly: boolean, secure: boolean, sameSite: "lax", path: string, maxAge: number } }}
 */
export function pendingAuthorizationCookie(authorizationId, { secure }) {
  return {
    name: PENDING_AUTHORIZATION_COOKIE,
    value: authorizationId,
    options: { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: 600 },
  };
}
