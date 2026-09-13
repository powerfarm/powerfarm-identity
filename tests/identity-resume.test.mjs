import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  authorizationRoute,
  PENDING_AUTHORIZATION_COOKIE,
  pendingAuthorizationCookie,
  resumeAuthorizationId,
} from "../apps/identity/lib/auth-flow.mjs";

const root = new URL("../apps/identity/", import.meta.url);

async function source(path) {
  return readFile(new URL(path, root), "utf8");
}

test("pending authorization prefers the query, then the sign-in cookie", () => {
  assert.equal(resumeAuthorizationId("auth_query", "auth_cookie"), "auth_query");
  assert.equal(resumeAuthorizationId(undefined, " auth_cookie "), "auth_cookie");
  assert.equal(resumeAuthorizationId("", ""), undefined);
  assert.equal(resumeAuthorizationId(undefined, "x".repeat(513)), undefined);
  assert.equal(authorizationRoute(resumeAuthorizationId(null, "auth_123")), "/oauth/consent?authorization_id=auth_123");
});

test("pending authorization cookie is short-lived, httpOnly and first-party", () => {
  const cookie = pendingAuthorizationCookie("auth_123", { secure: true });
  assert.equal(cookie.name, PENDING_AUTHORIZATION_COOKIE);
  assert.equal(cookie.value, "auth_123");
  assert.deepEqual(cookie.options, { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 600 });
});

test("sign-in keeps the OAuth request across hops that drop the query", async () => {
  const middleware = await source("middleware.ts");
  const callback = await source("app/auth/callback/route.ts");
  const login = await source("app/login/page.tsx");
  const home = await source("app/page.tsx");

  assert.match(middleware, /pathname === "\/login"/);
  assert.match(middleware, /pendingAuthorizationCookie/);
  assert.match(middleware, /cookies\.delete\(PENDING_AUTHORIZATION_COOKIE\)/);
  assert.match(callback, /request\.cookies\.get\(PENDING_AUTHORIZATION_COOKIE\)/);
  assert.match(login, /cookies\(\)\)\.get\(PENDING_AUTHORIZATION_COOKIE\)/);
  assert.match(login, /result === "complete" && authorizationId/);
  assert.match(home, /\/auth\/callback\?/);
});
