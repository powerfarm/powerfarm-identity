# Powerfarm Schengen Identity and LAB Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Priority:** MAXIMUM. This plan precedes new App Park, Engine Park, inference, and heavy-compute features because those features must not create another authority path.

**Goal:** Make Powerfarm Identity a low-friction Schengen trust zone and make authenticated identity, standing, grants, and one-use tickets the only software path by which `lab` deploys apps and engines to LAB 8GB and LAB 512.

**Architecture:** The Superstructure/Registry owns one versioned application manifest, app admission, standing policy, grants, ticket issuance, and receipts. The existing Rust `lab` CLI becomes a public PKCE OAuth client and keeps its source/build/verification machinery, but packages an artifact and hands it with a short-lived ticket to a dedicated `powerfarm-parkd` executor. Manhattan installs and observes that executor and the park filesystem boundary; SSH remains transport only.

**Tech Stack:** Next.js 15, React 19, Node.js 22/24, Supabase Auth OAuth 2.1 and Postgres/RLS, JCS + SHA-256, Rust 2021 with the existing offline dependency set, macOS Keychain, launchd, Unix domain sockets, `curl`, `tar`, SSH/Cloudflare tunnels, LAB 8GB, LAB 512.

**Spec:** `docs/superpowers/specs/2026-08-29-powerfarm-schengen-lab-design.md`

## Global Constraints

- Identity must remove repeated prompts: admitted standing resolves ordinary circulation automatically.
- The operator computer is a workbench only: everything local is a draft, even when running; official state exists only after a recorded promotion to LAB 8GB or LAB 512.
- Promotion intentionally mirrors the Git `local branch -> merge to main` ritual: source state is explicit, destination is explicit, and successful remote admission is the boundary.
- There is no implicit LAB destination. Every mutating command, ticket, executor request, and receipt names one canonical LAB resource.
- SSH, Cloudflare tunnels, local files, environment variables, and static Supabase keys are transports or bootstrap material, never authority.
- The Superstructure owns one manifest schema and guide; UI and API consume the same validator and canonical bytes.
- The manifest never contains tokens, passwords, client secrets, private keys, SSH material, or Supabase service keys.
- `client_secret` is returned once for confidential clients and never persisted in Registry tables, logs, manifests, or receipts.
- `lab` is a public OAuth client using Authorization Code with PKCE; it contains no client secret.
- Tokens live in macOS Keychain service `app.powerfarm.lab`, never in `.env`, `lab.json`, logs, shell history, or receipts.
- `--force` may bypass convenience checks only; it never bypasses identity, standing, grants, tickets, hashes, or target enforcement.
- Canonical resources are the eight exact `powerfarm:lab-{8gb,512}/{app-park,engine-park,inference,compute}` values from the spec.
- Normal deploys are prompt-free after admission; step-up is reserved for real borders listed in the spec.
- Supabase OAuth does not provide `client_credentials`; unattended work uses scoped workload identity plus a short-lived Registry ticket.
- Manhattan owns executor installation and machine health; Registry owns authority; `powerfarm-parkd` owns park effects.
- No completion claim is allowed until direct SSH writes to both live parks fail and ticketed deployments succeed.
- Registry changes are committed in `/Users/ubl-ops/dev/powerfarm-v0.1/powerfarm-registry`; CLI/executor changes are committed separately in `/Users/ubl-ops/cli`.

---

## Planned File Structure

### Canonical Superstructure/Registry repository

```text
schemas/
└── powerfarm-app-manifest.v1.schema.json
policies/
└── schengen-app.v1.json
docs/
├── APP-MANIFEST-GUIDE.md
└── operations/POWERFARM-LAB-ROLLBACK.md
lib/
├── app-manifest.mjs
├── admission-policy.mjs
├── bearer-principal.ts
├── deployment-ticket.mjs
└── deployment-authority.ts
app/
├── schemas/powerfarm-app-manifest.v1.json/route.ts
├── api/apps/onboard/route.ts
├── api/apps/admissions/[id]/verify/route.ts
├── api/account/context/route.ts
├── api/deployments/tickets/route.ts
├── api/deployments/tickets/[id]/claim/route.ts
├── api/deployments/tickets/[id]/complete/route.ts
└── admin/apps/page.tsx
supabase/migrations/
└── *_powerfarm_schengen_admission.sql
tests/
├── app-manifest.test.mjs
├── admission-policy.test.mjs
├── onboarding-manifest.test.mjs
├── bearer-principal.test.mjs
├── deployment-ticket.test.mjs
└── schengen-schema.test.mjs
```

### `lab` CLI repository

```text
src/
├── main.rs
├── fleet.rs
├── powerfarm.rs
├── oauth.rs
├── app_manifest.rs
├── deployment.rs
└── bin/powerfarm-parkd.rs
lab-stack/
└── parkd/
    ├── app.powerfarm.parkd.plist
    ├── install-powerfarm-parkd.sh
    ├── uninstall-powerfarm-parkd.sh
    └── verify-powerfarm-parkd.sh
tests/fixtures/
├── app-manifest.valid.json
├── app-manifest.invalid-secret.json
├── deployment-ticket.claimed.json
└── deployment-ticket.refused.json
```

---

### Task 1: Publish one canonical application manifest and guide

**Files:**
- Create: `schemas/powerfarm-app-manifest.v1.schema.json`
- Create: `policies/schengen-app.v1.json`
- Create: `docs/APP-MANIFEST-GUIDE.md`
- Create: `lib/app-manifest.mjs`
- Create: `tests/app-manifest.test.mjs`
- Create: `tests/admission-policy.test.mjs`
- Modify: `package.json`

**Interfaces:**
- Produces: `normalizeAppManifest(input) -> NormalizedAppManifest`, `canonicalizeAppManifest(input) -> { manifest, canonical, sha256 }`, and `loadAdmissionProfile("schengen.app.v1")`.
- `NormalizedAppManifest` has exact keys `schema`, `manifestVersion`, `app`, `source`, `oauth`, `requestedCapabilities`, and `deployment`.
- Later tasks must consume these functions rather than reparse form fields.

- [ ] **Step 1: Write the failing manifest tests**

```js
import assert from "node:assert/strict";
import test from "node:test";
import { canonicalizeAppManifest, normalizeAppManifest } from "../lib/app-manifest.mjs";

const valid = {
  $schema: "https://registry.powerfarm.app/schemas/powerfarm-app-manifest.v1.json",
  manifest_version: "1.0",
  app: { id: "marketing-team", name: "Powerfarm Marketing Team", homepage: "https://marketing.powerfarm.app", owner: "powerfarm" },
  source: { repository: "powerfarm/marketing-team", commit: "0123456789abcdef0123456789abcdef01234567", path: "powerfarm.app.json" },
  identity: { oauth: { client_type: "confidential", redirect_uris: ["https://marketing.powerfarm.app/auth/callback"], scopes: ["openid", "email", "profile", "offline_access"] } },
  requests: { capabilities: [{ action: "app_park.deploy", resource: "powerfarm:lab-8gb/app-park" }] },
  deployment: { destination: "marketing-team", exclude: [".env", ".git"], build: ["npm run build"], install: ["npm ci --omit=dev"], verify: ["npm run healthcheck"] }
};

test("equivalent manifests produce one digest", () => {
  const a = canonicalizeAppManifest(valid);
  const b = canonicalizeAppManifest(JSON.parse(JSON.stringify(valid)));
  assert.equal(a.sha256, b.sha256);
  assert.match(a.sha256, /^[0-9a-f]{64}$/);
});

test("manifest rejects secrets and noncanonical resources", () => {
  assert.throws(() => normalizeAppManifest({ ...valid, client_secret: "forbidden" }), /secret/i);
  assert.throws(() => normalizeAppManifest({ ...valid, requests: { capabilities: [{ action: "app_park.deploy", resource: "lab-8gb" }] } }), /canonical resource/);
});

test("public native clients may use an exact loopback callback", () => {
  const input = structuredClone(valid);
  input.identity.oauth.client_type = "public";
  input.identity.oauth.redirect_uris = ["http://127.0.0.1:45454/callback"];
  assert.equal(normalizeAppManifest(input).oauth.clientType, "public");
});
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `node --test tests/app-manifest.test.mjs tests/admission-policy.test.mjs`

Expected: FAIL because `lib/app-manifest.mjs` and the policy loader do not exist.

- [ ] **Step 3: Add the exact JSON Schema**

The schema must set `additionalProperties: false` at the root and every nested
object, require every field shown in the spec example, constrain `app.id` to
`^[a-z0-9]+(?:-[a-z0-9]+)*$`, constrain Git commits to 40 lowercase hexadecimal
characters, allow only `public|confidential`, allow only the five current OAuth
scopes, and enumerate the eight canonical resources. Include a negative-key
guard in `normalizeAppManifest()` for `/secret|password|token|private.?key|ssh/i`
at any depth because JSON Schema property constraints alone cannot detect a
secret hidden under a user-defined extension.

- [ ] **Step 4: Add the baseline standing policy**

```json
{
  "id": "schengen.app.v1",
  "version": 1,
  "kind": "app",
  "baseline": [
    { "action": "identity.read", "resource": "self" },
    { "action": "manifest.read", "resource": "self" },
    { "action": "artifact.exchange", "resource": "self" },
    { "action": "logs.write", "resource": "self" },
    { "action": "process.read_write", "resource": "self" },
    { "action": "inference.invoke", "resource": "treated" },
    { "action": "deployment.inspect", "resource": "self" }
  ],
  "borders": ["app_park.deploy", "engine_park.deploy", "secrets.read", "external.egress", "compute.exceptional", "autonomy.enable", "standing.admin"]
}
```

- [ ] **Step 5: Implement JCS-compatible canonicalization with existing dependencies**

Use deterministic recursive key ordering in Node, serialize without whitespace,
hash the resulting UTF-8 bytes with `createHash("sha256")`, and expose the exact
function names in the Interfaces block. Add a fixture assertion comparing the
Node digest to `lab hash` so Node and Rust cannot silently diverge.

- [ ] **Step 6: Write the human guide**

The guide must contain the complete minimal and full manifests, public versus
confidential clients, native loopback callback, resource vocabulary, standing
versus border grants, secret prohibition, idempotency, source custody, UI/API
equivalence, and the exact validation command `lab app validate powerfarm.app.json`.

- [ ] **Step 7: Run and commit**

Run: `npm test`

Expected: all existing tests plus manifest and policy tests PASS.

```bash
git add schemas policies docs/APP-MANIFEST-GUIDE.md lib/app-manifest.mjs tests package.json
git commit -m "feat: define canonical Powerfarm app manifest"
```

---

### Task 2: Add durable admissions, standing provenance, tickets, and receipts

**Files:**
- Create via `supabase migration new powerfarm_schengen_admission`: `supabase/migrations/*_powerfarm_schengen_admission.sql`
- Create: `tests/schengen-schema.test.mjs`

**Interfaces:**
- Produces tables `app_admissions`, `deployment_tickets`, and `deployment_receipts`.
- Extends `grants` with `source_kind`, `source_ref`, and `admission_id`.
- Produces SQL functions `effective_powerfarm_grant(identity, action, resource)` and `claim_deployment_ticket(token_hash, target_resource)`.

- [ ] **Step 1: Create the migration through the Supabase CLI**

Run: `supabase migration new powerfarm_schengen_admission`

Expected: one timestamped empty migration file ending in
`_powerfarm_schengen_admission.sql`. Record that emitted path in the task
checkbox when executing; do not hand-invent a second migration filename.

- [ ] **Step 2: Write the failing structural test**

```js
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

test("Schengen migration has one-use tickets and grant provenance", async () => {
  const files = (await readdir(new URL("../supabase/migrations/", import.meta.url))).filter((x) => x.endsWith("_powerfarm_schengen_admission.sql"));
  assert.equal(files.length, 1);
  const sql = await readFile(new URL(`../supabase/migrations/${files[0]}`, import.meta.url), "utf8");
  assert.match(sql, /create table public\.app_admissions/);
  assert.match(sql, /create table public\.deployment_tickets/);
  assert.match(sql, /unique.*token_hash/is);
  assert.match(sql, /claim_deployment_ticket/);
  assert.doesNotMatch(sql, /client_secret|ticket_token\s+text/i);
});
```

- [ ] **Step 3: Define the admission tables**

`app_admissions` stores `id`, `app_identity_id`, `oauth_client_id`, exact
`manifest jsonb`, `manifest_sha256`, `profile_id`, `profile_sha256`, status
`pending_callback|active|suspended|revoked`, creator/admitter identities, and
timestamps. Add unique `(app_identity_id, manifest_sha256)` for idempotency.

`deployment_tickets` stores the bindings from section 9 of the spec plus only
`token_hash`, state, claim metadata, and expiry. `deployment_receipts` is
append-only and stores ticket, status, machine identity, release/artifact hashes,
start/end timestamps, and structured detail. Add a unique receipt idempotency
key `(ticket_id, status, idempotency_key)`.

- [ ] **Step 4: Implement RLS and atomic functions**

Authenticated identities may read their own admissions, tickets, and receipts.
Only `registry.admin|oauth.clients.manage` may admit apps. Ticket issuance must
be server-side. `claim_deployment_ticket()` must lock the ticket row, check
`state='issued'`, expiry, target, admission activity, and grant validity, then
change state to `claimed` in the same transaction. Replays return no row.

- [ ] **Step 5: Validate against a disposable Supabase branch**

Run `supabase db start` only if local Docker is healthy; otherwise create a
Supabase development branch after obtaining cost confirmation. Apply the
migration there, run the SQL assertions in `tests/schengen-schema.test.mjs`, and
run security/performance advisors. Do not apply to production in this task.

- [ ] **Step 6: Run and commit**

Run: `npm test`

Expected: PASS, including migration parity and structural tests.

```bash
git add supabase/migrations tests/schengen-schema.test.mjs
git commit -m "feat: add Schengen admissions and deployment tickets"
```

---

### Task 3: Make UI and API perform the same manifest onboarding

**Files:**
- Create: `app/api/apps/onboard/route.ts`
- Create: `app/api/apps/admissions/[id]/verify/route.ts`
- Create: `app/schemas/powerfarm-app-manifest.v1.json/route.ts`
- Modify: `app/admin/apps/page.tsx`
- Modify: `app/api/oauth/clients/route.ts`
- Create: `tests/onboarding-manifest.test.mjs`

**Interfaces:**
- Consumes: `canonicalizeAppManifest()` and `loadAdmissionProfile()` from Task 1.
- Produces: `POST /api/apps/onboard`, `POST /api/apps/admissions/:id/verify`, and immutable schema GET.
- Keeps `/api/oauth/clients` as the internal provider adapter and reconciliation list, not a second public onboarding contract.

- [ ] **Step 1: Write failing route-boundary tests**

Assert that `/api/apps/onboard` imports `canonicalizeAppManifest`, requires a
Registry grant, calls a provider adapter, inserts `app_admissions`, and never
persists `client_secret`. Assert that the admin page submits one JSON manifest
to this route instead of `Object.fromEntries(form)` to `/api/oauth/clients`.

- [ ] **Step 2: Run the focused test and observe failure**

Run: `node --test tests/onboarding-manifest.test.mjs`

Expected: FAIL because the route does not exist and the page still posts flat fields.

- [ ] **Step 3: Extract the provider adapter**

Move the existing `auth.admin.oauth.createClient()` call behind
`createProviderOAuthClient(normalized.oauth)`. Permit exact HTTP loopback only
for public native clients; retain exact HTTPS and no-wildcard rules everywhere
else. Keep `listClients()` reconciliation behavior for unlinked clients.

- [ ] **Step 4: Implement idempotent onboarding**

Within one logical request: resolve admin, normalize/hash manifest, return the
existing admission for the same app/digest, create/reuse app identity, create
the provider client only when absent, insert provider link and admission, mint
baseline grants with `source_kind='standing'`, and return secret once. If the
provider succeeds and the local insert fails, return `unlinked` with the
provider client ID for reconciliation; never retry creation silently.

- [ ] **Step 5: Implement callback verification**

The verify route accepts an authenticated proof tied to the admission's exact
OAuth client and callback, sets `app_admissions.status='active'`, updates
`app_oauth_clients.status='active'`, records `callback_verified_at`, and emits an
admission receipt. A mismatched client, callback, or manifest digest leaves the
admission pending and records refusal.

- [ ] **Step 6: Convert the admin UI into a manifest editor**

Keep the current friendly fields but maintain one `manifest` object in state,
show its canonical JSON/digest before submission, add source and requested
capability fields, and POST that exact object. The page must display admission,
standing, border grants, callback state, and the one-time secret.

- [ ] **Step 7: Run and commit**

Run: `npm test && npm run build`

Expected: PASS; no second form-to-provider parser remains.

```bash
git add app lib tests
git commit -m "feat: onboard apps from canonical manifests"
```

---

### Task 4: Expose bearer identity context and automatic grant resolution

**Files:**
- Create: `lib/bearer-principal.ts`
- Create: `app/api/account/context/route.ts`
- Create: `tests/bearer-principal.test.mjs`
- Modify: `lib/registry-authority.ts`

**Interfaces:**
- Produces `principalFromRequest(request) -> { userId, identityId, identityName, clientId } | null`.
- Produces `GET /api/account/context` returning identity, OAuth client, standing, admissions, and effective grants without secrets.
- Both browser cookies and `Authorization: Bearer <access-token>` use the same principal resolver.

- [ ] **Step 1: Write failing tests for cookie and bearer equivalence**

Use injected Supabase clients to prove a cookie-authenticated request and a
bearer-authenticated CLI request resolve the same identity link and grants.
Assert that missing, expired, and malformed bearers return 401, not anonymous
success.

- [ ] **Step 2: Implement the minimal resolver**

For bearer requests call `auth.getUser(token)` with the public Supabase client;
for browser requests reuse `supabaseServer()`. Resolve authorization only from
`identity_links` and `grants`; never from `user_metadata`. Include OAuth
`client_id` from verified token claims only as context, never as an admin grant.

- [ ] **Step 3: Add the context projection**

Return stable JSON with `identity`, `session.client_id`, `standing`, `grants`,
and `admissions`. Collapse baseline standing into an effective grant list so the
CLI can show one useful answer without understanding Registry storage tables.

- [ ] **Step 4: Run and commit**

Run: `npm test && npm run build`

```bash
git add lib app/api/account tests/bearer-principal.test.mjs
git commit -m "feat: expose Powerfarm bearer identity context"
```

---

### Task 5: Issue, claim, complete, refuse, and revoke deployment tickets

**Files:**
- Create: `lib/deployment-ticket.mjs`
- Create: `lib/deployment-authority.ts`
- Create: `app/api/deployments/tickets/route.ts`
- Create: `app/api/deployments/tickets/[id]/claim/route.ts`
- Create: `app/api/deployments/tickets/[id]/complete/route.ts`
- Create: `tests/deployment-ticket.test.mjs`

**Interfaces:**
- Produces `mintOpaqueToken() -> { clearToken, tokenHash }` using 32 random bytes.
- Produces `authorizeDeployment({ principal, appId, action, resource, manifestSha256, artifactSha256, idempotencyKey })`.
- Ticket clear token is returned once; only SHA-256 is stored.

- [ ] **Step 1: Write failing ticket tests**

Test automatic issuance under an effective grant, refusal without a grant,
wrong target, expiry, revocation, claim replay, and completion idempotency. Test
that JSON/log projections never contain the clear token after the initial POST.

- [ ] **Step 2: Implement automatic authorization**

Resolve active admission and exact manifest digest, then baseline standing and
explicit grants. A matching durable right issues immediately without another
prompt. A border without a grant returns 403 with `border`, `action`, and
`resource`; it does not create an approval request implicitly.

- [ ] **Step 3: Implement one-use token lifecycle**

Issue with five-minute expiry. Claim accepts `Authorization: Ticket <clear>` and
an exact target resource, hashes the token, and delegates the row lock/change to
`claim_deployment_ticket()`. Completion accepts the same ticket plus a receipt,
allows only `claimed -> succeeded|failed|refused`, and is idempotent by receipt
key. Revocation changes `issued -> revoked`; claimed work must close honestly.

- [ ] **Step 4: Run and commit**

Run: `npm test && npm run build`

```bash
git add lib app/api/deployments tests/deployment-ticket.test.mjs
git commit -m "feat: issue one-use Powerfarm deployment tickets"
```

---

### Task 6: Register `lab` as a public OAuth client and implement PKCE login

**Files:**
- Create in Registry through Task 3 API: canonical manifest `powerfarm-lab-cli`
- Create in CLI: `src/oauth.rs`
- Create in CLI: `src/powerfarm.rs`
- Modify in CLI: `src/main.rs`
- Add tests in: `src/oauth.rs`

**Interfaces:**
- Produces `oauth::login()`, `oauth::logout()`, `oauth::status()`, and `oauth::access_token()`.
- Produces `powerfarm::api(method, path, body) -> ApiResponse` with automatic refresh.
- Keychain service is exactly `app.powerfarm.lab`; account is exactly `oauth`.

- [ ] **Step 1: Write Rust unit tests for PKCE and secret custody**

Add tests for verifier length, URL-safe challenge, random state, callback state
mismatch, token response redaction, and Keychain command arguments. Assert no
path under `$HOME` is selected for token persistence.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test oauth --offline`

Expected: FAIL because `oauth` module does not exist.

- [ ] **Step 3: Onboard the CLI manifest**

Register a `public` client with exact callback
`http://127.0.0.1:45454/callback`, scopes `openid email profile offline_access`,
and no client secret. Record its `client_id` as public configuration in the CLI;
do not embed any administrative or confidential credential.

- [ ] **Step 4: Implement PKCE with the existing offline toolchain**

Generate verifier/state from `/dev/urandom`, compute S256 with existing `sha2`,
base64url encode locally, bind `TcpListener` only to `127.0.0.1:45454`, open the
authorize URL with macOS `open`, parse one callback request, verify state, and
exchange the code using the existing `curl` subprocess boundary. Set a two-minute
listener timeout and close after one request.

- [ ] **Step 5: Store and refresh through Keychain**

Serialize access token, refresh token, expiry, issuer, and client ID as one JSON
value passed on stdin to `security add-generic-password -U`; retrieve with
`security find-generic-password -w`; delete with
`security delete-generic-password`. Never place token values in process
arguments, diagnostics, or receipts. Refresh sixty seconds before expiry.

- [ ] **Step 6: Add commands and useful output**

Add `lab auth login|logout|status`, `lab identity`, and `lab grants`. Successful
identity output shows person, CLI client, standing, and session expiry. The
default output hides internal token/ticket mechanics; `--json` exposes only
non-secret context.

- [ ] **Step 7: Run and commit**

Run: `cargo fmt --check && cargo test --offline && cargo build --release --offline`

```bash
git add src Cargo.toml Cargo.lock
git commit -m "feat: authenticate lab with Powerfarm PKCE"
```

---

### Task 7: Teach `lab` the canonical manifest and Schengen vocabulary

**Files:**
- Create in CLI: `src/app_manifest.rs`
- Create in CLI: `tests/fixtures/app-manifest.valid.json`
- Create in CLI: `tests/fixtures/app-manifest.invalid-secret.json`
- Modify in CLI: `src/main.rs`
- Modify in CLI: `src/fleet.rs`

**Interfaces:**
- Produces `AppManifest::read(path)`, `AppManifest::validate()`, `AppManifest::canonical_sha256()`, and `canonical_resource(alias)`.
- `lab app validate` and Registry Task 1 must produce the same SHA-256.
- The old `Manifest` in `fleet.rs` becomes a compatibility projection from `AppManifest`.

- [ ] **Step 1: Add cross-runtime digest fixtures**

Commit the valid fixture and its expected digest generated by Registry Task 1.
Add Rust tests asserting the same digest, secret rejection, exact callbacks,
canonical resources, and aliases `8gb -> powerfarm:lab-8gb/app-park` only when
the action is `app_park.deploy`.

- [ ] **Step 2: Implement the typed manifest parser**

Use `serde_json::Value` plus explicit getters and error paths; do not add an
uncached schema crate. Recursively reject secret-like keys, normalize URLs and
resources, and reuse existing `serde_jcs` + SHA-256 for the digest.

- [ ] **Step 3: Replace `lab push --init` output**

`lab app init` writes `powerfarm.app.json` matching the schema and guide. During
transition, `lab push --init` calls the same generator and prints the new name.
If only `lab.json` exists, parse it into a candidate manifest in memory and print
the exact conversion diff; never silently admit it.

- [ ] **Step 4: Add validate/onboard commands**

`lab app validate [path]` performs local validation and digest. `lab app onboard
[path]` requires `lab auth`, POSTs the exact manifest bytes to Task 3, and prints
identity, admission, standing, grants, and one-time client secret when present.

- [ ] **Step 5: Run and commit**

Run: `cargo fmt --check && cargo test --offline`

```bash
git add src tests/fixtures
git commit -m "feat: teach lab the Powerfarm app manifest"
```

---

### Task 8: Refactor `lab push` into ticketed `lab deploy`

**Files:**
- Create in CLI: `src/deployment.rs`
- Modify in CLI: `src/fleet.rs`
- Modify in CLI: `src/main.rs`
- Add tests in: `src/deployment.rs`

**Interfaces:**
- Produces `DeploymentPlan::from_manifest()`, `build_artifact() -> { path, sha256 }`, `request_ticket()`, and `ship_to_executor()`.
- `lab deploy` is the canonical command; `lab push` is a compatibility alias.

- [ ] **Step 1: Write failing plan tests**

Test target normalization, manifest target mismatch, dirty source, excluded
secrets, deterministic archive digest, `--dry-run`, missing grant, expired ticket,
the invariant that `--force` cannot set `authorized=true`, refusal when no
destination is provided, and the invariant that local success remains
`workbench (draft)` rather than `official`.

- [ ] **Step 2: Preserve the current preflight behavior**

Move workbench-only origin, source state, declared target, architecture, build,
exclude, verification description, and dry-run calculations into
`DeploymentPlan`. Keep existing user-facing refusals where they remain true.

- [ ] **Step 3: Replace direct live-directory rsync**

Create a deterministic tar archive after build, excluding credentials and the
manifest exclusions, compute SHA-256, request a ticket bound to that digest,
`scp` only to the machine inbox, and invoke remote
`lab deployment apply --ticket-stdin --artifact <inbox-path>`. Pass the ticket
through stdin, never command arguments.

- [ ] **Step 4: Make normal success terse and borders explanatory**

Default output:

```text
✓ Source: workbench (draft)
✓ Powerfarm identity: marketing-team
✓ Destination: LAB 8GB / App Park
✓ Standing permits deployment
✓ Artifact admitted
✓ Deployed and recorded
```

Only the final executor completion and health receipt changes the displayed
state from draft to official. Build, preview, archive upload, and ticket issuance
alone never do so. JSON output includes `source_state: "draft"`, the exact
`target_resource`, and `promotion_state`.

On refusal print one reason and `--explain` instructions. Do not expose raw
JWTs, tickets, SQL, or internal policy rows.

- [ ] **Step 5: Keep compatibility without an authority bypass**

`lab push` calls the same deploy function and prints one deprecation notice.
Delete the old direct `mkdir + rsync --delete + install` path after the executor
lands. `--force` remains available only for dirty-source and convenience checks.

- [ ] **Step 6: Run and commit**

Run: `cargo fmt --check && cargo test --offline && cargo build --release --offline`

```bash
git add src
git commit -m "feat: make lab deploy through Powerfarm tickets"
```

---

### Task 9: Build the park executor and close direct-write authority

**Files:**
- Create in CLI: `src/bin/powerfarm-parkd.rs`
- Create in CLI: `lab-stack/parkd/app.powerfarm.parkd.plist`
- Create in CLI: `lab-stack/parkd/install-powerfarm-parkd.sh`
- Create in CLI: `lab-stack/parkd/uninstall-powerfarm-parkd.sh`
- Create in CLI: `lab-stack/parkd/verify-powerfarm-parkd.sh`
- Create in CLI: `lab-stack/parkd/manhattan-policy-item.json`
- Create in CLI: `lab-stack/parkd/manhattan-parkd-probe.py`
- Modify in CLI: `Cargo.toml`
- Modify in CLI: `src/main.rs`
- Modify at installation: `/usr/local/project-manhattan/etc/PROJECT_MANHATTAN_POLICY_REVIEW.json`
- Modify at installation: `/usr/local/project-manhattan/src/manhattan.py`
- Create in Registry: `docs/operations/POWERFARM-LAB-ROLLBACK.md`

**Interfaces:**
- Produces Unix socket `/var/run/powerfarm-parkd.sock` and JSON-line request `{ ticket, artifact_path, target_resource }`.
- Produces executor states `claimed|staged|activated|succeeded|failed|refused` and posts the Task 5 receipt.
- Live park directories are writable only by the dedicated executor account.

- [ ] **Step 1: Write executor unit tests around a temporary park**

Test wrong resource, invalid/expired/replayed ticket response, artifact hash
mismatch, tar traversal (`../`), absolute paths, symlink escape, staging,
atomic activation, verification failure rollback, and receipt construction.
Use a temporary directory; tests must not need root or touch real parks.

- [ ] **Step 2: Implement a small Unix-socket executor**

Use `UnixListener`, one JSON request per connection, bounded artifact size,
five-minute command timeouts, exact allowlisted target roots, and no shell string
concatenation for archive paths. Claim the ticket before staging. Refuse rather
than infer missing fields. Post one terminal receipt even on verification failure.

- [ ] **Step 3: Define filesystem custody**

Installer creates dedicated account `_powerfarm`, `/var/db/powerfarm/inbox`,
`/var/db/powerfarm/releases`, and live App/Engine Park roots owned by that
account. Operator SSH account can place a file only in the inbox and connect to
the socket; it cannot modify release or live roots. Preserve the previous live
release for rollback.

- [ ] **Step 4: Make Manhattan the installer/health owner**

Add one versioned policy item from
`lab-stack/parkd/manhattan-policy-item.json` to the installed
`/usr/local/project-manhattan/etc/PROJECT_MANHATTAN_POLICY_REVIEW.json` and add
one probe/repair dispatch in `/usr/local/project-manhattan/src/manhattan.py`.
The installer must first hash and back up both installed files, apply a
deterministic merge, run Manhattan's package validator/audit, and restore the
backup on validation failure. Keep the reusable probe implementation in
`lab-stack/parkd/manhattan-parkd-probe.py`; do not create a second daemon or
fleet reconciler. The health proof is socket present, daemon PID unique,
directory ownership exact, Registry reachable, and a dry claim refused without
a ticket. Commit the versioned policy item/probe in `~/cli`; never treat the
unversioned installed edit alone as source custody.

- [ ] **Step 5: Write rollback instructions before live installation**

Document how to stop parkd, restore directory ownership and previous release,
re-enable the old `lab push` binary if necessary, and preserve receipts/artifacts.
Rollback must not delete admissions, grants, tickets, or receipts.

- [ ] **Step 6: Run local verification and commit**

Run: `cargo fmt --check && cargo test --offline && cargo build --release --offline`

Run installer/verify against a temporary prefix, not `/var`, and prove uninstall
restores that prefix.

```bash
git add Cargo.toml Cargo.lock src/bin lab-stack/parkd
git commit -m "feat: enforce ticketed Powerfarm park deployments"
```

Commit rollback docs separately in Registry:

```bash
git add docs/operations/POWERFARM-LAB-ROLLBACK.md
git commit -m "docs: add Powerfarm LAB executor rollback"
```

---

### Task 10: Replace generic Supabase write credentials with scoped identities

**Files:**
- Modify in CLI: `src/main.rs`
- Modify in CLI: `receiver/listen.mjs`
- Modify in CLI: `receiver/CONTRACT.md`
- Modify in CLI: `lab-stack/templates/sync.env.example`
- Create in Registry: `app/api/events/route.ts`
- Create in Registry: `tests/scoped-events.test.mjs`

**Interfaces:**
- Interactive writes consume `oauth::access_token()` and Registry bearer APIs.
- Unattended receiver writes consume a workload token scoped to its machine
  identity and actions `events.read:self`, `events.write:self`.
- No runtime uses a generic Supabase secret/service key.

- [ ] **Step 1: Inventory every write path as an executable test fixture**

List builtins and plugins that call `load_creds`, `write_hashed`, direct
PostgREST, or Supabase JS. Classify each as interactive person, machine
telemetry, deployment, or read-only. Fail CI if a new runtime reference to
`SUPABASE_SECRET_KEY|service_role|RADAR_SUPABASE_KEY|LAB_SUPABASE_KEY` appears.

- [ ] **Step 2: Add the scoped event API**

The API accepts canonical event JSON, resolves person or workload identity,
checks the exact event grant/resource, computes the hash server-side, inserts,
and returns a receipt. It rejects a caller attempting to stamp another identity.

- [ ] **Step 3: Move interactive CLI writes**

Change `emit`, `write`, `heartbeat`, judgment receipts, deployment receipts, and
plugins to call the Powerfarm API with the OAuth access token. Keep old ledger
reads temporarily read-only. Remove secret propagation from `run_external()`.

- [ ] **Step 4: Move receiver to a workload identity**

Onboard one workload identity per machine, give only its own event grants, store
refresh/private material in Keychain or executor custody, and replace direct
Supabase JS writes with the scoped event API. Preserve current idempotency and
refusal receipts.

- [ ] **Step 5: Remove bootstrap credentials after proof**

After live events from LAB 8GB and LAB 512 carry the new identity and receipt,
remove runtime dependence on `~/.radar/sync.env`, rotate the old key, and verify
the old key fails. Preserve unrelated Maileroo notification configuration.

- [ ] **Step 6: Run and commit both repositories**

Registry: `npm test && npm run build`

CLI: `cargo fmt --check && cargo test --offline && npm test --prefix receiver`

Commit the Registry API and CLI migration separately with messages
`feat: admit scoped Powerfarm events` and
`feat: remove generic runtime Supabase credentials`.

---

### Task 11: Prove Schengen UX, revocation, and the only-path invariant live

**Files:**
- Create in Registry: `docs/operations/POWERFARM-SCHENGEN-LIVE-PROOF.md`
- Modify: the task checkboxes in this plan with deployment and receipt IDs

**Interfaces:**
- Consumes all prior tasks.
- Produces a dated evidence record for Registry, LAB 8GB, and LAB 512.

- [ ] **Step 1: Run all local release gates**

Registry:

```bash
npm test
npm run build
```

CLI:

```bash
cargo fmt --check
cargo test --offline
cargo build --release --offline
```

Expected: all pass from clean worktrees.

- [ ] **Step 2: Deploy Registry safely**

Apply the reviewed migration to production, deploy Registry/Identity through the
existing Vercel projects, verify schema endpoint, onboarding API, OAuth flow,
ticket API, and account context. Record deployment URLs and commits.

- [ ] **Step 3: Install executor through Manhattan**

Install first on LAB 8GB, verify health/rollback, then LAB 512. Do not proceed to
the second machine after an ambiguous first result. Record binary SHA-256,
plist hash, uid/gid, directory modes, and daemon PID.

- [ ] **Step 4: Prove the low-friction happy path**

Login once, onboard one disposable fixture app, activate standing, grant one
park deployment, and deploy twice without another approval prompt. Verify the
second deployment reuses identity/standing but receives a new one-use ticket.

- [ ] **Step 5: Prove every negative control**

Run and record: no identity, no admission, missing grant, wrong target, changed
manifest digest, changed artifact digest, expired ticket, replayed ticket,
revoked grant, revoked admission, and `--force`. Every case must refuse before
park mutation and produce a receipt.

- [ ] **Step 6: Prove the only-path filesystem boundary**

On each LAB, attempt a harmless direct file creation in live App Park and Engine
Park as the ordinary SSH operator; expect permission denied. Then perform the
same release through `lab deploy`; expect success and a complete trace. Remove
the harmless inbox test file afterward and record that removal.

- [ ] **Step 7: Prove rollback**

Deploy a fixture whose verification fails, confirm the previous release remains
live, ticket closes `failed`, and receipt points to both attempted and restored
release digests.

- [ ] **Step 8: Prove revocation speed**

Revoke the app's deploy grant, immediately request another deployment, and
verify refusal in the first Registry request. Restore only by issuing a new
grant; never un-revoke the historical row.

- [ ] **Step 9: Publish the evidence and close**

The proof document contains commits, deployment URLs, machine evidence,
admission/grant/ticket/receipt IDs, commands, expected/actual status, rollback
result, and remaining non-blocking observations. Secrets and clear tickets are
redacted. Only then mark this plan complete.

```bash
git add docs/operations/POWERFARM-SCHENGEN-LIVE-PROOF.md docs/superpowers/plans/2026-08-29-powerfarm-schengen-lab.md
git commit -m "docs: prove Powerfarm Schengen LAB authority"
```

---

## Execution Order and Release Gates

```text
Tasks 1-5  Registry control plane, no production mutation
Task 6     CLI interactive identity
Task 7     shared manifest language
Task 8     ticketed deploy client
Task 9     target enforcement and filesystem custody
Task 10    static credential retirement
Task 11    production rollout and proof
```

Tasks 1-5 may deploy to a Supabase development branch and Vercel preview. No
production migration occurs before their tests and advisors pass. Task 8 must
not delete the legacy push path until Task 9 passes locally. Production rollout
is LAB 8GB first, then LAB 512. Any ambiguous effect stops rollout and uses the
documented rollback; it is never retried blindly.

## Definition of Done

This priority is not complete because schemas, tests, builds, or previews pass.
It is complete only after Task 11 proves both sides of the promise:

1. an admitted entity moves through ordinary Powerfarm operations with one login
   and no repeated approval bureaucracy; and
2. an unadmitted or unauthorized entity cannot mutate either private cloud even
   when it has network and SSH transport.
