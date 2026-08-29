# Powerfarm Schengen Identity and LAB Design

**Status:** approved direction, priority maximum

**Date:** 2026-08-29

**Authority:** Dan Voulez

## 1. Outcome

Powerfarm Identity must be an operational advantage. A person, app, office,
machine, or workload admitted to Powerfarm enters a Schengen-like trust zone:
it authenticates once, receives a durable standing, and circulates freely
inside the ordinary capabilities of that standing. Infrastructure performs
token refresh, grant resolution, ticket minting, audit, and revocation in the
background. Human interruption occurs only at a real border.

The local `lab` CLI becomes the Powerfarm operational client for the private
clouds LAB 8GB and LAB 512. It keeps its name and its useful fleet, source,
build, install, verification, and receipt machinery. It stops treating SSH
reachability, a local file, or a static Supabase key as authority.

## 2. Core rule

> Identity is the passport. Standing is the freedom of circulation. A grant is
> a durable visa for a boundary that is not included in standing. A short-lived
> ticket is only the invisible technical proof used at the moment of execution.

Authentication alone does not grant an arbitrary action. Conversely, an
admitted entity must not be asked to approve or reconfigure every ordinary
action already covered by its standing.

## 3. Authority chain

Every privileged LAB effect follows one chain:

```text
canonical app manifest
  -> admitted Powerfarm app identity
  -> active standing plus explicit grants
  -> short-lived, one-use execution ticket
  -> LAB executor validates and applies
  -> immutable completion/refusal/failure receipt
```

SSH, Cloudflare tunnels, `rsync`, `scp`, HTTP, and local sockets are transports.
They cannot mint identity, standing, grants, tickets, or admission.

## 4. Schengen zone

### 4.1 Ordinary circulation

The first admitted application profile is `schengen.app.v1`. After callback
verification it receives the baseline rights below, scoped to its own identity
and artifacts:

- `identity.read:self`
- `manifest.read:self`
- `artifact.exchange:self`
- `logs.write:self`
- `process.read_write:self`
- `inference.invoke:treated`
- `deployment.inspect:self`

These rights are resolved automatically. The user does not approve them on
every call.

### 4.2 Real borders

The following actions require an explicit grant and may require a step-up or
human approval according to policy:

- first admission to a new park or machine;
- `app_park.deploy` and `engine_park.deploy` for a new resource;
- destructive operations and rollback across custody boundaries;
- secret access;
- external egress not declared by the manifest;
- exceptional compute or inference budgets;
- autonomous operation without an active human session;
- changes to standing, grants, identity keys, or policy.

### 4.3 Revocation

Revoking an identity, admission, standing, grant, or key prevents new tickets
immediately. Existing unclaimed tickets become invalid. A claimed operation
must finish or fail with a receipt; it never disappears silently.

## 5. Canonical resources

The initial resource vocabulary is exact:

```text
powerfarm:lab-8gb/app-park
powerfarm:lab-8gb/engine-park
powerfarm:lab-8gb/inference
powerfarm:lab-8gb/compute
powerfarm:lab-512/app-park
powerfarm:lab-512/engine-park
powerfarm:lab-512/inference
powerfarm:lab-512/compute
```

Aliases such as `8gb` and `512` are accepted only as CLI conveniences and are
normalized before authorization. Grants and receipts store canonical resource
names only.

## 6. Application manifest

The Superstructure owns the schema and guide. The Registry hosts the schema at
an immutable versioned URL and exposes the same validator to its UI and API.
The UI is a visual manifest editor; it does not have a second onboarding model.

```json
{
  "$schema": "https://registry.powerfarm.app/schemas/powerfarm-app-manifest.v1.json",
  "manifest_version": "1.0",
  "app": {
    "id": "marketing-team",
    "name": "Powerfarm Marketing Team",
    "homepage": "https://marketing.powerfarm.app",
    "owner": "powerfarm"
  },
  "source": {
    "repository": "powerfarm/marketing-team",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "path": "powerfarm.app.json"
  },
  "identity": {
    "oauth": {
      "client_type": "confidential",
      "redirect_uris": ["https://marketing.powerfarm.app/auth/callback"],
      "scopes": ["openid", "email", "profile", "offline_access"]
    }
  },
  "requests": {
    "capabilities": [
      {
        "action": "app_park.deploy",
        "resource": "powerfarm:lab-8gb/app-park"
      }
    ]
  },
  "deployment": {
    "destination": "marketing-team",
    "exclude": ["node_modules", "target", ".git", ".env", "dist"],
    "build": ["npm ci", "npm run build"],
    "install": ["npm ci --omit=dev"],
    "verify": ["npm run healthcheck"]
  }
}
```

The manifest never contains tokens, passwords, client secrets, private keys,
SSH material, Supabase service keys, or machine credentials.

The Registry canonicalizes the manifest with JCS, computes SHA-256, stores the
exact JSON document and digest, and records its source repository, commit, and
path. Submitting the same digest is idempotent. A changed document creates a
new admission candidate; it does not mutate the admitted bytes silently.

## 7. Onboarding and admission

The UI and `POST /api/apps/onboard` consume the same manifest contract.

Onboarding performs:

1. authenticate the person and resolve their Powerfarm identity;
2. require `registry.admin` or `oauth.clients.manage`;
3. validate and hash the manifest;
4. create or reuse `identities(kind = 'app')`;
5. create an OAuth client through Supabase OAuth Admin;
6. store the app admission and provider link without storing the secret;
7. display a confidential client secret once;
8. verify a real OAuth callback;
9. activate `schengen.app.v1` standing;
10. admit only requested border grants approved by policy or an administrator.

The current `app_oauth_clients.status = pending_verification` becomes `active`
only after callback verification. A provider client created without a Registry
link is visible as `unlinked` and can be reconciled; another client is not
created silently.

## 8. Interactive CLI identity

`lab` is registered as a public OAuth client. It uses Authorization Code with
PKCE and contains no client secret. `lab auth login` opens Powerfarm Identity,
listens on the one registered loopback callback, verifies `state`, exchanges the
code, and stores refresh material in macOS Keychain under service
`app.powerfarm.lab`. Tokens are never written to `lab.json`, `.env`, shell
history, logs, or receipts.

`lab identity` shows the resolved person, CLI client, standing, and active
session. `lab grants` shows effective capabilities, their resources, expiry,
and source. Refresh is automatic and silent.

Supabase OAuth currently supports authorization code with PKCE and refresh
tokens, not `client_credentials`. Unattended work therefore uses a Powerfarm
workload identity and a short-lived ticket minted under a previously admitted
grant; it never reuses an OAuth client secret as a permanent machine password.

## 9. Deployment tickets

A ticket is an opaque, random, one-use bearer capability. The Registry stores
only its SHA-256 hash. The clear value is returned once to the caller and is
transported to the target executor over the existing SSH/Cloudflare path.

The recorded ticket binds:

- actor identity;
- app identity and admission;
- action;
- canonical target resource;
- manifest digest;
- artifact digest;
- standing and grant IDs used in the decision;
- issue and expiry timestamps;
- nonce and idempotency key;
- state `issued | claimed | succeeded | failed | refused | expired | revoked`.

Issuance is automatic when standing or grants already authorize the request.
The normal CLI output is one concise success path. Policy details appear only
on `--explain` or refusal.

## 10. LAB execution boundary

The existing `lab push` preflights remain valuable: workbench-only origin,
target normalization, source cleanliness, build, excludes, architecture,
staging, verification, rollback, and receipt.

The privileged write moves behind `powerfarm-parkd`, a small executor installed
on LAB 8GB and LAB 512. Park directories are owned by its dedicated system
account. The ordinary SSH user may upload an artifact to an inbox but cannot
write the live App Park or Engine Park directly.

The executor:

1. claims the ticket atomically at the Registry;
2. verifies target resource and ticket expiry;
3. verifies manifest and artifact SHA-256;
4. extracts into staging without following unsafe paths or symlinks;
5. runs only the admitted install and verification commands;
6. atomically activates the staged release;
7. rolls back on verification failure;
8. posts a completion, refusal, or failure receipt.

Manhattan owns installation and health of the machine-level executor and its
filesystem permissions. `powerfarm-parkd` owns deployment effects. Registry
owns identity, standing, grants, tickets, and receipts. None replaces another.

The phrase "only possible path" is not satisfied until a direct SSH write test
to both live park directories fails while a ticketed deployment succeeds.

## 11. CLI language

The first public command set is:

```text
lab auth login|logout|status
lab identity [--json]
lab grants [--json]
lab app validate [manifest]
lab app onboard [manifest]
lab deploy [manifest] --target <resource> [--dry-run] [--explain]
lab deployments [--json]
lab receipts [--json]
```

`lab push` remains temporarily as a compatibility alias for `lab deploy` and
prints one deprecation notice. `--force` may bypass source or target convenience
checks only; it can never bypass identity, grant, ticket, hash, or executor
validation.

## 12. Static credential retirement

The present `~/.radar/sync.env` and receiver Supabase key are bootstrap debt.
No app, engine, CLI plugin, or receiver may hold a generic administrative key
in the finished system. Interactive writes use the authenticated person token.
Unattended telemetry uses a scoped machine/workload identity with grants limited
to its own resource and event types.

Legacy paths remain read-only during migration. They are removed only after
the equivalent authenticated path has a live receipt and rollback proof.

## 13. Break glass

Emergency access is not a parallel authority. It is a separately named,
time-limited `break_glass` grant that requires explicit human step-up and always
emits a receipt with reason, actor, resource, start, expiry, and effects. The
normal `lab deploy` command cannot mint it.

## 14. Acceptance criteria

The feature is complete only when all statements below are proven:

1. UI and API validate the same manifest bytes and produce the same digest.
2. Repeating an onboarding request is idempotent.
3. An OAuth secret is shown once and never persisted by the Registry.
4. Callback verification activates admission and baseline standing.
5. `lab auth login` uses a public PKCE client and Keychain storage.
6. An admitted app deploys to an allowed park without a second approval prompt.
7. A missing, expired, wrong-resource, revoked, or replayed grant/ticket is
   refused with a receipt.
8. `--force` cannot bypass institutional authorization.
9. Direct SSH writes to live park directories fail on LAB 8GB and LAB 512.
10. Ticketed deployment, health verification, and rollback work on both LABs.
11. Revocation prevents a new deployment within one Registry request.
12. No generic Supabase service key remains in apps, engines, CLI plugins, or
    the receiver.
13. Every admitted deployment can be traced from receipt to ticket, grant,
    identities, manifest digest, artifact digest, machine, and human actor.

