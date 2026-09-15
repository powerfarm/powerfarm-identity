# Contract service migration

Applied to project `wmsrqefgdgcijupeogfa` on 2026-09-15 as migration
`20260915083641_antenna_service_contracts`. The file was initially created by the
CLI; its filename was reconciled to the version allocated by the deployment API.
The existing applied-ledger.json is the historical August snapshot and does not
claim to inventory September migrations.

Service definitions reference the existing artifacts/artifact_versions. Contracts
reference the existing identities. Mutations use the authenticated operator's
existing registry.admin grant; the event log records both represented party and
actual actor. Clients receive only authority from accepted, unexpired parents.

`powerfarm_service_command` is intentionally callable by authenticated users and
checks the admin mandate inside the transaction. Direct table writes are revoked.
`powerfarm_antenna_snapshot` is intentionally reachable with the publishable key:
it requires a valid opaque service credential, verifies its digest and lifetime,
and returns only bindings whose service provider is that credential's identity.
The returned snapshot is HMAC-signed, has a 60-second lease, and includes client
credential digests. It is private daemon data, not a public manifest.

The Supabase advisor reports these explicitly authenticated SECURITY DEFINER
boundaries as callable functions. Their allow/deny cases are exercised in
`tests/service-contracts.sql`; see the [advisor explanation](https://supabase.com/docs/guides/database/database-linter?lint=0028_anon_security_definer_function_executable).
Pre-existing notices outside these functions were not changed by this migration.

Run `sh tests/run-service-contracts.sh` for a fresh isolated PostgreSQL instance.
The test covers both acceptances, exact hash, immutable source, duplicate
acceptance, client limits, parent revocation, signature, unauthenticated access,
unrelated identity visibility and absent operator grants. The production CLI
activation additionally exercises the deployed RPC through the real OAuth/RLS path.
