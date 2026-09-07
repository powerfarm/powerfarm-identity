import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const migrationsUrl = new URL("../supabase/migrations/", import.meta.url);

test("migration source contains authority, one ADK table migration, and its advisor follow-up", async () => {
  const files = (await readdir(migrationsUrl)).filter((name) => name.endsWith(".sql")).sort();
  assert.deepEqual(files, [
    "0001_identity.sql",
    "0002_manifest.sql",
    "0003_autoridade.sql",
    "0004_adk_runtime.sql",
    "0005_adk_runtime_advisors.sql",
    "20260820192536_gadget_lineage.sql",
    "20260829012434_admit_brand_v03.sql",
    "20260829012439_registry_identity_authority.sql",
    "20260907180351_entity_contracts.sql",
    "20260907181653_entity_hardening.sql",
    "20260907181737_entity_hardening_fix_array_append.sql",
    "20260907195443_place_and_park_contracts.sql",
  ]);
});

test("recovered production entity migrations match live statement md5", async () => {
  const expected = {
    "20260907180351_entity_contracts.sql": "8374306a65f0ddc22ca56dac4bfd1233",
    "20260907181653_entity_hardening.sql": "34e30574a2407bbd94c7bfd185d9a06b",
    "20260907181737_entity_hardening_fix_array_append.sql": "f10de7d291aa06b7e9dedf28a2c78505",
  };
  for (const [name, hash] of Object.entries(expected)) {
    const raw = await readFile(new URL(name, migrationsUrl));
    const body = raw.at(-1) === 0x0a ? raw.subarray(0, -1) : raw;
    assert.equal(createHash("md5").update(body).digest("hex"), hash, name);
  }
});

test("Registry authority migration makes OAuth administration grant-bound", async () => {
  const sql = (await readFile(new URL("20260829012439_registry_identity_authority.sql", migrationsUrl), "utf8"))
    .replaceAll(/--.*$/gm, "")
    .toLowerCase();

  assert.match(sql, /create or replace function public\.has_registry_grant\(p_action text\)/);
  assert.match(sql, /set search_path = ''/);
  assert.match(sql, /revoke all on function public\.has_registry_grant\(text\) from public/);
  assert.match(sql, /grant execute on function public\.has_registry_grant\(text\) to authenticated/);
  assert.match(sql, /create table public\.app_oauth_clients/);
  assert.match(sql, /oauth_client_id\s+uuid\s+not null unique/);
  assert.match(sql, /alter table public\.app_oauth_clients enable row level security/);
  assert.match(sql, /revoke all on public\.app_oauth_clients from anon/);
  assert.match(sql, /revoke all on public\.app_oauth_clients from public/);
  assert.match(sql, /has_registry_grant\('oauth\.clients\.manage'/);
  assert.match(sql, /has_registry_grant\('registry\.admin'/);
  assert.doesNotMatch(sql, /client_secret/);
  assert.doesNotMatch(sql, /service_role/);
});

test("Gadget lineage migration resolves an exact authorized execution snapshot", async () => {
  const files = (await readdir(migrationsUrl)).filter((name) => name.endsWith("_gadget_lineage.sql"));
  assert.equal(files.length, 1);
  const sql = (await readFile(new URL(files[0], migrationsUrl), "utf8"))
    .replaceAll(/--.*$/gm, "")
    .toLowerCase();

  for (const table of ["workspaces", "workspace_members", "gadgets", "gadget_drafts",
    "gadget_revisions", "gadget_installations", "run_grants"]) {
    assert.match(sql, new RegExp(`create table public\\.${table}\\b`));
    assert.match(sql, new RegExp(`alter table public\\.${table} enable row level security`));
  }

  assert.match(sql, /unique\s*\(gadget_id, revision\)/);
  assert.match(sql, /unique\s*\(gadget_id, content_hash\)/);
  assert.match(sql, /check \(content_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/);
  assert.match(sql, /create or replace function public\.powerfarm_gadget_apply_patch/);
  assert.match(sql, /revision_conflict/);
  assert.match(sql, /create or replace function public\.powerfarm_gadget_publish/);
  assert.match(sql, /create or replace function public\.powerfarm_resolve_execution/);
  assert.match(sql, /create or replace function public\.powerfarm_issue_run_grant/);
  assert.match(sql, /create or replace function public\.powerfarm_execution_envelope/);
  assert.match(sql, /create or replace function public\.powerfarm_resume_envelope/);
  assert.match(sql, /gadget_revision_hash/);
  assert.match(sql, /gadget_definition_hash/);
  assert.match(sql, /allowed_capabilities/);
  assert.match(sql, /authority_version/);
  assert.match(sql, /idempotency_key/);
  assert.match(sql, /drop policy if exists runs_leitura on public\.runs/);
  assert.match(sql, /created_by = public\.identidade_atual\(\)/);
  assert.match(sql, /revoke insert, update, delete on public\.runs from authenticated/);
  assert.equal((sql.match(/extensions\.digest\(/g) ?? []).length, 2);
  assert.doesNotMatch(sql, /service_role|refresh_token|access_token/);
});

test("ADK advisor follow-up changes no table topology", async () => {
  const sql = (await readFile(new URL("0005_adk_runtime_advisors.sql", migrationsUrl), "utf8"))
    .replaceAll(/--.*$/gm, "")
    .toLowerCase();
  assert.match(sql, /alter function public\.identidade_atual\(\) security invoker/);
  assert.match(sql, /create index adk_sessions_user/);
  assert.doesNotMatch(sql, /create table|alter table|drop table/);
});

test("ADK runtime migration keeps durable state together and behind RLS", async () => {
  const sql = (await readFile(new URL("0004_adk_runtime.sql", migrationsUrl), "utf8"))
    .replaceAll(/--.*$/gm, "")
    .toLowerCase();

  assert.match(sql, /create schema if not exists adk/);
  for (const table of ["sessions", "events", "checkpoints", "effects"]) {
    assert.match(sql, new RegExp(`create table adk\\.${table}\\b`));
    assert.match(sql, new RegExp(`alter table adk\\.${table} enable row level security`));
  }

  assert.match(sql, /alter table public\.runs/);
  assert.match(sql, /'waiting_input'/);
  assert.match(sql, /'completed'/);
  assert.match(sql, /create or replace function public\.powerfarm_session_append_event/);
  assert.match(sql, /create or replace function public\.powerfarm_effect_claim/);
  assert.match(sql, /create or replace function public\.powerfarm_run_transition/);
  assert.match(sql, /revoke all on schema adk from public/);
  assert.match(sql, /revoke execute on function public\.powerfarm_session_create[\s\S]*from public/);
  assert.match(sql, /idempotency key is required/);
  assert.match(sql, /invalid run transition/);
  assert.match(sql, /v_inserted/);
  assert.doesNotMatch(sql, /service_role/);
});

test("place and park contracts add place kind, versioned contracts, and CI without a service_role", async () => {
  const sql = (await readFile(new URL("20260907195443_place_and_park_contracts.sql", migrationsUrl), "utf8"))
    .replaceAll(/--.*$/gm, "")
    .toLowerCase();

  assert.match(sql, /'place'/);
  assert.doesNotMatch(sql, /kind in \([^)]*'engine'/);
  assert.match(sql, /powerfarm_entity_contract\(p_kind text, p_version integer\)/);
  assert.match(sql, /when 2 then array\['slug','title','owner','lifecycle','runtime','repository','health','environments','place','qualifier'\]/);
  assert.match(sql, /park_type must be engine-park or app-park/);
  assert.match(sql, /qualifier must be app or engine/);
  assert.match(sql, /create or replace function public\.powerfarm_register_entity/);
  assert.match(sql, /create table if not exists public\.ci_reports/);
  assert.match(sql, /create table if not exists public\.service_credentials/);
  assert.match(sql, /alter table public\.ci_reports enable row level security/);
  assert.match(sql, /alter table public\.service_credentials enable row level security/);
  assert.match(sql, /create or replace view public\.park_occupancy/);
  assert.match(sql, /security_invoker = true/);
  assert.match(sql, /'ci\.report'/);
  assert.match(sql, /'deployments\.read'/);
  assert.match(sql, /this is the powerfarm service credential, not a github app key/);
  assert.doesNotMatch(sql, /service_role/);
});
