alter table public.identities drop constraint identities_kind_check;
alter table public.identities add constraint identities_kind_check
  check (kind in ('person', 'office', 'app', 'agent', 'machine', 'workflow', 'object'));

alter table public.identities
  add column slug text,
  add column contract_version integer,
  add column metadata jsonb not null default '{}'::jsonb;

update public.identities
   set slug = 'pf.' || regexp_replace(
                         regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g'),
                         '(^-+|-+$)', '', 'g')
 where slug is null;

alter table public.identities alter column slug set not null;
alter table public.identities add constraint identities_slug_key unique (slug);
alter table public.identities add constraint identities_slug_check
  check (slug ~ '^pf(\.[a-z0-9][a-z0-9-]*)+$');
alter table public.identities add constraint identities_contract_version_check
  check (contract_version is null or contract_version >= 1);

comment on column public.identities.slug is
  'Stable identifier. Never reused, never renamed - name may change, this may not.';
comment on column public.identities.contract_version is
  'Which contract admitted this entity. NULL means it predates contracts and is not retro-validated.';

create or replace function public.powerfarm_entity_contract(p_kind text)
returns text[]
language sql
immutable
set search_path = ''
as $$
  select case p_kind
    when 'person'   then array['slug','title']
    when 'office'   then array['slug','title','mandate']
    when 'app'      then array['slug','title','owner','lifecycle','runtime','repository','health','environments']
    when 'agent'    then array['slug','title','owner','lifecycle','mandate','capabilities']
    when 'machine'  then array['slug','title','owner','lifecycle','os','arch']
    when 'workflow' then array['slug','title','owner','lifecycle','trigger','steps']
    when 'object'   then array['slug','title','owner','qualifier']
  end;
$$;

comment on function public.powerfarm_entity_contract(text) is
  'Required metadata keys per kind. Must equal contracts/registry.json; enforced by scripts/check-contract-parity.mjs.';

create or replace function public.powerfarm_entity_admissible(p_kind text, p_metadata jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select coalesce(
    (select bool_and(p_metadata ? key)
       from unnest(public.powerfarm_entity_contract(p_kind)) as key),
    false);
$$;

alter table public.identities add constraint identities_contract_satisfied
  check (
    contract_version is null
    or public.powerfarm_entity_admissible(kind, metadata)
  );

create table public.deployments (
  id              uuid primary key default gen_random_uuid(),
  entity_id       uuid not null references public.identities(id) on delete restrict,
  environment     text not null check (environment in ('development','preview','production')),
  status          text not null check (status in ('pending','live','failed','stopped','rolled_back')),
  machine_id      uuid references public.identities(id) on delete restrict,
  revision        text,
  artifact_sha256 text check (artifact_sha256 is null or artifact_sha256 ~ '^[0-9a-f]{64}$'),
  url             text,
  health_status   text check (health_status in ('passing','failing','unknown')),
  health_checked_at timestamptz,
  deployed_by     uuid not null references public.identities(id) on delete restrict,
  started_at      timestamptz not null default now(),
  finished_at     timestamptz,
  note            text
);

create index deployments_entity_idx on public.deployments (entity_id, started_at desc);
create unique index deployments_one_live_per_env
  on public.deployments (entity_id, environment)
  where status = 'live';

create or replace view public.entity_deployment_status
with (security_invoker = true) as
select i.id            as entity_id,
       i.slug,
       i.kind,
       i.name,
       i.contract_version,
       e.environment,
       coalesce(d.status, 'not_deployed') as status,
       d.revision,
       d.url,
       d.health_status,
       d.health_checked_at,
       d.started_at
  from public.identities i
  cross join (values ('development'), ('preview'), ('production')) as e(environment)
  left join public.deployments d
         on d.entity_id = i.id
        and d.environment = e.environment
        and d.status = 'live';

alter table public.deployments enable row level security;

create policy deployments_leitura on public.deployments
  for select to authenticated using (true);

create policy deployments_escrita on public.deployments
  for insert to authenticated
  with check (
    public.has_registry_grant('registry.admin')
    or public.has_registry_grant('deployments.manage')
  );

create policy deployments_transicao on public.deployments
  for update to authenticated
  using (
    public.has_registry_grant('registry.admin')
    or public.has_registry_grant('deployments.manage')
  )
  with check (
    public.has_registry_grant('registry.admin')
    or public.has_registry_grant('deployments.manage')
  );

create policy identities_contrato on public.identities
  for update to authenticated
  using (public.has_registry_grant('registry.admin')
         or public.has_registry_grant('registry.entities.manage'))
  with check (public.has_registry_grant('registry.admin')
              or public.has_registry_grant('registry.entities.manage'));

insert into public.grants (identity_id, action, resource, granted_by)
select i.id, action, 'registry', i.id
  from public.identities i
 cross join (values ('registry.entities.manage'), ('deployments.manage')) as requested(action)
 where i.kind = 'person'
   and i.name = 'danvoulez'
   and not exists (
     select 1 from public.grants g
      where g.identity_id = i.id
        and g.action = requested.action
        and g.revoked_at is null
   );

revoke all on function public.powerfarm_entity_contract(text) from public, anon;
revoke all on function public.powerfarm_entity_admissible(text, jsonb) from public, anon;
grant execute on function public.powerfarm_entity_contract(text) to authenticated;
grant execute on function public.powerfarm_entity_admissible(text, jsonb) to authenticated;
