-- Place as a kind. Engine is an app qualifier, not a kind.
-- Two-tier contracts: Park ↔ Powerfarm (place.park_type) and tenant ↔ Park
-- (app.place + app.qualifier). powerfarm_entity_contract gains a version axis
-- so app v1 (Antenna, already admitted) stays valid.

alter table public.identities drop constraint if exists identities_contract_satisfied;
alter table public.identities drop constraint identities_kind_check;
alter table public.identities add constraint identities_kind_check
  check (kind in ('person', 'office', 'app', 'agent', 'machine', 'workflow', 'object', 'place'));

drop function if exists public.powerfarm_entity_admissible(text, jsonb);
drop function if exists public.powerfarm_entity_violations(text, jsonb);
drop function if exists public.powerfarm_entity_contract(text);

create or replace function public.powerfarm_entity_contract(p_kind text, p_version integer)
returns text[]
language sql
immutable
set search_path = ''
as $$
  select case p_kind
    when 'person' then
      case p_version
        when 1 then array['slug','title']
      end
    when 'office' then
      case p_version
        when 1 then array['slug','title','mandate']
      end
    when 'app' then
      case p_version
        when 1 then array['slug','title','owner','lifecycle','runtime','repository','health','environments']
        when 2 then array['slug','title','owner','lifecycle','runtime','repository','health','environments','place','qualifier']
      end
    when 'agent' then
      case p_version
        when 1 then array['slug','title','owner','lifecycle','mandate','capabilities']
      end
    when 'machine' then
      case p_version
        when 1 then array['slug','title','owner','lifecycle','os','arch']
      end
    when 'workflow' then
      case p_version
        when 1 then array['slug','title','owner','lifecycle','trigger','steps']
      end
    when 'object' then
      case p_version
        when 1 then array['slug','title','owner','qualifier']
      end
    when 'place' then
      case p_version
        when 1 then array['slug','title','owner','machine','path','park_type']
      end
  end;
$$;

comment on function public.powerfarm_entity_contract(text, integer) is
  'Required metadata keys per kind and contract version. Must equal contracts/registry.json; enforced by scripts/check-contract-parity.mjs.';

create or replace function public.powerfarm_current_contract_version(p_kind text)
returns integer
language sql
immutable
set search_path = ''
as $$
  select case p_kind
    when 'app' then 2
    when 'place' then 1
    when 'person' then 1
    when 'office' then 1
    when 'agent' then 1
    when 'machine' then 1
    when 'workflow' then 1
    when 'object' then 1
  end;
$$;

create or replace function public.powerfarm_entity_violations(p_kind text, p_metadata jsonb, p_version integer)
returns text[]
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_problems text[] := '{}';
  v_key      text;
  v_slug_re  constant text := '^pf(\.[a-z0-9][a-z0-9-]*)+$';
  v_lifecycles constant text[] := array['experimental','production','deprecated','retired'];
  v_environments constant text[] := array['development','preview','production'];
  v_required text[];
  v_qualifier text;
begin
  v_required := public.powerfarm_entity_contract(p_kind, p_version);
  if v_required is null then
    return array['unknown kind or contract version: ' || p_kind || ' v' || coalesce(p_version::text, 'null')];
  end if;
  if jsonb_typeof(p_metadata) is distinct from 'object' then
    return array['metadata must be a JSON object'];
  end if;

  foreach v_key in array v_required loop
    if not (p_metadata ? v_key) then
      v_problems := array_append(v_problems, 'missing required field: ' || v_key);
    end if;
  end loop;

  if p_metadata ? 'slug' and coalesce(p_metadata->>'slug', '') !~ v_slug_re then
    v_problems := array_append(v_problems, 'slug must match pf.<name>');
  end if;
  if p_metadata ? 'owner' and coalesce(p_metadata->>'owner', '') !~ v_slug_re then
    v_problems := array_append(v_problems, 'owner must be an entity slug');
  end if;
  if p_metadata ? 'title' and coalesce(length(p_metadata->>'title'), 0) < 2 then
    v_problems := array_append(v_problems, 'title must be at least 2 characters');
  end if;
  if p_metadata ? 'lifecycle' and not (p_metadata->>'lifecycle' = any (v_lifecycles)) then
    v_problems := array_append(v_problems, 'lifecycle must be one of ' || array_to_string(v_lifecycles, ', '));
  end if;

  if p_kind = 'app' then
    if jsonb_typeof(p_metadata->'repository') is distinct from 'object'
       or coalesce(p_metadata->'repository'->>'url', '') !~ '^https://' then
      v_problems := array_append(v_problems, 'repository.url must be an https URL');
    end if;
    if jsonb_typeof(p_metadata->'environments') is distinct from 'array'
       or jsonb_array_length(p_metadata->'environments') = 0 then
      v_problems := array_append(v_problems, 'environments must be a non-empty array');
    else
      if exists (
        select 1 from jsonb_array_elements_text(p_metadata->'environments') as e(name)
         where not (e.name = any (v_environments))
      ) then
        v_problems := array_append(v_problems, 'environments may only contain ' || array_to_string(v_environments, ', '));
      end if;
    end if;

    v_qualifier := coalesce(p_metadata->>'qualifier', 'app');
    if p_version >= 2 then
      if not (v_qualifier = any (array['app','engine'])) then
        v_problems := array_append(v_problems, 'qualifier must be app or engine');
      end if;
      if p_metadata ? 'place' and coalesce(p_metadata->>'place', '') !~ v_slug_re then
        v_problems := array_append(v_problems, 'place must be an entity slug');
      end if;
    end if;

    if v_qualifier = 'engine' then
      if jsonb_typeof(p_metadata->'resources') is distinct from 'object' then
        v_problems := array_append(v_problems, 'resources must be a JSON object');
      end if;
      if jsonb_typeof(p_metadata->'capabilities') is distinct from 'array'
         or jsonb_array_length(p_metadata->'capabilities') = 0 then
        v_problems := array_append(v_problems, 'capabilities must be a non-empty array');
      end if;
      if jsonb_typeof(p_metadata->'bindings') is distinct from 'object'
         and jsonb_typeof(p_metadata->'bindings') is distinct from 'array' then
        v_problems := array_append(v_problems, 'bindings must be an object or array');
      end if;
      if jsonb_typeof(p_metadata->'health') is distinct from 'object'
         or not (coalesce(p_metadata->'health'->>'kind','process') = any (array['process','http'])) then
        v_problems := array_append(v_problems, 'health.kind must be process or http');
      end if;
    else
      if jsonb_typeof(p_metadata->'health') is distinct from 'object'
         or coalesce(p_metadata->'health'->>'path', '') !~ '^/' then
        v_problems := array_append(v_problems, 'health.path must be an absolute path');
      end if;
      if p_version >= 2 then
        if coalesce(length(p_metadata->>'route'), 0) < 1 then
          v_problems := array_append(v_problems, 'route is required in an app-park');
        end if;
        if coalesce(length(p_metadata->>'brand_version'), 0) < 1 then
          v_problems := array_append(v_problems, 'brand_version is required in an app-park');
        end if;
      end if;
    end if;
  end if;

  if p_kind = 'agent' then
    if jsonb_typeof(p_metadata->'capabilities') is distinct from 'array'
       or jsonb_array_length(p_metadata->'capabilities') = 0 then
      v_problems := array_append(v_problems, 'capabilities must be a non-empty array');
    end if;
  end if;

  if p_kind = 'machine' then
    if not (coalesce(p_metadata->>'os','') = any (array['macos','linux','windows','other'])) then
      v_problems := array_append(v_problems, 'os must be macos, linux, windows or other');
    end if;
    if not (coalesce(p_metadata->>'arch','') = any (array['arm64','x86_64','other'])) then
      v_problems := array_append(v_problems, 'arch must be arm64, x86_64 or other');
    end if;
  end if;

  if p_kind = 'workflow' then
    if jsonb_typeof(p_metadata->'trigger') is distinct from 'object'
       or not (coalesce(p_metadata->'trigger'->>'kind','') = any (array['webhook','schedule','manual','event'])) then
      v_problems := array_append(v_problems, 'trigger.kind must be webhook, schedule, manual or event');
    end if;
    if jsonb_typeof(p_metadata->'steps') is distinct from 'array'
       or jsonb_array_length(p_metadata->'steps') = 0 then
      v_problems := array_append(v_problems, 'steps must be a non-empty array');
    end if;
  end if;

  if p_kind = 'object' then
    if not (coalesce(p_metadata->>'qualifier','') = any (
      array['brand','store','policy','prompt','schema','dataset','document'])) then
      v_problems := array_append(v_problems, 'qualifier is not one of the permitted values');
    end if;
  end if;

  if p_kind = 'place' then
    if coalesce(p_metadata->>'machine', '') !~ v_slug_re then
      v_problems := array_append(v_problems, 'machine must be an entity slug');
    end if;
    if coalesce(p_metadata->>'path', '') !~ '^/' then
      v_problems := array_append(v_problems, 'path must be an absolute path');
    end if;
    if not (coalesce(p_metadata->>'park_type','') = any (array['engine-park','app-park'])) then
      v_problems := array_append(v_problems, 'park_type must be engine-park or app-park');
    end if;
  end if;

  return v_problems;
end;
$$;

create or replace function public.powerfarm_entity_admissible(p_kind text, p_metadata jsonb, p_version integer)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select cardinality(public.powerfarm_entity_violations(p_kind, p_metadata, p_version)) = 0;
$$;

alter table public.identities add constraint identities_contract_satisfied
  check (
    contract_version is null
    or public.powerfarm_entity_admissible(kind, metadata, contract_version)
  );

create or replace function public.powerfarm_identity_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_problems text[];
  v_place    public.identities%rowtype;
  v_park     text;
  v_qual     text;
begin
  if tg_op = 'UPDATE' then
    if new.slug is distinct from old.slug then
      raise exception 'slug is immutable: % may not become %', old.slug, new.slug;
    end if;
    if new.kind is distinct from old.kind then
      raise exception 'kind is immutable: % may not become %', old.kind, new.kind;
    end if;
    if old.contract_version is not null
       and coalesce(new.contract_version, 0) < old.contract_version then
      raise exception 'contract_version may not go backwards (% -> %)',
        old.contract_version, new.contract_version;
    end if;
  end if;

  if new.contract_version is not null then
    if coalesce(new.metadata->>'slug', '') <> new.slug then
      raise exception 'metadata.slug (%) must equal the entity slug (%)',
        coalesce(new.metadata->>'slug', '<absent>'), new.slug;
    end if;

    v_problems := public.powerfarm_entity_violations(new.kind, new.metadata, new.contract_version);
    if cardinality(v_problems) > 0 then
      raise exception 'contract violated: %', array_to_string(v_problems, '; ');
    end if;

    if new.metadata ? 'owner'
       and not exists (select 1 from public.identities i where i.slug = new.metadata->>'owner') then
      raise exception 'owner % is not a registered entity', new.metadata->>'owner';
    end if;

    if new.kind = 'place' then
      if not exists (
        select 1 from public.identities i
         where i.slug = new.metadata->>'machine' and i.kind = 'machine'
      ) then
        raise exception 'machine % is not a registered machine', new.metadata->>'machine';
      end if;
    end if;

    if new.metadata ? 'place' then
      select * into v_place from public.identities i where i.slug = new.metadata->>'place';
      if not found then
        raise exception 'place % is not a registered entity', new.metadata->>'place';
      end if;
      if v_place.kind is distinct from 'place' then
        raise exception 'place % is kind %, not place', v_place.slug, v_place.kind;
      end if;
      v_park := v_place.metadata->>'park_type';
      v_qual := coalesce(new.metadata->>'qualifier', 'app');
      if v_qual = 'engine' and v_park is distinct from 'engine-park' then
        raise exception 'engine % must sit in an engine-park, not %', new.slug, coalesce(v_park, '<none>');
      end if;
      if v_qual = 'app' and v_park is distinct from 'app-park' then
        raise exception 'app % must sit in an app-park, not %', new.slug, coalesce(v_park, '<none>');
      end if;
    end if;
  end if;

  return new;
end;
$$;

drop policy if exists identities_escrita on public.identities;
create policy identities_escrita on public.identities
  for insert to authenticated
  with check (
    public.has_registry_grant('registry.admin')
    or public.has_registry_grant('registry.entities.manage')
  );

create or replace function public.powerfarm_register_entity(
  p_kind             text,
  p_name             text,
  p_metadata         jsonb,
  p_mandate          text default null,
  p_contract_version integer default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me      uuid := public.identidade_atual();
  v_kind    text := p_kind;
  v_meta    jsonb := coalesce(p_metadata, '{}'::jsonb);
  v_version integer := p_contract_version;
  v_slug    text;
  v_row     public.identities%rowtype;
begin
  if v_me is null then
    raise exception 'Powerfarm identity link required';
  end if;
  if not (public.has_registry_grant('registry.admin')
          or public.has_registry_grant('registry.entities.manage')) then
    raise exception 'registry.entities.manage required';
  end if;

  if v_kind = 'engine' then
    v_kind := 'app';
    if coalesce(v_meta->>'qualifier', '') is distinct from 'engine' then
      v_meta := v_meta || jsonb_build_object('qualifier', 'engine');
    end if;
  end if;

  if v_version is null then
    v_version := public.powerfarm_current_contract_version(v_kind);
  end if;
  if v_version is null then
    raise exception 'unknown kind: %', p_kind;
  end if;

  v_slug := v_meta->>'slug';
  if v_slug is null or v_slug = '' then
    raise exception 'metadata.slug is required';
  end if;
  if p_name is null or length(p_name) < 2 then
    raise exception 'name is required';
  end if;

  select * into v_row from public.identities where slug = v_slug;
  if found then
    if v_row.kind is distinct from v_kind then
      raise exception 'slug % is already kind %', v_slug, v_row.kind;
    end if;
    if v_row.contract_version is not null then
      raise exception '% is already admitted at contract v%', v_slug, v_row.contract_version;
    end if;
    update public.identities
       set name = p_name,
           mandate = coalesce(p_mandate, mandate),
           metadata = v_meta,
           contract_version = v_version
     where id = v_row.id
     returning * into v_row;
  else
    insert into public.identities (kind, name, mandate, slug, metadata, contract_version, created_by)
    values (v_kind, p_name, p_mandate, v_slug, v_meta, v_version, v_me)
    returning * into v_row;
  end if;

  return to_jsonb(v_row);
end;
$$;

create or replace function public.powerfarm_record_deployment(
  p_slug        text,
  p_environment text,
  p_revision    text,
  p_url         text default null,
  p_machine     text default null,
  p_health      text default null,
  p_note        text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_entity  public.identities%rowtype;
  v_machine uuid;
  v_machine_slug text := p_machine;
  v_row     public.deployments%rowtype;
begin
  if public.identidade_atual() is null then
    raise exception 'Powerfarm identity link required';
  end if;
  if not (public.has_registry_grant('registry.admin')
          or public.has_registry_grant('deployments.manage')) then
    raise exception 'deployments.manage required';
  end if;

  select * into v_entity from public.identities where slug = p_slug;
  if not found then raise exception 'unknown entity: %', p_slug; end if;

  if v_entity.kind = 'place' then
    if v_machine_slug is null then
      v_machine_slug := v_entity.metadata->>'machine';
    elsif v_machine_slug is distinct from v_entity.metadata->>'machine' then
      raise exception 'place % is bound to machine %', v_entity.slug, v_entity.metadata->>'machine';
    end if;
  end if;

  if v_machine_slug is not null then
    select id into v_machine from public.identities where slug = v_machine_slug and kind = 'machine';
    if v_machine is null then raise exception 'unknown machine: %', v_machine_slug; end if;
  end if;

  update public.deployments
     set status = 'rolled_back', finished_at = now()
   where entity_id = v_entity.id
     and environment = p_environment
     and status = 'live';

  insert into public.deployments (
    entity_id, environment, status, machine_id, revision, url,
    health_status, health_checked_at, deployed_by, finished_at, note
  ) values (
    v_entity.id, p_environment, 'live', v_machine, p_revision, p_url,
    p_health, case when p_health is null then null else now() end,
    public.identidade_atual(), now(), p_note
  ) returning * into v_row;

  return to_jsonb(v_row);
end;
$$;

create table if not exists public.ci_reports (
  id           uuid primary key default gen_random_uuid(),
  entity_id    uuid not null references public.identities(id) on delete restrict,
  check_name   text not null,
  sha          text,
  status       text not null check (status in ('queued','in_progress','passed','failed','cancelled')),
  url          text,
  payload      jsonb not null default '{}'::jsonb,
  reported_by  uuid not null references public.identities(id) on delete restrict,
  reported_at  timestamptz not null default now()
);

create index if not exists ci_reports_entity_idx
  on public.ci_reports (entity_id, reported_at desc);

alter table public.ci_reports enable row level security;
revoke all on public.ci_reports from public, anon;
grant select on public.ci_reports to authenticated;

create policy ci_reports_leitura on public.ci_reports
  for select to authenticated using (true);

revoke insert, update, delete on public.ci_reports from authenticated;

create table if not exists public.service_credentials (
  id           uuid primary key default gen_random_uuid(),
  identity_id  uuid not null references public.identities(id) on delete cascade,
  label        text not null,
  secret_hash  text not null check (secret_hash ~ '^[0-9a-f]{64}$'),
  valid_from   timestamptz not null default now(),
  valid_until  timestamptz,
  revoked_at   timestamptz,
  revoked_reason text,
  created_by   uuid not null references public.identities(id) on delete restrict,
  created_at   timestamptz not null default now()
);

create unique index if not exists service_credentials_hash_active
  on public.service_credentials (secret_hash)
  where revoked_at is null;

alter table public.service_credentials enable row level security;
revoke all on public.service_credentials from public, anon, authenticated;

create policy service_credentials_admin on public.service_credentials
  for all to authenticated
  using (public.has_registry_grant('registry.admin'))
  with check (public.has_registry_grant('registry.admin'));

grant select on public.service_credentials to authenticated;

create or replace function public.powerfarm_issue_service_credential(
  p_slug  text,
  p_label text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me      uuid := public.identidade_atual();
  v_target  public.identities%rowtype;
  v_token   text;
  v_hash    text;
  v_row     public.service_credentials%rowtype;
begin
  if v_me is null then
    raise exception 'Powerfarm identity link required';
  end if;
  if not public.has_registry_grant('registry.admin') then
    raise exception 'registry.admin required';
  end if;

  select * into v_target from public.identities where slug = p_slug;
  if not found then raise exception 'unknown entity: %', p_slug; end if;

  v_token := 'pfk_' || encode(extensions.gen_random_bytes(32), 'hex');
  v_hash := encode(extensions.digest(convert_to(v_token, 'utf8'), 'sha256'), 'hex');

  insert into public.service_credentials (
    identity_id, label, secret_hash, created_by
  ) values (
    v_target.id, p_label, v_hash, v_me
  ) returning * into v_row;

  return jsonb_build_object(
    'id', v_row.id,
    'identity', v_target.slug,
    'label', v_row.label,
    'token', v_token,
    'note', 'Shown once. This is the Powerfarm service credential, not a GitHub App key.'
  );
end;
$$;

create or replace function public.powerfarm_report_ci(
  p_slug       text,
  p_check_name text,
  p_status     text,
  p_sha        text default null,
  p_url        text default null,
  p_payload    jsonb default '{}'::jsonb,
  p_token      text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me     uuid := public.identidade_atual();
  v_hash   text;
  v_entity public.identities%rowtype;
  v_row    public.ci_reports%rowtype;
begin
  if v_me is null then
    if p_token is null or p_token = '' then
      raise exception 'Powerfarm identity link or service credential required';
    end if;
    v_hash := encode(extensions.digest(convert_to(p_token, 'utf8'), 'sha256'), 'hex');
    select c.identity_id into v_me
      from public.service_credentials c
     where c.secret_hash = v_hash
       and c.revoked_at is null
       and c.valid_from <= now()
       and (c.valid_until is null or c.valid_until > now());
    if v_me is null then
      raise exception 'invalid service credential';
    end if;
    if not exists (
      select 1 from public.grants g
       where g.identity_id = v_me
         and g.action = 'ci.report'
         and g.revoked_at is null
         and g.valid_from <= now()
         and (g.valid_until is null or g.valid_until > now())
    ) then
      raise exception 'ci.report required';
    end if;
  else
    if not (public.has_registry_grant('ci.report')
            or public.has_registry_grant('registry.admin')) then
      raise exception 'ci.report required';
    end if;
  end if;

  select * into v_entity from public.identities where slug = p_slug;
  if not found then raise exception 'unknown entity: %', p_slug; end if;

  insert into public.ci_reports (
    entity_id, check_name, sha, status, url, payload, reported_by
  ) values (
    v_entity.id, p_check_name, p_sha, p_status, p_url, coalesce(p_payload, '{}'::jsonb), v_me
  ) returning * into v_row;

  return to_jsonb(v_row);
end;
$$;

create or replace view public.park_occupancy
with (security_invoker = true) as
select p.id              as place_id,
       p.slug            as place,
       p.name            as place_name,
       p.metadata->>'park_type' as park_type,
       p.metadata->>'machine'   as machine,
       p.metadata->>'path'      as path,
       t.id              as tenant_id,
       t.slug            as tenant,
       t.kind            as tenant_kind,
       t.metadata->>'qualifier' as qualifier,
       t.contract_version as tenant_contract_version
  from public.identities p
  left join public.identities t
         on t.metadata->>'place' = p.slug
 where p.kind = 'place';

insert into public.grants (identity_id, action, resource, granted_by)
select antenna.id, requested.action, 'registry', owner.id
  from public.identities antenna
  join public.identities owner
    on owner.slug = 'pf.danvoulez'
  cross join (values ('ci.report'), ('deployments.read')) as requested(action)
 where antenna.slug = 'pf.antenna'
   and not exists (
     select 1 from public.grants g
      where g.identity_id = antenna.id
        and g.action = requested.action
        and g.revoked_at is null
   );

revoke all on function public.powerfarm_entity_contract(text, integer) from public, anon;
revoke all on function public.powerfarm_entity_violations(text, jsonb, integer) from public, anon;
revoke all on function public.powerfarm_entity_admissible(text, jsonb, integer) from public, anon;
revoke all on function public.powerfarm_current_contract_version(text) from public, anon;
revoke all on function public.powerfarm_register_entity(text, text, jsonb, text, integer) from public, anon;
revoke all on function public.powerfarm_issue_service_credential(text, text) from public, anon;
revoke all on function public.powerfarm_report_ci(text, text, text, text, text, jsonb, text) from public, anon;

grant execute on function public.powerfarm_entity_contract(text, integer) to authenticated;
grant execute on function public.powerfarm_entity_violations(text, jsonb, integer) to authenticated;
grant execute on function public.powerfarm_entity_admissible(text, jsonb, integer) to authenticated;
grant execute on function public.powerfarm_current_contract_version(text) to authenticated;
grant execute on function public.powerfarm_register_entity(text, text, jsonb, text, integer) to authenticated;
grant execute on function public.powerfarm_issue_service_credential(text, text) to authenticated;
grant execute on function public.powerfarm_report_ci(text, text, text, text, text, jsonb, text) to authenticated;
grant execute on function public.powerfarm_record_deployment(text, text, text, text, text, text, text) to authenticated;

revoke all on public.park_occupancy from public, anon;
grant select on public.park_occupancy to authenticated;
