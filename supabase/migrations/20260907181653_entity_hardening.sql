create or replace function public.powerfarm_entity_violations(p_kind text, p_metadata jsonb)
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
begin
  if public.powerfarm_entity_contract(p_kind) is null then
    return array['unknown kind: ' || p_kind];
  end if;
  if jsonb_typeof(p_metadata) is distinct from 'object' then
    return array['metadata must be a JSON object'];
  end if;

  foreach v_key in array public.powerfarm_entity_contract(p_kind) loop
    if not (p_metadata ? v_key) then
      v_problems := v_problems || ('missing required field: ' || v_key);
    end if;
  end loop;

  if p_metadata ? 'slug' and coalesce(p_metadata->>'slug', '') !~ v_slug_re then
    v_problems := v_problems || 'slug must match pf.<name>';
  end if;
  if p_metadata ? 'owner' and coalesce(p_metadata->>'owner', '') !~ v_slug_re then
    v_problems := v_problems || 'owner must be an entity slug';
  end if;
  if p_metadata ? 'title' and coalesce(length(p_metadata->>'title'), 0) < 2 then
    v_problems := v_problems || 'title must be at least 2 characters';
  end if;
  if p_metadata ? 'lifecycle' and not (p_metadata->>'lifecycle' = any (v_lifecycles)) then
    v_problems := v_problems || ('lifecycle must be one of ' || array_to_string(v_lifecycles, ', '));
  end if;

  if p_kind = 'app' then
    if jsonb_typeof(p_metadata->'repository') is distinct from 'object'
       or coalesce(p_metadata->'repository'->>'url', '') !~ '^https://' then
      v_problems := v_problems || 'repository.url must be an https URL';
    end if;
    if jsonb_typeof(p_metadata->'health') is distinct from 'object'
       or coalesce(p_metadata->'health'->>'path', '') !~ '^/' then
      v_problems := v_problems || 'health.path must be an absolute path';
    end if;
    if jsonb_typeof(p_metadata->'environments') is distinct from 'array'
       or jsonb_array_length(p_metadata->'environments') = 0 then
      v_problems := v_problems || 'environments must be a non-empty array';
    else
      if exists (
        select 1 from jsonb_array_elements_text(p_metadata->'environments') as e(name)
         where not (e.name = any (v_environments))
      ) then
        v_problems := v_problems || ('environments may only contain ' || array_to_string(v_environments, ', '));
      end if;
    end if;
  end if;

  if p_kind = 'agent' then
    if jsonb_typeof(p_metadata->'capabilities') is distinct from 'array'
       or jsonb_array_length(p_metadata->'capabilities') = 0 then
      v_problems := v_problems || 'capabilities must be a non-empty array';
    end if;
  end if;

  if p_kind = 'machine' then
    if not (coalesce(p_metadata->>'os','') = any (array['macos','linux','windows','other'])) then
      v_problems := v_problems || 'os must be macos, linux, windows or other';
    end if;
    if not (coalesce(p_metadata->>'arch','') = any (array['arm64','x86_64','other'])) then
      v_problems := v_problems || 'arch must be arm64, x86_64 or other';
    end if;
  end if;

  if p_kind = 'workflow' then
    if jsonb_typeof(p_metadata->'trigger') is distinct from 'object'
       or not (coalesce(p_metadata->'trigger'->>'kind','') = any (array['webhook','schedule','manual','event'])) then
      v_problems := v_problems || 'trigger.kind must be webhook, schedule, manual or event';
    end if;
    if jsonb_typeof(p_metadata->'steps') is distinct from 'array'
       or jsonb_array_length(p_metadata->'steps') = 0 then
      v_problems := v_problems || 'steps must be a non-empty array';
    end if;
  end if;

  if p_kind = 'object' then
    if not (coalesce(p_metadata->>'qualifier','') = any (
      array['brand','store','policy','prompt','schema','dataset','document'])) then
      v_problems := v_problems || 'qualifier is not one of the permitted values';
    end if;
  end if;

  return v_problems;
end;
$$;

create or replace function public.powerfarm_entity_admissible(p_kind text, p_metadata jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select cardinality(public.powerfarm_entity_violations(p_kind, p_metadata)) = 0;
$$;

create or replace function public.powerfarm_identity_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_problems text[];
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

    v_problems := public.powerfarm_entity_violations(new.kind, new.metadata);
    if cardinality(v_problems) > 0 then
      raise exception 'contract violated: %', array_to_string(v_problems, '; ');
    end if;

    if new.metadata ? 'owner'
       and not exists (select 1 from public.identities i where i.slug = new.metadata->>'owner') then
      raise exception 'owner % is not a registered entity', new.metadata->>'owner';
    end if;
  end if;

  return new;
end;
$$;

create trigger identities_guard
  before insert or update on public.identities
  for each row execute function public.powerfarm_identity_guard();

create or replace function public.powerfarm_deployment_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me uuid := public.identidade_atual();
begin
  if v_me is null then
    raise exception 'Powerfarm identity link required';
  end if;
  if tg_op = 'INSERT' then
    new.deployed_by := v_me;
  elsif new.deployed_by is distinct from old.deployed_by then
    raise exception 'deployed_by is immutable';
  end if;

  if new.entity_id is not null and not exists (
    select 1 from public.identities i where i.id = new.entity_id
  ) then
    raise exception 'unknown entity';
  end if;

  if new.machine_id is not null and not exists (
    select 1 from public.identities i where i.id = new.machine_id and i.kind = 'machine'
  ) then
    raise exception 'machine_id must reference an entity of kind machine';
  end if;

  return new;
end;
$$;

create trigger deployments_guard
  before insert or update on public.deployments
  for each row execute function public.powerfarm_deployment_guard();

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

  if p_machine is not null then
    select id into v_machine from public.identities where slug = p_machine and kind = 'machine';
    if v_machine is null then raise exception 'unknown machine: %', p_machine; end if;
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

revoke all on function public.powerfarm_entity_violations(text, jsonb) from public, anon;
revoke all on function public.powerfarm_record_deployment(text, text, text, text, text, text, text) from public, anon;
grant execute on function public.powerfarm_entity_violations(text, jsonb) to authenticated;
grant execute on function public.powerfarm_record_deployment(text, text, text, text, text, text, text) to authenticated;
