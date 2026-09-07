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
    if jsonb_typeof(p_metadata->'health') is distinct from 'object'
       or coalesce(p_metadata->'health'->>'path', '') !~ '^/' then
      v_problems := array_append(v_problems, 'health.path must be an absolute path');
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

  return v_problems;
end;
$$;
