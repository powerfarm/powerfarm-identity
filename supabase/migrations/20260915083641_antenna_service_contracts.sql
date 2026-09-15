-- Service definitions are compiled projections of versioned Registry artifacts.
-- The existing identities, operator grants and service credentials remain the authority.
create table public.service_definitions (
  artifact_id text not null,
  version text not null,
  definition jsonb not null,
  primary key (artifact_id, version),
  foreign key (artifact_id, version) references public.artifact_versions(artifact_id,version)
);

create table public.service_contracts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique check (length(name) between 1 and 128),
  kind text not null check (kind in ('service','client')),
  parent_id uuid references public.service_contracts(id),
  provider_id uuid not null references public.identities(id),
  client_id uuid not null references public.identities(id),
  artifact_id text not null,
  version text not null,
  terms jsonb not null,
  terms_sha256 text not null,
  valid_until timestamptz not null,
  revoked_at timestamptz,
  created_by uuid not null references public.identities(id),
  created_at timestamptz not null default now(),
  foreign key (artifact_id,version) references public.service_definitions(artifact_id,version),
  check ((kind='service' and parent_id is null) or (kind='client' and parent_id is not null)),
  check (provider_id <> client_id)
);
create index service_contracts_parent on public.service_contracts(parent_id);
create index service_contracts_provider on public.service_contracts(provider_id);
create index service_contracts_client on public.service_contracts(client_id);
create index service_contracts_definition on public.service_contracts(artifact_id,version);
create index service_contracts_creator on public.service_contracts(created_by);

create table public.service_contract_events (
  id bigint generated always as identity primary key,
  contract_id uuid not null references public.service_contracts(id),
  action text not null check (action in ('proposed','accepted','revoked')),
  party_id uuid references public.identities(id),
  actor_id uuid not null references public.identities(id),
  terms_sha256 text not null,
  created_at timestamptz not null default now()
);
create index service_contract_events_contract on public.service_contract_events(contract_id,id);
create index service_contract_events_actor on public.service_contract_events(actor_id);
create index service_contract_events_party on public.service_contract_events(party_id);
create unique index service_contract_accept_once on public.service_contract_events(contract_id,party_id,terms_sha256)
  where action='accepted';

alter table public.service_definitions enable row level security;
alter table public.service_contracts enable row level security;
alter table public.service_contract_events enable row level security;
revoke all on public.service_definitions,public.service_contracts,public.service_contract_events from public,anon,authenticated;
grant select on public.service_definitions,public.service_contracts,public.service_contract_events to authenticated;
create policy service_definitions_read on public.service_definitions for select to authenticated using (public.identidade_atual() is not null);
create policy service_contracts_read on public.service_contracts for select to authenticated using (
  provider_id=public.identidade_atual() or client_id=public.identidade_atual() or public.has_registry_grant('registry.admin')
);
create policy service_contract_events_read on public.service_contract_events for select to authenticated using (
  exists(select 1 from public.service_contracts c where c.id=contract_id)
);

-- Only this command boundary writes contract state. Accepted terms never mutate.
create function public.powerfarm_service_command(p_operation text,p_document jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  me uuid := public.identidade_atual();
  c public.service_contracts%rowtype;
  parent public.service_contracts%rowtype;
  definition jsonb;
  raw text;
  sha text;
  party uuid;
  limits jsonb;
  item text;
begin
  if me is null or not public.has_registry_grant('registry.admin') then
    raise exception 'registry.admin required' using errcode='42501';
  end if;
  if p_operation='publish' then
    raw:=p_document->>'source';
    if raw is null or octet_length(raw)>65536 then raise exception 'definition source required, max 64 KiB'; end if;
    definition:=raw::jsonb;
    if definition->>'schema' is distinct from 'antenna.service.v1'
       or coalesce(definition->>'transport','') not in ('http','webhook','websocket','sse')
       or jsonb_typeof(definition->'graph') is distinct from 'object'
       or jsonb_typeof(definition->'capabilities') is distinct from 'array'
       or jsonb_array_length(definition->'capabilities')=0 then raise exception 'invalid service definition'; end if;
    for item in select jsonb_array_elements_text(definition->'capabilities') loop
      if item not in ('echo','object.store','document.inspect','delivery.create') then raise exception 'unsupported capability: %',item; end if;
    end loop;
    if coalesce(p_document->>'source_repo','')='' or coalesce(p_document->>'source_commit','') !~ '^[0-9a-f]{40}$'
       or coalesce(p_document->>'source_path','')='' then raise exception 'immutable source reference required'; end if;
    sha:=encode(extensions.digest(convert_to(raw,'UTF8'),'sha256'),'hex');
    if sha is distinct from p_document->>'sha256' then raise exception 'source hash mismatch'; end if;
    if exists(select 1 from public.service_definitions where artifact_id=p_document->>'artifact_id' and version=p_document->>'version') then
      if not exists(select 1 from public.artifact_versions where artifact_id=p_document->>'artifact_id' and version=p_document->>'version' and sha256=sha) then
        raise exception 'version is immutable';
      end if;
      return jsonb_build_object('artifact_id',p_document->>'artifact_id','version',p_document->>'version','sha256',sha,'existing',true);
    end if;
    insert into public.artifacts(id,kind,title,publisher,created_by)
      values(p_document->>'artifact_id','schema',coalesce(definition->>'title',p_document->>'artifact_id'),me,me)
      on conflict(id) do nothing;
    insert into public.artifact_versions(artifact_id,version,status,source_repo,source_commit,source_path,sha256,media_type,size_bytes,created_by)
      values(p_document->>'artifact_id',p_document->>'version','approved',p_document->>'source_repo',p_document->>'source_commit',p_document->>'source_path',sha,'application/json',octet_length(raw),me);
    insert into public.service_definitions values(p_document->>'artifact_id',p_document->>'version',definition);
    return jsonb_build_object('artifact_id',p_document->>'artifact_id','version',p_document->>'version','sha256',sha);
  elsif p_operation='propose' then
    limits:=coalesce(p_document->'terms','{}');
    if jsonb_typeof(limits) is distinct from 'object' or (limits - array['max_bytes','destinations'])<>'{}'::jsonb then
      raise exception 'unknown contract constraint';
    end if;
    if (limits->>'max_bytes')::bigint is null or (limits->>'max_bytes')::bigint not between 1 and 1048576 then raise exception 'max_bytes must be 1..1048576'; end if;
    if jsonb_typeof(limits->'destinations') is distinct from 'array' then raise exception 'destinations must be an array'; end if;
    for item in select jsonb_array_elements_text(limits->'destinations') loop
      if item !~ '^https?://' then raise exception 'destination must be an HTTP URL'; end if;
    end loop;
    if (p_document->>'valid_until')::timestamptz is null or (p_document->>'valid_until')::timestamptz<=now() then raise exception 'future valid_until required'; end if;
    if p_document->>'kind'='client' then
      select * into parent from public.service_contracts where name=p_document->>'parent' for update;
      if not found or parent.kind<>'service' or parent.revoked_at is not null or parent.valid_until<=now() then raise exception 'active parent service required'; end if;
      if (select count(distinct party_id) from public.service_contract_events where contract_id=parent.id and action='accepted' and terms_sha256=parent.terms_sha256)<>2 then raise exception 'parent service not accepted by both parties'; end if;
      if (limits->>'max_bytes')::bigint>(parent.terms->>'max_bytes')::bigint or not ((parent.terms->'destinations') @> (limits->'destinations'))
         or (p_document->>'valid_until')::timestamptz>parent.valid_until then raise exception 'client exceeds parent contract'; end if;
      p_document:=p_document || jsonb_build_object('provider_id',parent.client_id,'artifact_id',parent.artifact_id,'version',parent.version);
    elsif p_document->>'kind' is distinct from 'service' then raise exception 'kind must be service or client'; end if;
    -- The accepted hash covers the entire relationship, not only its limits.
    sha:=encode(extensions.digest(convert_to(jsonb_build_object(
      'kind',p_document->>'kind','parent_id',parent.id,'provider_id',p_document->>'provider_id',
      'client_id',p_document->>'client_id','artifact_id',p_document->>'artifact_id','version',p_document->>'version',
      'terms',limits,'valid_until',p_document->>'valid_until')::text,'UTF8'),'sha256'),'hex');
    insert into public.service_contracts(name,kind,parent_id,provider_id,client_id,artifact_id,version,terms,terms_sha256,valid_until,created_by)
      values(p_document->>'name',p_document->>'kind',parent.id,(p_document->>'provider_id')::uuid,(p_document->>'client_id')::uuid,
        p_document->>'artifact_id',p_document->>'version',limits,sha,(p_document->>'valid_until')::timestamptz,me) returning * into c;
    insert into public.service_contract_events(contract_id,action,actor_id,terms_sha256) values(c.id,'proposed',me,sha);
  elsif p_operation in ('accept','revoke') then
    select * into c from public.service_contracts where name=p_document->>'name' for update;
    if not found then raise exception 'unknown contract'; end if;
    if c.terms_sha256 is distinct from p_document->>'sha256' then raise exception 'exact contract hash required'; end if;
    if p_operation='accept' then
      if c.revoked_at is not null or c.valid_until<=now() then raise exception 'contract revoked or expired'; end if;
      party:=(p_document->>'party_id')::uuid;
      if party is null or party not in (c.provider_id,c.client_id) then raise exception 'signer is not a contract party'; end if;
      -- registry.admin is the existing explicit operator mandate. Both the
      -- represented party and the human operator accepting for it are retained.
      insert into public.service_contract_events(contract_id,action,party_id,actor_id,terms_sha256)
        values(c.id,'accepted',party,me,c.terms_sha256) on conflict do nothing;
    elsif c.revoked_at is null then
      update public.service_contracts set revoked_at=now() where id=c.id returning * into c;
      insert into public.service_contract_events(contract_id,action,actor_id,terms_sha256) values(c.id,'revoked',me,c.terms_sha256);
    end if;
  else raise exception 'unknown service operation'; end if;
  return to_jsonb(c) || jsonb_build_object('acceptances',(
    select count(distinct party_id) from public.service_contract_events where contract_id=c.id and action='accepted' and terms_sha256=c.terms_sha256));
end;
$$;
revoke all on function public.powerfarm_service_command(text,jsonb) from public,anon;
grant execute on function public.powerfarm_service_command(text,jsonb) to authenticated;

-- An authenticated daemon receives a short-lived compiled snapshot. Raw client
-- credentials never leave their holders; only digests are in this private response.
create function public.powerfarm_antenna_snapshot(p_token text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  audience uuid;
  payload jsonb;
  raw text;
begin
  select sc.identity_id into audience from public.service_credentials sc
    where sc.secret_hash=encode(extensions.digest(convert_to(p_token,'UTF8'),'sha256'),'hex')
      and sc.revoked_at is null and sc.valid_from<=now() and (sc.valid_until is null or sc.valid_until>now());
  if audience is null then raise exception 'invalid service credential' using errcode='42501'; end if;
  select jsonb_build_object('schema','antenna.snapshot.v1','audience',audience,'issued_at',now(),'expires_at',now()+interval '60 seconds',
    'bindings',coalesce(jsonb_agg(jsonb_build_object(
      'contract_id',c.id,'name',c.name,'terms_sha256',c.terms_sha256,'service_id',s.id,'service_sha256',s.terms_sha256,
      'client_id',c.client_id,'terms',c.terms,'definition',d.definition,'definition_sha256',v.sha256,
      'valid_until',least(c.valid_until,s.valid_until),
      'credentials',(select coalesce(jsonb_agg(jsonb_build_object('sha256',k.secret_hash,'valid_until',k.valid_until)),'[]')
          from public.service_credentials k where k.identity_id=c.client_id and k.revoked_at is null and k.valid_from<=now() and (k.valid_until is null or k.valid_until>now()))
    )),'[]')) into payload
    from public.service_contracts c
    join public.service_contracts s on s.id=c.parent_id
    join public.service_definitions d on (d.artifact_id,d.version)=(s.artifact_id,s.version)
    join public.artifact_versions v on (v.artifact_id,v.version)=(d.artifact_id,d.version)
    where c.kind='client' and s.provider_id=audience and v.status='approved'
      and c.revoked_at is null and s.revoked_at is null and c.valid_until>now() and s.valid_until>now()
      and (select count(distinct party_id) from public.service_contract_events e where e.contract_id=c.id and e.action='accepted' and e.terms_sha256=c.terms_sha256)=2
      and (select count(distinct party_id) from public.service_contract_events e where e.contract_id=s.id and e.action='accepted' and e.terms_sha256=s.terms_sha256)=2;
  raw:=payload::text;
  return jsonb_build_object('payload',raw,'hmac_sha256',encode(extensions.hmac(convert_to(raw,'UTF8'),convert_to(p_token,'UTF8'),'sha256'),'hex'));
end;
$$;
revoke all on function public.powerfarm_antenna_snapshot(text) from public;
grant execute on function public.powerfarm_antenna_snapshot(text) to anon,authenticated;

-- No API caller may rewrite a published service definition or its source hash.
create function public.service_definition_immutable() returns trigger language plpgsql set search_path='' as $$
begin
  if tg_table_name='artifact_versions' and not exists(select 1 from public.service_definitions where artifact_id=old.artifact_id and version=old.version) then
    if tg_op='DELETE' then return old; else return new; end if;
  end if;
  if tg_table_name='artifact_versions' and tg_op='UPDATE' and (to_jsonb(new)-'status'-'notes')=(to_jsonb(old)-'status'-'notes') then return new; end if;
  raise exception 'published service definition is immutable';
end;
$$;
create trigger service_definition_no_rewrite before update or delete on public.service_definitions for each row execute function public.service_definition_immutable();
create trigger service_source_no_rewrite before update or delete on public.artifact_versions for each row execute function public.service_definition_immutable();
revoke all on function public.service_definition_immutable() from public,anon,authenticated;
