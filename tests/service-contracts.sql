-- Run against the isolated Registry fixture after the service migration.
-- No production identities, credentials or contracts are used here.
begin;
insert into public.identities(id,kind,name) values
 ('11111111-1111-4111-8111-111111111111','app','Antenna test'),
 ('22222222-2222-4222-8222-222222222222','app','Webhook test'),
 ('33333333-3333-4333-8333-333333333333','app','Client test');
insert into public.service_credentials(identity_id,label,secret_hash) values
 ('11111111-1111-4111-8111-111111111111','test',encode(extensions.digest('test-antenna-token','sha256'),'hex')),
 ('33333333-3333-4333-8333-333333333333','test',encode(extensions.digest('test-client-token','sha256'),'hex'));
select set_config('request.jwt.claim.sub','e9f02bf2-936a-4b73-b27e-4d53b6736c13',true);
set local role authenticated;
do $$
declare
 raw text := '{"schema":"antenna.service.v1","title":"Webhook test","transport":"webhook","capabilities":["object.store"],"graph":{"start":"store","nodes":{"store":"object.store"},"edges":[["store","END"]]}}';
 c jsonb; child jsonb; snap jsonb; denied boolean; admin_id uuid;
begin
 select public.identidade_atual() into admin_id;
 perform public.powerfarm_service_command('publish',jsonb_build_object('source',raw,'sha256',encode(extensions.digest(raw,'sha256'),'hex'),
   'artifact_id','pf.test.service','version','1','source_repo','test/fixture','source_commit',repeat('a',40),'source_path','test.json'));
 c:=public.powerfarm_service_command('propose',jsonb_build_object('name','parent-test','kind','service',
   'provider_id','11111111-1111-4111-8111-111111111111','client_id','22222222-2222-4222-8222-222222222222',
   'artifact_id','pf.test.service','version','1','valid_until',now()+interval '1 day',
   'terms',jsonb_build_object('max_bytes',1024,'destinations','[]'::jsonb)));
 denied:=false;
 begin perform public.powerfarm_service_command('propose',jsonb_build_object('name','unaccepted','kind','client','parent','parent-test',
   'client_id','33333333-3333-4333-8333-333333333333','valid_until',now()+interval '1 hour','terms',jsonb_build_object('max_bytes',512,'destinations','[]'::jsonb)));
 exception when others then denied:=true; end;
 if not denied then raise exception 'unaccepted parent admitted a client'; end if;
 denied:=false;
 begin perform public.powerfarm_service_command('accept',jsonb_build_object('name','parent-test','sha256','wrong','party_id',c->>'provider_id'));
 exception when others then denied:=true; end;
 if not denied then raise exception 'accepted wrong hash'; end if;
 perform public.powerfarm_service_command('accept',jsonb_build_object('name','parent-test','sha256',c->>'terms_sha256','party_id',c->>'provider_id'));
 perform public.powerfarm_service_command('accept',jsonb_build_object('name','parent-test','sha256',c->>'terms_sha256','party_id',c->>'client_id'));
 child:=public.powerfarm_service_command('propose',jsonb_build_object('name','client-test','kind','client','parent','parent-test',
   'client_id','33333333-3333-4333-8333-333333333333','valid_until',now()+interval '1 hour',
   'terms',jsonb_build_object('max_bytes',512,'destinations','[]'::jsonb)));
 perform public.powerfarm_service_command('accept',jsonb_build_object('name','client-test','sha256',child->>'terms_sha256','party_id',child->>'provider_id'));
 perform public.powerfarm_service_command('accept',jsonb_build_object('name','client-test','sha256',child->>'terms_sha256','party_id',child->>'client_id'));
 -- Duplicate acceptance is idempotent.
 perform public.powerfarm_service_command('accept',jsonb_build_object('name','client-test','sha256',child->>'terms_sha256','party_id',child->>'client_id'));
 if (select count(*) from public.service_contract_events where contract_id=(child->>'id')::uuid and action='accepted')<>2 then raise exception 'duplicate acceptance'; end if;
 snap:=public.powerfarm_antenna_snapshot('test-antenna-token');
 if jsonb_array_length((snap->>'payload')::jsonb->'bindings')<>1 then raise exception 'accepted client missing from snapshot'; end if;
 if snap->>'hmac_sha256'<>encode(extensions.hmac(snap->>'payload','test-antenna-token','sha256'),'hex') then raise exception 'bad snapshot signature'; end if;
 denied:=false;
 begin perform public.powerfarm_service_command('propose',jsonb_build_object('name','overbroad','kind','client','parent','parent-test',
   'client_id','33333333-3333-4333-8333-333333333333','valid_until',now()+interval '1 hour','terms',jsonb_build_object('max_bytes',2048,'destinations','[]'::jsonb)));
 exception when others then denied:=true; end;
 if not denied then raise exception 'client exceeded parent limits'; end if;
 denied:=false;
 begin update public.artifact_versions set sha256=repeat('b',64) where artifact_id='pf.test.service';
 exception when others then denied:=true; end;
 if not denied then raise exception 'rewrote service definition source'; end if;
 perform public.powerfarm_service_command('revoke',jsonb_build_object('name','parent-test','sha256',c->>'terms_sha256'));
 snap:=public.powerfarm_antenna_snapshot('test-antenna-token');
 if jsonb_array_length((snap->>'payload')::jsonb->'bindings')<>0 then raise exception 'revoked parent still grants client authority'; end if;
 -- A logged-in subject without identity/grant cannot mutate service contracts.
 perform set_config('request.jwt.claim.sub','44444444-4444-4444-8444-444444444444',true);
 denied:=false;
 begin perform public.powerfarm_service_command('revoke',jsonb_build_object('name','parent-test','sha256',c->>'terms_sha256'));
 exception when insufficient_privilege then denied:=true; end;
 if not denied then raise exception 'unprivileged operator wrote contracts'; end if;
 if (select count(*) from public.service_contracts)>0 then raise exception 'RLS exposed unrelated contracts'; end if;
end;
$$;
set local role anon;
do $$
declare denied boolean:=false;
begin
 begin perform * from public.service_contracts; exception when insufficient_privilege then denied:=true; end;
 if not denied then raise exception 'anonymous contract read allowed'; end if;
 denied:=false;
 begin perform public.powerfarm_antenna_snapshot('wrong-token'); exception when insufficient_privilege then denied:=true; end;
 if not denied then raise exception 'snapshot allowed invalid daemon credential'; end if;
end;
$$;
rollback;
