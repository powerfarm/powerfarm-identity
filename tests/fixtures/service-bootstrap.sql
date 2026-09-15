create role anon; create role authenticated; create role service_role;
create schema auth; create schema extensions;
create extension pgcrypto with schema extensions;
create table auth.users(id uuid primary key);
insert into auth.users values('e9f02bf2-936a-4b73-b27e-4d53b6736c13');
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
grant usage on schema public,auth to authenticated,anon;
grant execute on function auth.uid() to authenticated,anon;
