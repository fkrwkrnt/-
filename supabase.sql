-- =====================================================================
--  우리끼리 테니스 리그 - Supabase 데이터베이스 설정
--  사용법: Supabase 대시보드 → SQL Editor → 이 파일 전체를 붙여넣고 Run
--  ※ 맨 아래 '여기에_운영자_비밀번호' 부분을 꼭 바꾼 뒤 실행하세요.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- 테이블 ----------
create table if not exists public.players (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(name) between 1 and 20),
  pin_hash    text,
  guest       boolean not null default false,
  created_at  timestamptz not null default now()
);
create unique index if not exists players_name_key on public.players (lower(name));

create table if not exists public.matches (
  id            uuid primary key default gen_random_uuid(),
  type          text not null check (type in ('singles','doubles')),
  a             uuid[] not null,
  b             uuid[] not null,
  sets          jsonb not null,
  winner        text not null check (winner in ('A','B')),
  played_on     date not null default current_date,
  reported_by   uuid references public.players(id) on delete set null,
  status        text not null default 'pending' check (status in ('pending','confirmed')),
  created_at    timestamptz not null default now(),
  confirmed_at  timestamptz
);
create index if not exists matches_reported_by_idx on public.matches (reported_by);

create table if not exists public.settings (
  id            int primary key default 1 check (id = 1),
  ranking_mode  text not null default 'winrate' check (ranking_mode in ('winrate','elo')),
  min_games     int  not null default 0 check (min_games between 0 and 50),
  admin_hash    text not null
);

-- ---------- 접근 권한 ----------
-- 누구나 읽을 수 있지만, 쓰기는 아래 함수(PIN/운영자 비밀번호 검사)로만 가능
alter table public.players  enable row level security;
alter table public.matches  enable row level security;
alter table public.settings enable row level security;

revoke all on public.players, public.settings, public.matches from anon, authenticated;
grant select on public.matches to anon, authenticated;
drop policy if exists "matches are public" on public.matches;
create policy "matches are public" on public.matches for select using (true);

-- PIN과 운영자 비밀번호 열은 읽을 수 없게 열 단위로만 공개
grant select (id, name, guest, created_at) on public.players to anon, authenticated;
grant select (ranking_mode, min_games) on public.settings to anon, authenticated;
drop policy if exists "players are public" on public.players;
create policy "players are public" on public.players for select using (true);
drop policy if exists "settings are public" on public.settings;
create policy "settings are public" on public.settings for select using (true);
create or replace view public.v_players with (security_invoker = on) as
  select id, name, guest, created_at from public.players;
create or replace view public.v_settings with (security_invoker = on) as
  select ranking_mode, min_games from public.settings;
grant select on public.v_players, public.v_settings to anon, authenticated;

-- ---------- 내부 검사 함수 ----------
create or replace function public._auth(p_player uuid, p_pin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from players
                 where id = p_player and pin_hash is not null and pin_hash = crypt(coalesce(p_pin,''), pin_hash)) then
    raise exception '로그인 정보가 맞지 않아요. 다시 로그인해 주세요.';
  end if;
end $$;

create or replace function public._admin(p_pw text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from settings where admin_hash = crypt(coalesce(p_pw,''), admin_hash)) then
    raise exception '운영자 비밀번호가 맞지 않아요.';
  end if;
end $$;

create or replace function public._clean_name(p_name text) returns text
language plpgsql immutable set search_path = public as $$
declare n text := btrim(coalesce(p_name,''));
begin
  if char_length(n) < 1 or char_length(n) > 20 then
    raise exception '이름은 1~20자로 입력해 주세요.';
  end if;
  return n;
end $$;

create or replace function public._check_pin(p_pin text) returns void
language plpgsql immutable set search_path = public as $$
begin
  if coalesce(p_pin,'') !~ '^[0-9]{4,6}$' then
    raise exception 'PIN은 숫자 4~6자리로 정해 주세요.';
  end if;
end $$;

revoke all on function public._auth(uuid,text), public._admin(text) from public, anon, authenticated;

-- ---------- 참가자 함수 ----------
-- 처음 참가 (운영자가 미리 이름만 등록해 둔 선수라면 그 이름을 이어받음)
create or replace function public.join_league(p_name text, p_pin text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare n text := _clean_name(p_name); v uuid; g boolean; h text;
begin
  perform _check_pin(p_pin);
  select id, guest, pin_hash into v, g, h from players where lower(name) = lower(n);
  if v is not null then
    if g and h is null then
      update players set pin_hash = crypt(p_pin, gen_salt('bf')), guest = false where id = v;
      return v;
    end if;
    raise exception '이미 있는 이름이에요. 본인이라면 ‘로그인’을 눌러 주세요.';
  end if;
  insert into players(name, pin_hash) values (n, crypt(p_pin, gen_salt('bf'))) returning id into v;
  return v;
end $$;

create or replace function public.login(p_name text, p_pin text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v uuid;
begin
  select id into v from players
   where lower(name) = lower(btrim(coalesce(p_name,'')))
     and pin_hash is not null and pin_hash = crypt(coalesce(p_pin,''), pin_hash);
  if v is null then raise exception '이름 또는 PIN이 맞지 않아요.'; end if;
  return v;
end $$;

create or replace function public.rename_me(p_player uuid, p_pin text, p_name text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare n text := _clean_name(p_name);
begin
  perform _auth(p_player, p_pin);
  if exists (select 1 from players where lower(name) = lower(n) and id <> p_player) then
    raise exception '이미 있는 이름이에요.';
  end if;
  update players set name = n where id = p_player;
end $$;

-- 경기 결과 올리기 (본인이 뛴 경기만)
create or replace function public.report_match(
  p_player uuid, p_pin text, p_type text, p_a uuid[], p_b uuid[], p_sets jsonb, p_date date
) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare
  n int := case when p_type = 'singles' then 1 when p_type = 'doubles' then 2 else 0 end;
  allp uuid[] := coalesce(p_a,'{}') || coalesce(p_b,'{}');
  s jsonb; x int; y int; sa int := 0; sb int := 0; clean jsonb := '[]'::jsonb; v uuid;
begin
  perform _auth(p_player, p_pin);
  if n = 0 then raise exception '경기 종류가 올바르지 않아요.'; end if;
  if coalesce(cardinality(p_a),0) <> n or coalesce(cardinality(p_b),0) <> n then
    raise exception '선수 수가 경기 종류와 맞지 않아요.';
  end if;
  if (select count(distinct u) from unnest(allp) u) <> cardinality(allp) then
    raise exception '같은 선수를 두 번 고를 수 없어요.';
  end if;
  if (select count(*) from players where id = any(allp)) <> cardinality(allp) then
    raise exception '등록되지 않은 선수가 있어요.';
  end if;
  if not (p_player = any(allp)) then
    raise exception '내가 뛴 경기만 올릴 수 있어요.';
  end if;
  if p_date is null or p_date > current_date + 1 or p_date < current_date - 365 then
    raise exception '경기 날짜를 확인해 주세요.';
  end if;
  if jsonb_typeof(p_sets) <> 'array' or jsonb_array_length(p_sets) not between 1 and 5 then
    raise exception '세트 스코어를 1~5세트로 입력해 주세요.';
  end if;
  for s in select value from jsonb_array_elements(p_sets) loop
    if jsonb_typeof(s) <> 'array' or jsonb_array_length(s) <> 2
       or jsonb_typeof(s->0) <> 'number' or jsonb_typeof(s->1) <> 'number' then
      raise exception '세트 스코어 형식이 올바르지 않아요.';
    end if;
    x := (s->>0)::numeric::int; y := (s->>1)::numeric::int;
    if x < 0 or y < 0 or x > 99 or y > 99 or x = y then
      raise exception '세트 스코어를 확인해 주세요. (동점 세트는 안 돼요)';
    end if;
    if x > y then sa := sa + 1; else sb := sb + 1; end if;
    clean := clean || jsonb_build_array(jsonb_build_array(x, y));
  end loop;
  if sa = sb then raise exception '세트 수가 동률이에요. 승패가 갈리도록 입력해 주세요.'; end if;

  insert into matches(type, a, b, sets, winner, played_on, reported_by)
  values (p_type, p_a, p_b, clean, case when sa > sb then 'A' else 'B' end, p_date, p_player)
  returning id into v;
  return v;
end $$;

create or replace function public.cancel_match(p_player uuid, p_pin text, p_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _auth(p_player, p_pin);
  delete from matches where id = p_id and reported_by = p_player and status = 'pending';
  if not found then raise exception '취소할 수 없는 경기예요. (이미 확정됐거나 내가 올린 경기가 아니에요)'; end if;
end $$;

-- ---------- 운영자 함수 ----------
create or replace function public.admin_login(p_pw text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin perform _admin(p_pw); return true; end $$;

create or replace function public.admin_confirm(p_pw text, p_ids uuid[]) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare c int;
begin
  perform _admin(p_pw);
  update matches set status = 'confirmed', confirmed_at = now()
   where id = any(p_ids) and status = 'pending';
  get diagnostics c = row_count;
  return c;
end $$;

create or replace function public.admin_unconfirm(p_pw text, p_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _admin(p_pw);
  update matches set status = 'pending', confirmed_at = null where id = p_id;
end $$;

create or replace function public.admin_delete_match(p_pw text, p_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _admin(p_pw);
  delete from matches where id = p_id;
end $$;

create or replace function public.admin_settings(p_pw text, p_mode text, p_min int) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _admin(p_pw);
  if p_mode not in ('winrate','elo') then raise exception '순위 기준이 올바르지 않아요.'; end if;
  update settings set ranking_mode = p_mode, min_games = greatest(0, least(50, coalesce(p_min,0)))
   where id = 1;
end $$;

create or replace function public.admin_add_guest(p_pw text, p_name text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare n text := _clean_name(p_name); v uuid;
begin
  perform _admin(p_pw);
  if exists (select 1 from players where lower(name) = lower(n)) then
    raise exception '이미 있는 이름이에요.';
  end if;
  insert into players(name, guest) values (n, true) returning id into v;
  return v;
end $$;

create or replace function public.admin_rename(p_pw text, p_id uuid, p_name text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare n text := _clean_name(p_name);
begin
  perform _admin(p_pw);
  if exists (select 1 from players where lower(name) = lower(n) and id <> p_id) then
    raise exception '이미 있는 이름이에요.';
  end if;
  update players set name = n where id = p_id;
end $$;

create or replace function public.admin_reset_pin(p_pw text, p_id uuid, p_pin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _admin(p_pw);
  perform _check_pin(p_pin);
  update players set pin_hash = crypt(p_pin, gen_salt('bf')), guest = false where id = p_id;
end $$;

create or replace function public.admin_change_password(p_pw text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _admin(p_pw);
  if char_length(coalesce(p_new,'')) < 6 then raise exception '새 비밀번호는 6자 이상으로 정해 주세요.'; end if;
  update settings set admin_hash = crypt(p_new, gen_salt('bf')) where id = 1;
end $$;

grant execute on function
  public.join_league(text,text), public.login(text,text), public.rename_me(uuid,text,text),
  public.report_match(uuid,text,text,uuid[],uuid[],jsonb,date), public.cancel_match(uuid,text,uuid),
  public.admin_login(text), public.admin_confirm(text,uuid[]), public.admin_unconfirm(text,uuid),
  public.admin_delete_match(text,uuid), public.admin_settings(text,text,int),
  public.admin_add_guest(text,text), public.admin_rename(text,uuid,text),
  public.admin_reset_pin(text,uuid,text), public.admin_change_password(text,text)
to anon, authenticated;

-- ---------- 운영자 비밀번호 (꼭 바꾸세요!) ----------
insert into public.settings (id, admin_hash)
values (1, extensions.crypt('여기에_운영자_비밀번호', extensions.gen_salt('bf')))
on conflict (id) do nothing;
