-- =====================================================================
-- Qemam Aljibal — Payroll & Project Costing System
-- Supabase Schema (PostgreSQL) — v2
-- =====================================================================
-- التحديثات في هذه النسخة عن الملف الأول (supabase_schema.sql):
-- 1) Trigger تلقائي: أي مستخدم جديد يتسجل عبر Supabase Auth (تسجيل
--    الدخول الحقيقي المُضاف حديثًا للتطبيق) يحصل تلقائيًا على صف في
--    profiles بدور افتراضي "Accountant" (أقل صلاحية، آمن) — بدل ما
--    كان لازم تضيفه يدويًا بالـ SQL في كل مرة.
-- 2) صلاحيات إضافية لدور Owner: يقدر يشوف كل الملفات الشخصية (profiles)
--    ويقدر يغيّر دور أي مستخدم (لتفعيل صفحة "المستخدمون والصلاحيات"
--    مستقبلاً بشكل حقيقي، بدل ما تفضل عرض مبدئي فقط).
-- باقي الملف (الشهور، الاعتماد، الموظفين، سجل التدقيق، الإقامات،
-- العهدة، السيارات، الأصول، المركبات، الإعدادات) بنفس محتوى النسخة
-- الأولى، بدون أي تغيير في المنطق أو حذف أي شيء.
--
-- ملاحظة: التطبيق حاليًا يستخدم فقط Anon Public Key + Supabase Auth
-- (تسجيل الدخول بالبريد/كلمة المرور). لا يوجد ولن يوجد أي استخدام
-- لـ Service Role Key داخل التطبيق نفسه.
--
-- SAFE TO RE-RUN: uses IF NOT EXISTS / CREATE OR REPLACE / DROP POLICY
-- IF EXISTS everywhere, so running this again (even after v1) is safe.
-- Run in Supabase → SQL Editor → New query → Run.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Extensions
-- ---------------------------------------------------------------------
create extension if not exists "pgcrypto";        -- for gen_random_uuid()

-- ---------------------------------------------------------------------
-- 1. Roles (enum) — matches the 4 roles already used in the app UI
-- ---------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type user_role as enum ('Owner', 'Accountant', 'HR', 'Project Manager');
  end if;
end$$;

-- ---------------------------------------------------------------------
-- 2. profiles — links a Supabase Auth user to a role
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  full_name   text not null default '',
  role        user_role not null default 'Accountant',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- كل مستخدم يشوف/يعدّل ملفه الشخصي هو بس
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
  on public.profiles for select
  using (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
  on public.profiles for update
  using (auth.uid() = id);

-- Helper: fetch the role of the currently-logged-in user (used inside policies)
create or replace function public.current_role_name()
returns user_role
language sql
stable
security definer
as $$
  select role from public.profiles where id = auth.uid();
$$;

-- [جديد] Owner يقدر يشوف ويدير كل الملفات الشخصية (لإدارة الأدوار فعليًا)
drop policy if exists "profiles_select_owner_all" on public.profiles;
create policy "profiles_select_owner_all"
  on public.profiles for select
  using (public.current_role_name() = 'Owner');

drop policy if exists "profiles_update_owner_all" on public.profiles;
create policy "profiles_update_owner_all"
  on public.profiles for update
  using (public.current_role_name() = 'Owner');

-- [جديد] إنشاء صف profiles تلقائيًا عند تسجيل مستخدم جديد في Supabase Auth
-- (يحل مشكلة أنك كنت مضطر تضيف الصف يدويًا بعد كل تسجيل حساب جديد)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    'Accountant'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ---------------------------------------------------------------------
-- 3. months — one row per payroll month (matches `data[]` + staffSheet)
-- ---------------------------------------------------------------------
create table if not exists public.months (
  id              uuid primary key default gen_random_uuid(),
  key             text not null,              -- e.g. "يونيو" / "يوليو" / "مرتبات الكادر الفني شهر يوليو"
  days            int  not null,
  projects        jsonb not null default '[]',
  show_notes      boolean not null default false,
  editable_names  boolean not null default false,  -- true only for the staff sheet
  is_staff_sheet  boolean not null default false,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

alter table public.months enable row level security;

-- كل الأدوار (Owner/Accountant/HR/Project Manager) تقدر تقرأ وتُدخل بيانات شهرية عادية
drop policy if exists "months_select_all" on public.months;
create policy "months_select_all" on public.months for select using (true);

drop policy if exists "months_insert_all" on public.months;
create policy "months_insert_all" on public.months for insert with check (true);

drop policy if exists "months_update_all" on public.months;
create policy "months_update_all" on public.months for update using (true);

-- ---------------------------------------------------------------------
-- 4. month_approvals — الاعتماد/إعادة الفتح: Owner فقط
--    (جدول منفصل عمدًا حتى يسهل تقييد الصلاحية عليه بدون التأثير على
--    باقي بيانات الشهر، لأن RLS في Postgres يعمل على مستوى الصف كاملاً)
-- ---------------------------------------------------------------------
create table if not exists public.month_approvals (
  id            uuid primary key default gen_random_uuid(),
  month_id      uuid not null references public.months (id) on delete cascade,
  approved      boolean not null default false,
  approved_by   text,
  approved_role user_role,
  approved_at   timestamptz,
  reason        text,
  created_at    timestamptz not null default now()
);

alter table public.month_approvals enable row level security;

drop policy if exists "approvals_select_all" on public.month_approvals;
create policy "approvals_select_all"
  on public.month_approvals for select
  using (true);

-- فقط Owner يقدر يعمل approve/reopen (insert/update على هذا الجدول)
drop policy if exists "approvals_owner_only_insert" on public.month_approvals;
create policy "approvals_owner_only_insert"
  on public.month_approvals for insert
  with check (public.current_role_name() = 'Owner');

drop policy if exists "approvals_owner_only_update" on public.month_approvals;
create policy "approvals_owner_only_update"
  on public.month_approvals for update
  using (public.current_role_name() = 'Owner');

-- ---------------------------------------------------------------------
-- 5. employees — صفوف الموظفين داخل كل شهر (attendance cells كـ jsonb)
-- ---------------------------------------------------------------------
create table if not exists public.employees (
  id            uuid primary key default gen_random_uuid(),
  month_id      uuid not null references public.months (id) on delete cascade,
  name          text not null default '',
  salary        numeric not null default 0,
  ot_hours      numeric not null default 0,
  ot_rate       numeric not null default 0,
  advances      numeric not null default 0,
  deductions    numeric not null default 0,
  notes         text not null default '',
  cells         jsonb not null default '[]',   -- array of day values, same shape as the app
  archived      boolean not null default false,
  archived_at   timestamptz,
  is_new        boolean not null default false,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table public.employees enable row level security;

drop policy if exists "employees_select_all" on public.employees;
create policy "employees_select_all" on public.employees for select using (true);

drop policy if exists "employees_insert_all" on public.employees;
create policy "employees_insert_all" on public.employees for insert with check (true);

drop policy if exists "employees_update_all" on public.employees;
create policy "employees_update_all" on public.employees for update using (true);

drop policy if exists "employees_delete_all" on public.employees;
create policy "employees_delete_all" on public.employees for delete using (true);

-- ---------------------------------------------------------------------
-- 6. audit_log — سجل تدقيق: قراءة للجميع، إضافة فقط (لا تعديل ولا حذف)
-- ---------------------------------------------------------------------
create table if not exists public.audit_log (
  id          uuid primary key default gen_random_uuid(),
  ts          timestamptz not null default now(),
  action      text not null,       -- edit / create / delete / archive / unarchive / approve / reopen
  month_key   text,
  employee    text,
  field       text,
  old_value   text,
  new_value   text,
  actor       text,
  role        user_role,
  reason      text
);

alter table public.audit_log enable row level security;

drop policy if exists "audit_select_all" on public.audit_log;
create policy "audit_select_all" on public.audit_log for select using (true);

drop policy if exists "audit_insert_all" on public.audit_log;
create policy "audit_insert_all" on public.audit_log for insert with check (true);

-- عمدًا: لا توجد policy لـ update أو delete → السجل غير قابل للتعديل أو الحذف نهائيًا.

-- ---------------------------------------------------------------------
-- 7. residencies / custody / cars / assets / vehicles
--    (نفس الحقول المستخدمة في الواجهة تمامًا)
-- ---------------------------------------------------------------------
create table if not exists public.residencies (
  id          uuid primary key default gen_random_uuid(),
  name        text not null default '',
  nationality text not null default '',
  job         text not null default '',
  res_no      text not null default '',
  pass_no     text not null default '',
  issue_date  date,
  expiry_date date,
  notes       text not null default '',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.custody (
  id          uuid primary key default gen_random_uuid(),
  employee    text not null default '',
  item        text not null default '',
  value       numeric not null default 0,
  date_given  date,
  notes       text not null default '',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.cars (
  id           uuid primary key default gen_random_uuid(),
  plate        text not null default '',
  emirate      text not null default '',
  car_type     text not null default '',
  model        text not null default '',
  color        text not null default '',
  driver       text not null default '',
  project      text not null default '',
  lic_start    date,
  lic_expiry   date,
  insurer      text not null default '',
  ins_expiry   date,
  notes        text not null default '',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.assets (
  id             uuid primary key default gen_random_uuid(),
  name           text not null default '',
  type           text not null default '',
  serial         text not null default '',
  assignee       text not null default '',
  project        text not null default '',
  purchase_date  date,
  value          numeric not null default 0,
  status         text not null default 'نشط',
  notes          text not null default '',
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create table if not exists public.vehicles (
  id            uuid primary key default gen_random_uuid(),
  name          text not null default '',
  plate         text not null default '',
  assignee      text not null default '',
  project       text not null default '',
  lic_expiry    date,
  ins_expiry    date,
  maint_date    date,
  status        text not null default 'نشط',
  notes         text not null default '',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table public.residencies enable row level security;
alter table public.custody     enable row level security;
alter table public.cars        enable row level security;
alter table public.assets      enable row level security;
alter table public.vehicles    enable row level security;

-- سياسة موحّدة (قراءة/إضافة/تعديل/حذف لكل الأدوار المسجّلة) لهذه الجداول الخمسة
do $$
declare
  t text;
begin
  foreach t in array array['residencies','custody','cars','assets','vehicles']
  loop
    execute format('drop policy if exists "%s_select_all" on public.%I', t, t);
    execute format('create policy "%s_select_all" on public.%I for select using (true)', t, t);

    execute format('drop policy if exists "%s_insert_all" on public.%I', t, t);
    execute format('create policy "%s_insert_all" on public.%I for insert with check (true)', t, t);

    execute format('drop policy if exists "%s_update_all" on public.%I', t, t);
    execute format('create policy "%s_update_all" on public.%I for update using (true)', t, t);

    execute format('drop policy if exists "%s_delete_all" on public.%I', t, t);
    execute format('create policy "%s_delete_all" on public.%I for delete using (true)', t, t);
  end loop;
end$$;

-- ---------------------------------------------------------------------
-- 8. app_settings — صف واحد فقط (إعدادات الشركة/الرواتب/العملة...)
-- ---------------------------------------------------------------------
create table if not exists public.app_settings (
  id                    int primary key default 1,
  company_name          text not null default '',
  company_address       text not null default '',
  currency              text not null default 'د.إ',
  payroll_month         text not null default '',
  working_days          int  not null default 26,
  weekend_day           text not null default 'الجمعة',
  projects_root_path    text not null default '',
  salary_basis          text not null default 'month_days',
  updated_at            timestamptz not null default now(),
  constraint app_settings_singleton check (id = 1)
);

insert into public.app_settings (id) values (1)
on conflict (id) do nothing;

alter table public.app_settings enable row level security;

drop policy if exists "settings_select_all" on public.app_settings;
create policy "settings_select_all" on public.app_settings for select using (true);

drop policy if exists "settings_update_all" on public.app_settings;
create policy "settings_update_all" on public.app_settings for update using (true);

-- =====================================================================
-- بعد تشغيل هذا الملف:
-- 1) اعمل أول حساب "Owner" حقيقي بنفسك:
--      - Supabase Dashboard → Authentication → Users → Add user
--        (بريد إلكتروني + كلمة مرور).
--      - الـ Trigger هيضيفه تلقائيًا في profiles بدور "Accountant".
--      - رقّي دوره لـ Owner بالأمر التالي (غيّر البريد فقط):
--
--        update public.profiles
--        set role = 'Owner'
--        where id = (select id from auth.users where email = 'your@email.com');
--
-- 2) في التطبيق: System Settings → الاتصال السحابي → حط Project URL
--    والـ Anon Public Key (مش Service Role) → اضغط "حفظ واتصال".
--    شاشة تسجيل الدخول هتظهر تلقائيًا بعد نجاح الاتصال.
-- 3) هذا الملف لسه بيجهّز الجداول والصلاحيات فقط على مستوى القاعدة؛
--    مزامنة القراءة/الكتابة الفعلية بين التطبيق وSupabase (بدل
--    localStorage) تحتاج تطويرًا إضافيًا منفصلًا لو حبيت تكمل فيه.
-- =====================================================================
