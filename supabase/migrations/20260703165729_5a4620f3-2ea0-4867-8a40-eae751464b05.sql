
-- ==========================================
-- ENUMS
-- ==========================================
CREATE TYPE public.app_role AS ENUM ('student', 'admin');
CREATE TYPE public.item_status AS ENUM ('pending_verification','approved','rejected','matched','claimed','handed_over','resolved','archived');
CREATE TYPE public.claim_status AS ENUM ('pending','approved','rejected','more_info','withdrawn');
CREATE TYPE public.meeting_status AS ENUM ('waiting','scheduled','completed','cancelled');
CREATE TYPE public.report_type AS ENUM ('lost','found');
CREATE TYPE public.notification_type AS ENUM (
  'registration','password_reset','report_submitted','report_approved','report_rejected',
  'claim_submitted','claim_approved','claim_rejected','more_info_requested','possible_match',
  'meeting_scheduled','contact_reveal_request','contact_revealed','item_handed_over',
  'item_received','case_resolved','generic'
);

-- ==========================================
-- DEPARTMENTS
-- ==========================================
CREATE TABLE public.departments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT ON public.departments TO anon, authenticated;
GRANT ALL ON public.departments TO service_role;
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "departments_read_all" ON public.departments FOR SELECT USING (true);

INSERT INTO public.departments (code,name) VALUES
  ('CSE','Computer Science and Engineering'),
  ('IT','Information Technology'),
  ('ECE','Electronics and Communication Engineering'),
  ('EEE','Electrical and Electronics Engineering'),
  ('MECH','Mechanical Engineering'),
  ('CIVIL','Civil Engineering'),
  ('MCA','Master of Computer Applications'),
  ('MBA','Master of Business Administration'),
  ('SH','Science and Humanities'),
  ('ADMIN','Administrative Office');

-- ==========================================
-- WHITELIST EMAILS
-- ==========================================
CREATE TABLE public.whitelist_emails (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  role public.app_role NOT NULL DEFAULT 'student',
  notes TEXT,
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT ON public.whitelist_emails TO anon, authenticated;
GRANT ALL ON public.whitelist_emails TO service_role;
ALTER TABLE public.whitelist_emails ENABLE ROW LEVEL SECURITY;
CREATE POLICY "whitelist_read_public" ON public.whitelist_emails FOR SELECT USING (true);

-- Seed sample whitelist entries (replace with real ones from Admin UI)
INSERT INTO public.whitelist_emails (email, role, notes) VALUES
  ('student1@tce.edu','student','Sample student'),
  ('student2@tce.edu','student','Sample student'),
  ('faculty1@tce.edu','student','Sample faculty (student role)'),
  ('admin@admin.tce.edu','admin','Bootstrap administrator');

-- ==========================================
-- USER ROLES (separate table per security best practice)
-- ==========================================
CREATE TABLE public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role)
RETURNS BOOLEAN LANGUAGE SQL STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role);
$$;

CREATE POLICY "user_roles_self_read" ON public.user_roles FOR SELECT
  TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'));

-- ==========================================
-- PROFILES
-- ==========================================
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL DEFAULT '',
  register_no TEXT,
  department TEXT,
  email TEXT NOT NULL,
  phone TEXT,
  photo_url TEXT,
  is_suspended BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "profiles_self_read" ON public.profiles FOR SELECT
  TO authenticated USING (id = auth.uid() OR public.has_role(auth.uid(),'admin'));
CREATE POLICY "profiles_self_update" ON public.profiles FOR UPDATE
  TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
CREATE POLICY "profiles_admin_update" ON public.profiles FOR UPDATE
  TO authenticated USING (public.has_role(auth.uid(),'admin'));

-- ==========================================
-- HANDLE NEW USER: enforce whitelist + domain + create profile + role
-- ==========================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  wl_role public.app_role;
  meta JSONB;
  email_lower TEXT;
BEGIN
  email_lower := lower(NEW.email);
  meta := COALESCE(NEW.raw_user_meta_data, '{}'::jsonb);

  -- Domain check
  IF email_lower NOT LIKE '%@tce.edu' AND email_lower NOT LIKE '%@admin.tce.edu' THEN
    RAISE EXCEPTION 'Registration blocked: only @tce.edu or @admin.tce.edu email addresses are permitted.';
  END IF;

  -- Whitelist check
  SELECT role INTO wl_role FROM public.whitelist_emails WHERE lower(email) = email_lower;
  IF wl_role IS NULL THEN
    RAISE EXCEPTION 'Registration blocked: your email is not in the approved whitelist. Contact the administrator.';
  END IF;

  -- Domain must match role
  IF wl_role = 'admin' AND email_lower NOT LIKE '%@admin.tce.edu' THEN
    RAISE EXCEPTION 'Admin accounts must use an @admin.tce.edu email.';
  END IF;

  INSERT INTO public.profiles (id, full_name, register_no, department, email, phone)
  VALUES (
    NEW.id,
    COALESCE(meta->>'full_name',''),
    meta->>'register_no',
    meta->>'department',
    NEW.email,
    meta->>'phone'
  );

  INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, wl_role);

  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==========================================
-- UPDATED_AT helper
-- ==========================================
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public
AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;

CREATE TRIGGER profiles_updated BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ==========================================
-- CASE ID SEQUENCE
-- ==========================================
CREATE SEQUENCE public.case_id_seq START 1000;

CREATE OR REPLACE FUNCTION public.generate_case_id(_type public.report_type)
RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE n BIGINT; prefix TEXT;
BEGIN
  n := nextval('public.case_id_seq');
  prefix := CASE WHEN _type = 'lost' THEN 'LST' ELSE 'FND' END;
  RETURN prefix || '-' || to_char(now(),'YYYY') || '-' || lpad(n::text,5,'0');
END;
$$;

-- ==========================================
-- ITEMS (unified lost & found table)
-- ==========================================
CREATE TABLE public.items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id TEXT UNIQUE NOT NULL,
  report_type public.report_type NOT NULL,
  reporter_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  item_name TEXT NOT NULL,
  category TEXT NOT NULL,
  brand TEXT,
  colour TEXT,
  description TEXT NOT NULL,
  identification_marks TEXT,
  incident_date DATE NOT NULL,
  incident_time TIME,
  location TEXT NOT NULL,
  general_location TEXT NOT NULL,
  reward TEXT,
  contact_number TEXT NOT NULL,
  current_holder TEXT,
  image_urls TEXT[] NOT NULL DEFAULT '{}',
  status public.item_status NOT NULL DEFAULT 'pending_verification',
  admin_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.items TO authenticated;
GRANT SELECT ON public.items TO anon;
GRANT ALL ON public.items TO service_role;
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;

-- Public can only see approved items (privacy fields filtered at query level in code)
CREATE POLICY "items_public_read_approved" ON public.items FOR SELECT
  USING (status IN ('approved','matched','claimed','handed_over','resolved'));
CREATE POLICY "items_owner_read" ON public.items FOR SELECT
  TO authenticated USING (reporter_id = auth.uid());
CREATE POLICY "items_admin_read" ON public.items FOR SELECT
  TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE POLICY "items_owner_insert" ON public.items FOR INSERT
  TO authenticated WITH CHECK (reporter_id = auth.uid());
CREATE POLICY "items_owner_update" ON public.items FOR UPDATE
  TO authenticated USING (reporter_id = auth.uid() AND status = 'pending_verification');
CREATE POLICY "items_admin_update" ON public.items FOR UPDATE
  TO authenticated USING (public.has_role(auth.uid(),'admin'));

CREATE TRIGGER items_updated BEFORE UPDATE ON public.items
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE INDEX items_status_idx ON public.items(status);
CREATE INDEX items_type_idx ON public.items(report_type);
CREATE INDEX items_reporter_idx ON public.items(reporter_id);

-- ==========================================
-- CLAIMS
-- ==========================================
CREATE TABLE public.claims (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id TEXT UNIQUE NOT NULL,
  item_id UUID NOT NULL REFERENCES public.items(id) ON DELETE CASCADE,
  claimant_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  brand TEXT,
  colour TEXT,
  identification_marks TEXT,
  approx_date DATE,
  approx_time TIME,
  additional_desc TEXT,
  proof_urls TEXT[] NOT NULL DEFAULT '{}',
  status public.claim_status NOT NULL DEFAULT 'pending',
  admin_notes TEXT,
  reporter_reveal_ok BOOLEAN NOT NULL DEFAULT false,
  claimant_reveal_ok BOOLEAN NOT NULL DEFAULT false,
  contact_revealed BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.claims TO authenticated;
GRANT ALL ON public.claims TO service_role;
ALTER TABLE public.claims ENABLE ROW LEVEL SECURITY;

CREATE POLICY "claims_participant_read" ON public.claims FOR SELECT
  TO authenticated USING (
    claimant_id = auth.uid()
    OR public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.items i WHERE i.id = claims.item_id AND i.reporter_id = auth.uid())
  );
CREATE POLICY "claims_insert" ON public.claims FOR INSERT
  TO authenticated WITH CHECK (claimant_id = auth.uid());
CREATE POLICY "claims_participant_update" ON public.claims FOR UPDATE
  TO authenticated USING (
    claimant_id = auth.uid()
    OR public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.items i WHERE i.id = claims.item_id AND i.reporter_id = auth.uid())
  );

CREATE TRIGGER claims_updated BEFORE UPDATE ON public.claims
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ==========================================
-- MEETINGS
-- ==========================================
CREATE TABLE public.meetings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id UUID NOT NULL REFERENCES public.claims(id) ON DELETE CASCADE,
  item_id UUID NOT NULL REFERENCES public.items(id) ON DELETE CASCADE,
  meet_date DATE,
  meet_time TIME,
  location TEXT,
  status public.meeting_status NOT NULL DEFAULT 'waiting',
  handed_over BOOLEAN NOT NULL DEFAULT false,
  handed_over_at TIMESTAMPTZ,
  received BOOLEAN NOT NULL DEFAULT false,
  received_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.meetings TO authenticated;
GRANT ALL ON public.meetings TO service_role;
ALTER TABLE public.meetings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "meetings_participant_read" ON public.meetings FOR SELECT
  TO authenticated USING (
    public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.claims c WHERE c.id = meetings.claim_id AND c.claimant_id = auth.uid())
    OR EXISTS (SELECT 1 FROM public.items i WHERE i.id = meetings.item_id AND i.reporter_id = auth.uid())
  );
CREATE POLICY "meetings_participant_write" ON public.meetings FOR ALL
  TO authenticated USING (
    public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.claims c WHERE c.id = meetings.claim_id AND c.claimant_id = auth.uid())
    OR EXISTS (SELECT 1 FROM public.items i WHERE i.id = meetings.item_id AND i.reporter_id = auth.uid())
  ) WITH CHECK (
    public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.claims c WHERE c.id = meetings.claim_id AND c.claimant_id = auth.uid())
    OR EXISTS (SELECT 1 FROM public.items i WHERE i.id = meetings.item_id AND i.reporter_id = auth.uid())
  );

CREATE TRIGGER meetings_updated BEFORE UPDATE ON public.meetings
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ==========================================
-- NOTIFICATIONS
-- ==========================================
CREATE TABLE public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type public.notification_type NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  case_id TEXT,
  link TEXT,
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.notifications TO authenticated;
GRANT ALL ON public.notifications TO service_role;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "notif_self_read" ON public.notifications FOR SELECT
  TO authenticated USING (user_id = auth.uid());
CREATE POLICY "notif_self_update" ON public.notifications FOR UPDATE
  TO authenticated USING (user_id = auth.uid());
CREATE POLICY "notif_admin_insert" ON public.notifications FOR INSERT
  TO authenticated WITH CHECK (public.has_role(auth.uid(),'admin') OR user_id = auth.uid());

-- ==========================================
-- FEEDBACK
-- ==========================================
CREATE TABLE public.feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id UUID NOT NULL REFERENCES public.claims(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  rating INT NOT NULL,
  comment TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (claim_id, user_id)
);
GRANT SELECT, INSERT ON public.feedback TO authenticated;
GRANT ALL ON public.feedback TO service_role;
ALTER TABLE public.feedback ENABLE ROW LEVEL SECURITY;

CREATE POLICY "feedback_read_participant" ON public.feedback FOR SELECT
  TO authenticated USING (
    user_id = auth.uid()
    OR public.has_role(auth.uid(),'admin')
    OR EXISTS (SELECT 1 FROM public.claims c WHERE c.id = feedback.claim_id AND (c.claimant_id = auth.uid()))
  );
CREATE POLICY "feedback_self_insert" ON public.feedback FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());

-- ==========================================
-- AUDIT LOGS (append only, never deletable)
-- ==========================================
CREATE TABLE public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity TEXT,
  entity_id TEXT,
  metadata JSONB,
  ip_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON public.audit_logs TO authenticated;
GRANT ALL ON public.audit_logs TO service_role;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "audit_admin_read" ON public.audit_logs FOR SELECT
  TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE POLICY "audit_self_insert" ON public.audit_logs FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);

-- ==========================================
-- Whitelist admin write (must come after has_role exists)
-- ==========================================
CREATE POLICY "whitelist_admin_write" ON public.whitelist_emails FOR ALL
  TO authenticated USING (public.has_role(auth.uid(),'admin')) WITH CHECK (public.has_role(auth.uid(),'admin'));
