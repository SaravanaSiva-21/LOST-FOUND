
-- 1. Meeting enum extensions
ALTER TYPE public.meeting_status ADD VALUE IF NOT EXISTS 'rescheduled';

-- 2. Meeting extra columns
ALTER TABLE public.meetings
  ADD COLUMN IF NOT EXISTS purpose TEXT,
  ADD COLUMN IF NOT EXISTS notes TEXT,
  ADD COLUMN IF NOT EXISTS handover_remarks TEXT,
  ADD COLUMN IF NOT EXISTS receive_remarks TEXT,
  ADD COLUMN IF NOT EXISTS handed_over_by UUID,
  ADD COLUMN IF NOT EXISTS received_by UUID,
  ADD COLUMN IF NOT EXISTS admin_verified BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS admin_verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admin_verified_by UUID;

-- 3. Configurable meeting locations
CREATE TABLE IF NOT EXISTS public.meeting_locations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT ON public.meeting_locations TO authenticated;
GRANT ALL ON public.meeting_locations TO service_role;
ALTER TABLE public.meeting_locations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "meeting_loc_read" ON public.meeting_locations FOR SELECT TO authenticated USING (true);
CREATE POLICY "meeting_loc_admin_write" ON public.meeting_locations FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE TRIGGER meeting_locations_updated BEFORE UPDATE ON public.meeting_locations
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

INSERT INTO public.meeting_locations (name, description) VALUES
  ('College Security Office', 'Main security desk near entrance'),
  ('Library — Front Desk', 'Ground floor issue counter'),
  ('Department Office', 'Respective department HOD office'),
  ('Administrative Block', 'Main admin reception')
ON CONFLICT (name) DO NOTHING;

-- 4. Bookmarks
CREATE TABLE IF NOT EXISTS public.bookmarks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  item_id UUID NOT NULL REFERENCES public.items(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, item_id)
);
GRANT SELECT, INSERT, DELETE ON public.bookmarks TO authenticated;
GRANT ALL ON public.bookmarks TO service_role;
ALTER TABLE public.bookmarks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "bookmarks_self_all" ON public.bookmarks FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- 5. Search history + recently viewed
CREATE TABLE IF NOT EXISTS public.search_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  keyword TEXT,
  viewed_item_id UUID REFERENCES public.items(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('search','view')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, DELETE ON public.search_history TO authenticated;
GRANT ALL ON public.search_history TO service_role;
ALTER TABLE public.search_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY "search_history_self" ON public.search_history FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE INDEX IF NOT EXISTS idx_search_history_user_created ON public.search_history(user_id, created_at DESC);

-- 6. Notify all admins helper
CREATE OR REPLACE FUNCTION public.notify_all_admins(
  _type public.notification_type,
  _title TEXT,
  _message TEXT,
  _case_id TEXT DEFAULT NULL,
  _link TEXT DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO public.notifications (user_id, type, title, message, case_id, link)
  SELECT ur.user_id, _type, _title, _message, _case_id, _link
  FROM public.user_roles ur WHERE ur.role = 'admin';
END;
$$;

-- 7. Trigger: admin notification when new item report is created
CREATE OR REPLACE FUNCTION public.trg_notify_admin_new_item()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  PERFORM public.notify_all_admins(
    'report_submitted'::public.notification_type,
    'New ' || NEW.report_type::text || ' report',
    'Case ' || NEW.case_id || ' — ' || NEW.item_name || ' awaiting verification.',
    NEW.case_id
  );
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS items_notify_admin_new ON public.items;
CREATE TRIGGER items_notify_admin_new AFTER INSERT ON public.items
  FOR EACH ROW EXECUTE FUNCTION public.trg_notify_admin_new_item();

-- 8. Trigger: admin notification when new claim is submitted
CREATE OR REPLACE FUNCTION public.trg_notify_admin_new_claim()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  PERFORM public.notify_all_admins(
    'claim_submitted'::public.notification_type,
    'New claim submitted',
    'Claim ' || NEW.case_id || ' awaiting your review.',
    NEW.case_id
  );
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS claims_notify_admin_new ON public.claims;
CREATE TRIGGER claims_notify_admin_new AFTER INSERT ON public.claims
  FOR EACH ROW EXECUTE FUNCTION public.trg_notify_admin_new_claim();

-- 9. Trigger: admin notification when meeting is scheduled / completed / handover / receive
CREATE OR REPLACE FUNCTION public.trg_notify_admin_meeting()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE case_ref TEXT;
BEGIN
  SELECT i.case_id INTO case_ref FROM public.items i WHERE i.id = NEW.item_id;
  IF (OLD.status IS DISTINCT FROM NEW.status) AND NEW.status IN ('scheduled','rescheduled','completed','cancelled') THEN
    PERFORM public.notify_all_admins(
      'meeting_scheduled'::public.notification_type,
      'Meeting ' || NEW.status::text,
      'Handover meeting for case ' || case_ref || ' is now ' || NEW.status::text || '.',
      case_ref
    );
  END IF;
  IF (COALESCE(OLD.handed_over,false) = false AND NEW.handed_over = true) THEN
    PERFORM public.notify_all_admins(
      'item_handed_over'::public.notification_type,
      'Item handed over',
      'Handover confirmed for case ' || case_ref || '.',
      case_ref
    );
  END IF;
  IF (COALESCE(OLD.received,false) = false AND NEW.received = true) THEN
    PERFORM public.notify_all_admins(
      'item_received'::public.notification_type,
      'Item received',
      'Owner confirmed receipt for case ' || case_ref || '.',
      case_ref
    );
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS meetings_notify_admin ON public.meetings;
CREATE TRIGGER meetings_notify_admin AFTER UPDATE ON public.meetings
  FOR EACH ROW EXECUTE FUNCTION public.trg_notify_admin_meeting();

-- 10. Trigger: admin notification when feedback is submitted
CREATE OR REPLACE FUNCTION public.trg_notify_admin_feedback()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE case_ref TEXT;
BEGIN
  SELECT c.case_id INTO case_ref FROM public.claims c WHERE c.id = NEW.claim_id;
  PERFORM public.notify_all_admins(
    'generic'::public.notification_type,
    'New feedback submitted',
    'Rating ' || NEW.rating || '/5 for claim ' || COALESCE(case_ref,'') || '.',
    case_ref
  );
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS feedback_notify_admin ON public.feedback;
CREATE TRIGGER feedback_notify_admin AFTER INSERT ON public.feedback
  FOR EACH ROW EXECUTE FUNCTION public.trg_notify_admin_feedback();

-- 11. Add feedback columns
ALTER TABLE public.feedback
  ADD COLUMN IF NOT EXISTS suggestions TEXT,
  ADD COLUMN IF NOT EXISTS recommend BOOLEAN;
