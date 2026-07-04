
-- ============================================================
-- 1. Extend claims with handover-confirmation fields
-- ============================================================
ALTER TABLE public.claims
  ADD COLUMN IF NOT EXISTS contact_shared_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS contact_shared_by UUID,
  ADD COLUMN IF NOT EXISTS finder_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS finder_confirmed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS finder_confirm_remarks TEXT,
  ADD COLUMN IF NOT EXISTS owner_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS owner_confirmed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS owner_confirm_remarks TEXT,
  ADD COLUMN IF NOT EXISTS reminder_sent BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS reminder_sent_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- ============================================================
-- 2. Migrate data from meetings into claims (in-flight cases)
-- ============================================================
UPDATE public.claims c
SET
  contact_shared_at    = COALESCE(c.contact_shared_at,
                          CASE WHEN c.contact_revealed THEN m.created_at ELSE NULL END),
  finder_confirmed     = COALESCE(m.handed_over, FALSE),
  finder_confirmed_at  = m.handed_over_at,
  finder_confirm_remarks = m.handover_remarks,
  owner_confirmed      = COALESCE(m.received, FALSE),
  owner_confirmed_at   = m.received_at,
  owner_confirm_remarks = m.receive_remarks,
  resolved_at          = CASE WHEN c.status = 'resolved' THEN m.admin_verified_at ELSE NULL END
FROM public.meetings m
WHERE m.claim_id = c.id;

-- ============================================================
-- 3. Drop meeting tables, trigger, function, and enum
-- ============================================================
DROP TRIGGER IF EXISTS meetings_notify_admin ON public.meetings;
DROP FUNCTION IF EXISTS public.trg_notify_admin_meeting() CASCADE;
DROP TABLE IF EXISTS public.meetings CASCADE;
DROP TABLE IF EXISTS public.meeting_locations CASCADE;
DROP TYPE IF EXISTS public.meeting_status CASCADE;

-- ============================================================
-- 4. Add new notification type for handover reminders
-- ============================================================
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_enum
    WHERE enumlabel = 'handover_reminder'
      AND enumtypid = 'public.notification_type'::regtype
  ) THEN
    ALTER TYPE public.notification_type ADD VALUE 'handover_reminder';
  END IF;
END$$;

-- ============================================================
-- 5. Guard: only admins can toggle contact_shared fields
-- ============================================================
CREATE OR REPLACE FUNCTION public.guard_contact_share_admin_only()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF (NEW.contact_shared_at IS DISTINCT FROM OLD.contact_shared_at
      OR NEW.contact_shared_by IS DISTINCT FROM OLD.contact_shared_by
      OR NEW.contact_revealed IS DISTINCT FROM OLD.contact_revealed
      OR NEW.reporter_reveal_ok IS DISTINCT FROM OLD.reporter_reveal_ok
      OR NEW.claimant_reveal_ok IS DISTINCT FROM OLD.claimant_reveal_ok)
     AND NOT public.has_role(auth.uid(), 'admin'::app_role) THEN
    RAISE EXCEPTION 'Only administrators can share contact details.';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS claims_guard_contact_share ON public.claims;
CREATE TRIGGER claims_guard_contact_share
BEFORE UPDATE ON public.claims
FOR EACH ROW EXECUTE FUNCTION public.guard_contact_share_admin_only();

-- ============================================================
-- 6. Notify admins when both parties have confirmed handover
-- ============================================================
CREATE OR REPLACE FUNCTION public.trg_notify_admin_handover_complete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  case_ref TEXT;
BEGIN
  IF NEW.finder_confirmed AND NEW.owner_confirmed
     AND NOT (OLD.finder_confirmed AND OLD.owner_confirmed) THEN
    SELECT i.case_id INTO case_ref FROM public.items i WHERE i.id = NEW.item_id;
    PERFORM public.notify_all_admins(
      'item_received'::public.notification_type,
      'Handover confirmed by both parties',
      'Case ' || COALESCE(case_ref, NEW.case_id) || ' is ready for final resolution.',
      COALESCE(case_ref, NEW.case_id)
    );
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS claims_handover_complete ON public.claims;
CREATE TRIGGER claims_handover_complete
AFTER UPDATE ON public.claims
FOR EACH ROW EXECUTE FUNCTION public.trg_notify_admin_handover_complete();

-- ============================================================
-- 7. Hourly cron: 24-hour reminder for un-confirmed handovers
-- ============================================================
CREATE EXTENSION IF NOT EXISTS pg_cron;

CREATE OR REPLACE FUNCTION public.send_handover_reminders()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN
    SELECT c.id, c.case_id, c.claimant_id, i.reporter_id, i.case_id AS item_case_id
    FROM public.claims c
    JOIN public.items i ON i.id = c.item_id
    WHERE c.status = 'approved'
      AND c.contact_shared_at IS NOT NULL
      AND c.contact_shared_at < now() - interval '24 hours'
      AND NOT (c.finder_confirmed AND c.owner_confirmed)
      AND c.reminder_sent = FALSE
  LOOP
    INSERT INTO public.notifications (user_id, type, title, message, case_id)
    VALUES
      (rec.reporter_id, 'handover_reminder', 'Handover reminder',
       'Our records show that case ' || rec.item_case_id ||
       ' has not yet been completed. Please confirm whether the item has been handed over. If the exchange has already occurred, kindly update the status in the portal.',
       rec.item_case_id),
      (rec.claimant_id, 'handover_reminder', 'Handover reminder',
       'Our records show that case ' || rec.item_case_id ||
       ' has not yet been completed. Please confirm whether the item has been received. If the exchange has already occurred, kindly update the status in the portal.',
       rec.item_case_id);

    UPDATE public.claims
    SET reminder_sent = TRUE, reminder_sent_at = now()
    WHERE id = rec.id;
  END LOOP;
END;
$$;

-- Unschedule any pre-existing job with the same name, then schedule hourly.
DO $$
DECLARE jid BIGINT;
BEGIN
  SELECT jobid INTO jid FROM cron.job WHERE jobname = 'handover-24h-reminder';
  IF jid IS NOT NULL THEN
    PERFORM cron.unschedule(jid);
  END IF;
  PERFORM cron.schedule('handover-24h-reminder', '0 * * * *',
    $CRON$ SELECT public.send_handover_reminders(); $CRON$);
END$$;
