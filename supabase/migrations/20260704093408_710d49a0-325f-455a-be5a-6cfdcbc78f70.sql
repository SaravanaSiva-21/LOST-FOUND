
-- 1) items: restrict sensitive columns from anon (public browsing)
REVOKE SELECT ON public.items FROM anon;
GRANT SELECT (
  id, case_id, report_type, reporter_id, item_name, category, brand, colour,
  description, incident_date, incident_time, general_location, image_urls,
  status, current_holder, reward, admin_notes, created_at, updated_at
) ON public.items TO anon;
-- Deliberately omit: contact_number, location, identification_marks

-- 2) whitelist_emails: drop public read policy
DROP POLICY IF EXISTS whitelist_read_public ON public.whitelist_emails;

-- 3) claims: restrict which fields non-admins can modify (BEFORE UPDATE trigger)
CREATE OR REPLACE FUNCTION public.guard_claim_field_updates()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  is_admin boolean;
  is_claimant boolean;
  is_reporter boolean;
BEGIN
  is_admin := public.has_role(auth.uid(), 'admin'::app_role);
  IF is_admin THEN
    RETURN NEW;
  END IF;

  is_claimant := (auth.uid() = OLD.claimant_id);
  is_reporter := EXISTS (
    SELECT 1 FROM public.items i
    WHERE i.id = OLD.item_id AND i.reporter_id = auth.uid()
  );

  -- Admin-only fields
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'Only administrators can change claim status.';
  END IF;
  IF NEW.admin_notes IS DISTINCT FROM OLD.admin_notes THEN
    RAISE EXCEPTION 'Only administrators can change admin notes.';
  END IF;
  IF NEW.contact_revealed IS DISTINCT FROM OLD.contact_revealed THEN
    RAISE EXCEPTION 'Only administrators can change contact reveal state.';
  END IF;
  IF NEW.resolved_at IS DISTINCT FROM OLD.resolved_at THEN
    RAISE EXCEPTION 'Only administrators can mark a claim resolved.';
  END IF;
  IF NEW.reminder_sent IS DISTINCT FROM OLD.reminder_sent
     OR NEW.reminder_sent_at IS DISTINCT FROM OLD.reminder_sent_at THEN
    RAISE EXCEPTION 'Only administrators can change reminder state.';
  END IF;

  -- Consent fields: each party may only toggle their own
  IF NEW.claimant_reveal_ok IS DISTINCT FROM OLD.claimant_reveal_ok AND NOT is_claimant THEN
    RAISE EXCEPTION 'Only the claimant can change their consent flag.';
  END IF;
  IF NEW.reporter_reveal_ok IS DISTINCT FROM OLD.reporter_reveal_ok AND NOT is_reporter THEN
    RAISE EXCEPTION 'Only the item reporter can change their consent flag.';
  END IF;

  -- Handover confirmations
  IF (NEW.finder_confirmed IS DISTINCT FROM OLD.finder_confirmed
      OR NEW.finder_confirmed_at IS DISTINCT FROM OLD.finder_confirmed_at
      OR NEW.finder_confirm_remarks IS DISTINCT FROM OLD.finder_confirm_remarks)
     AND NOT is_reporter THEN
    RAISE EXCEPTION 'Only the finder can update handover confirmation.';
  END IF;
  IF (NEW.owner_confirmed IS DISTINCT FROM OLD.owner_confirmed
      OR NEW.owner_confirmed_at IS DISTINCT FROM OLD.owner_confirmed_at
      OR NEW.owner_confirm_remarks IS DISTINCT FROM OLD.owner_confirm_remarks)
     AND NOT is_claimant THEN
    RAISE EXCEPTION 'Only the owner can update receipt confirmation.';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_claim_fields ON public.claims;
CREATE TRIGGER guard_claim_fields
  BEFORE UPDATE ON public.claims
  FOR EACH ROW EXECUTE FUNCTION public.guard_claim_field_updates();

-- Also attach the existing guard for contact-share admin-only if not attached
DROP TRIGGER IF EXISTS guard_contact_share ON public.claims;
CREATE TRIGGER guard_contact_share
  BEFORE UPDATE ON public.claims
  FOR EACH ROW EXECUTE FUNCTION public.guard_contact_share_admin_only();

-- 4) notifications: server-side counterparty notify + tighten INSERT policy
CREATE OR REPLACE FUNCTION public.notify_claim_confirmations()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  case_ref text;
  reporter uuid;
BEGIN
  SELECT i.case_id, i.reporter_id INTO case_ref, reporter
  FROM public.items i WHERE i.id = NEW.item_id;

  IF NEW.finder_confirmed AND NOT OLD.finder_confirmed THEN
    INSERT INTO public.notifications (user_id, type, title, message, case_id)
    VALUES (NEW.claimant_id, 'item_handed_over'::notification_type,
            'Finder confirmed handover',
            'The finder confirmed handover for case ' || COALESCE(case_ref, NEW.case_id) || '. Please confirm you have received the item.',
            COALESCE(case_ref, NEW.case_id));
  END IF;

  IF NEW.owner_confirmed AND NOT OLD.owner_confirmed AND reporter IS NOT NULL THEN
    INSERT INTO public.notifications (user_id, type, title, message, case_id)
    VALUES (reporter, 'item_received'::notification_type,
            'Owner confirmed receipt',
            'The owner confirmed receipt for case ' || COALESCE(case_ref, NEW.case_id) || '.',
            COALESCE(case_ref, NEW.case_id));
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS notify_claim_confirmations ON public.claims;
CREATE TRIGGER notify_claim_confirmations
  AFTER UPDATE ON public.claims
  FOR EACH ROW EXECUTE FUNCTION public.notify_claim_confirmations();

-- Tighten notifications INSERT policy: only admins can insert (self-inserts not needed; triggers handle system messages)
DROP POLICY IF EXISTS notif_admin_insert ON public.notifications;
CREATE POLICY notif_admin_insert ON public.notifications
  FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'::app_role));

-- 5) storage: allow item reporters to view claim proofs for claims against their found item
DROP POLICY IF EXISTS claim_proofs_reporter_select ON storage.objects;
CREATE POLICY claim_proofs_reporter_select ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'claim-proofs'
    AND EXISTS (
      SELECT 1
      FROM public.claims c
      JOIN public.items i ON i.id = c.item_id
      WHERE i.reporter_id = auth.uid()
        AND (storage.foldername(name))[1] = c.claimant_id::text
    )
  );

-- 6) Revoke EXECUTE on privileged SECURITY DEFINER functions from end users
-- (has_role is kept executable because RLS policies invoke it)
REVOKE ALL ON FUNCTION public.notify_all_admins(notification_type, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.send_handover_reminders() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.notify_admins_of_potential_match() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.guard_contact_share_admin_only() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.guard_claim_field_updates() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.notify_claim_confirmations() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_notify_admin_new_item() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_notify_admin_new_claim() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_notify_admin_feedback() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_notify_admin_handover_complete() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
