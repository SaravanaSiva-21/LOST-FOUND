
-- Revoke default PUBLIC execute rights on the new SECURITY DEFINER helpers.
REVOKE ALL ON FUNCTION public.guard_contact_share_admin_only() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_notify_admin_handover_complete() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.send_handover_reminders() FROM PUBLIC, anon, authenticated;
