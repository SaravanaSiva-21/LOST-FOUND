
ALTER FUNCTION public.generate_case_id(public.report_type) SET search_path = public;

REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) TO authenticated;

REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.generate_case_id(public.report_type) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.generate_case_id(public.report_type) TO authenticated;
