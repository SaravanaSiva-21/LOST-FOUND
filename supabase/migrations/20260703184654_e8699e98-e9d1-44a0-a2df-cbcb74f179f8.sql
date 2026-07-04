CREATE OR REPLACE FUNCTION public.handle_new_user()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  wl_role public.app_role;
  meta JSONB;
  email_lower TEXT;
  is_student_domain BOOLEAN;
  is_admin_domain BOOLEAN;
BEGIN
  email_lower := lower(NEW.email);
  meta := COALESCE(NEW.raw_user_meta_data, '{}'::jsonb);

  is_admin_domain := email_lower LIKE '%@admin.tce.edu';
  is_student_domain := (email_lower LIKE '%@tce.edu' OR email_lower LIKE '%@student.tce.edu') AND NOT is_admin_domain;

  -- Domain check
  IF NOT (is_student_domain OR is_admin_domain) THEN
    RAISE EXCEPTION 'Registration blocked: only @tce.edu, @student.tce.edu, or @admin.tce.edu email addresses are permitted.';
  END IF;

  -- Whitelist check
  SELECT role INTO wl_role FROM public.whitelist_emails WHERE lower(email) = email_lower;
  IF wl_role IS NULL THEN
    RAISE EXCEPTION 'Registration blocked: your email is not in the approved whitelist. Contact the administrator.';
  END IF;

  -- Domain must match role
  IF wl_role = 'admin' AND NOT is_admin_domain THEN
    RAISE EXCEPTION 'Admin accounts must use an @admin.tce.edu email.';
  END IF;
  IF wl_role <> 'admin' AND is_admin_domain THEN
    RAISE EXCEPTION 'Student accounts must use an @tce.edu or @student.tce.edu email.';
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
$function$;