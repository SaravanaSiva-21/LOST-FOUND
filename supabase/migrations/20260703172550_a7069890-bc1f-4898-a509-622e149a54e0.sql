
-- 1. Extend claim status enum
ALTER TYPE public.claim_status ADD VALUE IF NOT EXISTS 'under_review';
ALTER TYPE public.claim_status ADD VALUE IF NOT EXISTS 'contact_shared';
ALTER TYPE public.claim_status ADD VALUE IF NOT EXISTS 'meeting_scheduled';
ALTER TYPE public.claim_status ADD VALUE IF NOT EXISTS 'completed';
ALTER TYPE public.claim_status ADD VALUE IF NOT EXISTS 'resolved';

-- 2. Approximate lost location on claim
ALTER TABLE public.claims
  ADD COLUMN IF NOT EXISTS approx_location TEXT;

-- 3. Smart-match trigger: on new verified item, notify admins if there is a
--    potential opposite-type match (basic scoring: same category + name/colour/brand overlap).
CREATE OR REPLACE FUNCTION public.notify_admins_of_potential_match()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  opp public.report_type;
  admin_id UUID;
  match_row RECORD;
  match_score INT;
  q TEXT;
BEGIN
  opp := CASE WHEN NEW.report_type = 'lost' THEN 'found'::public.report_type
               ELSE 'lost'::public.report_type END;

  q := lower(coalesce(NEW.item_name,'') || ' ' || coalesce(NEW.colour,'') || ' ' || coalesce(NEW.brand,''));

  -- Find best potential match
  FOR match_row IN
    SELECT id, case_id, item_name, colour, brand, general_location, category
    FROM public.items
    WHERE report_type = opp
      AND category = NEW.category
      AND status IN ('approved','matched','pending_verification')
      AND id <> NEW.id
    ORDER BY created_at DESC
    LIMIT 5
  LOOP
    match_score := 0;
    IF lower(match_row.item_name) = lower(NEW.item_name) THEN match_score := match_score + 3; END IF;
    IF match_row.colour IS NOT NULL AND NEW.colour IS NOT NULL
       AND lower(match_row.colour) = lower(NEW.colour) THEN match_score := match_score + 2; END IF;
    IF match_row.brand IS NOT NULL AND NEW.brand IS NOT NULL
       AND lower(match_row.brand) = lower(NEW.brand) THEN match_score := match_score + 2; END IF;
    IF match_row.general_location = NEW.general_location THEN match_score := match_score + 1; END IF;

    IF match_score >= 3 THEN
      -- Notify every admin
      FOR admin_id IN
        SELECT user_id FROM public.user_roles WHERE role = 'admin'
      LOOP
        INSERT INTO public.notifications (user_id, type, title, message, case_id)
        VALUES (
          admin_id,
          'possible_match',
          'Potential match detected',
          'New ' || NEW.report_type::text || ' report ' || NEW.case_id ||
          ' may match ' || match_row.case_id || ' (score ' || match_score || ').',
          NEW.case_id
        );
      END LOOP;
      -- Only alert once per new report
      EXIT;
    END IF;
  END LOOP;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_notify_potential_match ON public.items;
CREATE TRIGGER trg_notify_potential_match
AFTER INSERT ON public.items
FOR EACH ROW EXECUTE FUNCTION public.notify_admins_of_potential_match();
