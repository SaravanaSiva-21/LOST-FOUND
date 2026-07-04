
ALTER TABLE public.items DROP CONSTRAINT IF EXISTS items_reporter_id_fkey;
ALTER TABLE public.items ADD CONSTRAINT items_reporter_id_fkey FOREIGN KEY (reporter_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

ALTER TABLE public.claims DROP CONSTRAINT IF EXISTS claims_claimant_id_fkey;
ALTER TABLE public.claims ADD CONSTRAINT claims_claimant_id_fkey FOREIGN KEY (claimant_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

NOTIFY pgrst, 'reload schema';
