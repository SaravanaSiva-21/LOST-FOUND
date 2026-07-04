CREATE POLICY profiles_read_shared_contact ON public.profiles
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.claims c
    JOIN public.items i ON i.id = c.item_id
    WHERE c.contact_shared_at IS NOT NULL
      AND (
        (c.claimant_id = auth.uid() AND profiles.id = i.reporter_id)
        OR
        (i.reporter_id = auth.uid() AND profiles.id = c.claimant_id)
      )
  )
);