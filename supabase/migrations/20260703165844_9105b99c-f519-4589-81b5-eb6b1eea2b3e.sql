
-- Item images: owner (folder = user_id) and admins
CREATE POLICY "item_images_owner_admin_select" ON storage.objects FOR SELECT
  TO authenticated USING (
    bucket_id = 'item-images' AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR public.has_role(auth.uid(),'admin')
    )
  );
CREATE POLICY "item_images_owner_insert" ON storage.objects FOR INSERT
  TO authenticated WITH CHECK (
    bucket_id = 'item-images' AND (storage.foldername(name))[1] = auth.uid()::text
  );
CREATE POLICY "item_images_owner_delete" ON storage.objects FOR DELETE
  TO authenticated USING (
    bucket_id = 'item-images' AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR public.has_role(auth.uid(),'admin')
    )
  );

-- Claim proofs
CREATE POLICY "claim_proofs_owner_admin_select" ON storage.objects FOR SELECT
  TO authenticated USING (
    bucket_id = 'claim-proofs' AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR public.has_role(auth.uid(),'admin')
    )
  );
CREATE POLICY "claim_proofs_owner_insert" ON storage.objects FOR INSERT
  TO authenticated WITH CHECK (
    bucket_id = 'claim-proofs' AND (storage.foldername(name))[1] = auth.uid()::text
  );

-- Avatars
CREATE POLICY "avatars_self_select" ON storage.objects FOR SELECT
  TO authenticated USING (
    bucket_id = 'avatars' AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR public.has_role(auth.uid(),'admin')
    )
  );
CREATE POLICY "avatars_self_all" ON storage.objects FOR ALL
  TO authenticated USING (
    bucket_id = 'avatars' AND (storage.foldername(name))[1] = auth.uid()::text
  ) WITH CHECK (
    bucket_id = 'avatars' AND (storage.foldername(name))[1] = auth.uid()::text
  );
