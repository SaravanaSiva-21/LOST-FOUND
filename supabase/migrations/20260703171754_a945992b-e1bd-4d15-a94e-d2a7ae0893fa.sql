
-- RLS policies for new storage buckets: lost-items, found-items, claim-documents
-- Convention: first folder segment is the owner's user id

-- LOST ITEMS
CREATE POLICY "lost_items_owner_all" ON storage.objects FOR ALL TO authenticated
  USING (bucket_id = 'lost-items' AND (storage.foldername(name))[1] = auth.uid()::text)
  WITH CHECK (bucket_id = 'lost-items' AND (storage.foldername(name))[1] = auth.uid()::text);

CREATE POLICY "lost_items_admin_select" ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'lost-items' AND public.has_role(auth.uid(),'admin'));

-- FOUND ITEMS
CREATE POLICY "found_items_owner_all" ON storage.objects FOR ALL TO authenticated
  USING (bucket_id = 'found-items' AND (storage.foldername(name))[1] = auth.uid()::text)
  WITH CHECK (bucket_id = 'found-items' AND (storage.foldername(name))[1] = auth.uid()::text);

CREATE POLICY "found_items_admin_select" ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'found-items' AND public.has_role(auth.uid(),'admin'));

-- CLAIM DOCUMENTS
CREATE POLICY "claim_docs_owner_all" ON storage.objects FOR ALL TO authenticated
  USING (bucket_id = 'claim-documents' AND (storage.foldername(name))[1] = auth.uid()::text)
  WITH CHECK (bucket_id = 'claim-documents' AND (storage.foldername(name))[1] = auth.uid()::text);

CREATE POLICY "claim_docs_admin_select" ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'claim-documents' AND public.has_role(auth.uid(),'admin'));
