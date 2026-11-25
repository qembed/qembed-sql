-- RT-063: protect Knowledge revisions while invocations are active.
BEGIN;

CREATE TABLE public.knowledge_revision_pins (
  tenant_id UUID NOT NULL,
  object_id UUID NOT NULL,
  invocation_id UUID NOT NULL,
  revision BIGINT NOT NULL CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_id, invocation_id),
  FOREIGN KEY (tenant_id, object_id, invocation_id)
    REFERENCES public.object_invocations (tenant_id, object_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, object_id, revision)
    REFERENCES public.knowledge_revision_log (tenant_id, object_id, revision)
);
CREATE INDEX idx_knowledge_revision_pins_revision
  ON public.knowledge_revision_pins (tenant_id, object_id, revision);

ALTER TABLE public.knowledge_revision_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.knowledge_revision_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.knowledge_revision_pins TO qembed_runtime
  USING (tenant_id = (SELECT qembed_crypto.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT qembed_crypto.current_tenant_id()));
CREATE POLICY admin_knowledge_revision_pins ON public.knowledge_revision_pins
  FOR SELECT TO qembed_admin USING (true);
CREATE POLICY definer_access ON public.knowledge_revision_pins
  TO qembed_definer USING (true) WITH CHECK (true);
CREATE POLICY definer_access ON public.knowledge_revisions
  TO qembed_definer USING (true) WITH CHECK (true);
CREATE POLICY definer_access ON public.knowledge_documents
  TO qembed_definer USING (true) WITH CHECK (true);

GRANT SELECT, INSERT ON public.knowledge_revision_pins TO qembed_runtime;
GRANT SELECT ON public.knowledge_revision_pins TO qembed_admin;
GRANT SELECT, DELETE ON public.knowledge_revision_pins TO qembed_definer;
GRANT SELECT, UPDATE ON public.knowledge_revisions TO qembed_definer;
GRANT SELECT, UPDATE, DELETE ON public.knowledge_documents TO qembed_definer;

CREATE FUNCTION public.knowledge_revision_pin_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $rt063_pin_guard$
DECLARE
  v_current_revision BIGINT;
BEGIN
  SELECT current_revision INTO v_current_revision
    FROM public.knowledge_revisions
   WHERE tenant_id = NEW.tenant_id AND object_id = NEW.object_id
   FOR SHARE;

  IF NOT FOUND OR NEW.revision <> v_current_revision THEN
    RAISE EXCEPTION 'knowledge revision pin must target the current committed revision'
      USING ERRCODE = '23514';
  END IF;

  PERFORM 1
    FROM public.object_invocations
   WHERE tenant_id = NEW.tenant_id
     AND object_id = NEW.object_id
     AND id = NEW.invocation_id
     AND knowledge_revision = NEW.revision
     AND status NOT IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled')
   FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'knowledge revision pin must belong to an active matching invocation'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$rt063_pin_guard$;

CREATE TRIGGER trg_knowledge_revision_pin_guard
  BEFORE INSERT ON public.knowledge_revision_pins
  FOR EACH ROW EXECUTE FUNCTION public.knowledge_revision_pin_guard();

CREATE FUNCTION public.release_terminal_invocation_knowledge_pin() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $rt063_release_pin$
BEGIN
  IF NEW.status IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled') THEN
    DELETE FROM public.knowledge_revision_pins
     WHERE tenant_id = NEW.tenant_id
       AND object_id = NEW.object_id
       AND invocation_id = NEW.id;
  END IF;
  RETURN NEW;
END
$rt063_release_pin$;

CREATE TRIGGER trg_release_terminal_invocation_knowledge_pin
  AFTER UPDATE OF status ON public.object_invocations
  FOR EACH ROW
  WHEN (NEW.status IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled'))
  EXECUTE FUNCTION public.release_terminal_invocation_knowledge_pin();

CREATE FUNCTION public.collect_retired_knowledge_documents(
  p_tenant_id UUID,
  p_object_id UUID,
  p_batch_size INTEGER
)
RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $rt063_knowledge_gc$
DECLARE
  v_current_revision BIGINT;
  v_deleted INTEGER;
  v_context_tenant UUID := qembed_crypto.current_tenant_id();
BEGIN
  IF v_context_tenant IS NULL OR v_context_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'Knowledge GC tenant differs from verified transaction context'
      USING ERRCODE = '42501';
  END IF;
  IF p_batch_size IS NULL OR p_batch_size < 1 OR p_batch_size > 500 THEN
    RAISE EXCEPTION 'Knowledge GC batch size must be between 1 and 500'
      USING ERRCODE = '22023';
  END IF;

  SELECT current_revision INTO v_current_revision
    FROM public.knowledge_revisions
   WHERE tenant_id = p_tenant_id AND object_id = p_object_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  WITH eligible AS MATERIALIZED (
    SELECT document.id
      FROM public.knowledge_documents AS document
     WHERE document.tenant_id = p_tenant_id
       AND document.object_id = p_object_id
       AND document.status = 'retired'
       AND document.valid_to_revision <= v_current_revision
       AND NOT EXISTS (
         SELECT 1
           FROM public.knowledge_revision_pins AS pin
          WHERE pin.tenant_id = document.tenant_id
            AND pin.object_id = document.object_id
            AND pin.revision < document.valid_to_revision
       )
     ORDER BY document.valid_to_revision, document.id
     LIMIT p_batch_size
     FOR UPDATE OF document SKIP LOCKED
  ),
  deleted AS (
    DELETE FROM public.knowledge_documents AS document
     USING eligible
     WHERE document.tenant_id = p_tenant_id
       AND document.object_id = p_object_id
       AND document.id = eligible.id
    RETURNING 1
  )
  SELECT count(*)::integer INTO v_deleted FROM deleted;

  RETURN v_deleted;
END
$rt063_knowledge_gc$;

ALTER FUNCTION public.release_terminal_invocation_knowledge_pin() OWNER TO qembed_definer;
ALTER FUNCTION public.collect_retired_knowledge_documents(UUID, UUID, INTEGER) OWNER TO qembed_definer;
REVOKE ALL ON FUNCTION public.release_terminal_invocation_knowledge_pin() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.collect_retired_knowledge_documents(UUID, UUID, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.collect_retired_knowledge_documents(UUID, UUID, INTEGER) TO qembed_runtime;

DO $rt063_rls_audit$
DECLARE
  v_definition TEXT;
BEGIN
  SELECT pg_get_functiondef('public.assert_tenant_rls_classification()'::regprocedure)
    INTO v_definition;
  v_definition := regexp_replace(
    v_definition,
    $rt063_pattern$('knowledge_revision_log',[[:space:]]*)('knowledge_documents')$rt063_pattern$,
    $rt063_replacement$\1'knowledge_revision_pins',\2$rt063_replacement$,
    'g'
  );
  IF position('knowledge_revision_pins' IN v_definition) = 0 THEN
    RAISE EXCEPTION 'RT-063 could not extend the tenant RLS audit allowlists';
  END IF;
  EXECUTE v_definition;
END
$rt063_rls_audit$;

SELECT public.assert_tenant_rls_classification();

COMMIT;
