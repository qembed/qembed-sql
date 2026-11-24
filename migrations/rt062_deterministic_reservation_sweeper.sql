-- RT-062: make worker reservation expiry deterministic and bounded.
-- Upgrade the previous one-argument worker function without weakening grants.
BEGIN;

DROP FUNCTION IF EXISTS public.sweep_expired_reservations(integer);

CREATE FUNCTION public.sweep_expired_reservations(
  p_limit INT,
  p_now TIMESTAMPTZ DEFAULT clock_timestamp()
) RETURNS INT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $rt062$
DECLARE
  r RECORD;
  n INT := 0;
BEGIN
  IF p_limit < 1 OR p_limit > 500 THEN
    RAISE EXCEPTION 'reservation sweep batch size must be between 1 and 500'
      USING ERRCODE = '22023';
  END IF;
  IF p_now IS NULL THEN
    RAISE EXCEPTION 'reservation sweep cutoff must not be NULL'
      USING ERRCODE = '22023';
  END IF;

  FOR r IN
    SELECT br.*
      FROM public.budget_reservations AS br
      JOIN public.provider_call_attempts AS pca
        ON pca.tenant_id = br.tenant_id
       AND pca.object_id = br.object_id
       AND pca.invocation_id = br.invocation_id
     WHERE br.status = 'Reserved'
       AND br.expires_at < p_now
       AND pca.state IN ('NotStarted', 'ConfirmedNotAccepted', 'CancelledBeforeSend')
     ORDER BY br.expires_at
     LIMIT p_limit
     FOR UPDATE OF pca SKIP LOCKED
  LOOP
    UPDATE public.budget_reservations
       SET status = 'Expired'
     WHERE id = r.id AND status = 'Reserved';

    UPDATE public.usage_counters
       SET reserved_tokens = greatest(0, reserved_tokens - r.reserved_tokens),
           reserved_cost_micros = greatest(0, reserved_cost_micros - r.reserved_cost_micros)
     WHERE tenant_id = r.tenant_id
       AND object_id = r.object_id
       AND usage_date = r.usage_date
       AND pool = r.pool;

    UPDATE public.caller_usage_counters AS c
       SET reserved_tokens = greatest(0, c.reserved_tokens - r.reserved_tokens)
      FROM public.object_invocations AS i
     WHERE i.tenant_id = r.tenant_id
       AND i.object_id = r.object_id
       AND i.id = r.invocation_id
       AND c.tenant_id = i.tenant_id
       AND c.object_id = i.object_id
       AND c.caller_id = i.caller_id
       AND c.usage_date = r.usage_date;

    n := n + 1;
  END LOOP;

  RETURN n;
END
$rt062$;

ALTER FUNCTION public.sweep_expired_reservations(integer, timestamptz)
  OWNER TO qembed_definer;
REVOKE ALL ON FUNCTION public.sweep_expired_reservations(integer, timestamptz)
  FROM PUBLIC, qembed_runtime, qembed_dispatcher, qembed_admin, qembed_retention;
GRANT EXECUTE ON FUNCTION public.sweep_expired_reservations(integer, timestamptz)
  TO qembed_worker;

COMMIT;
