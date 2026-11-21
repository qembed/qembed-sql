-- =============================================================================
-- Qembed Object Runtime — M0 v2.3.3 CLEAN SCHEMA CANDIDATE r4 (fresh install only)
-- PostgreSQL 15+, pgvector >= 0.8. Apply as qembed_migrator (table owner).
-- NOT an upgrade script for v2.2 databases (see errata, section "Upgrade").
-- Status: FINALIZATION CANDIDATE. Architecture frozen; DB release gate = T-01..T-64 on supported matrix.
-- r3: fixes R3-01..R3-06 (see Addendum §10, acceptance 'R3 regression'); marked 'r3' at each change.
-- r4: implements T-27 Caller-level episodic memory RLS (see Addendum §11 and ADR RT-049).
-- Rust-compat remediation: AUDIT-001..009 applied (physical contracts, owner auth, objects, snapshots, events/outbox, tenant RLS, composite tenant FKs, Invocation lifecycle/fencing).
-- AUDIT-010 SECURITY DEFINER hardening; r4 adds caller-scoped memory isolation.
-- =============================================================================
\set ON_ERROR_STOP on
BEGIN;

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- pgvector gate (r1): fail fast below 0.8.0 (hnsw.iterative_scan, addendum §5).
-- Local smoke only: SET qembed.allow_old_pgvector = 'on'. Never in CI/prod.
DO $$
DECLARE v TEXT; parts INT[];
BEGIN
  SELECT extversion INTO v FROM pg_extension WHERE extname = 'vector';
  IF v IS NULL THEN RAISE EXCEPTION 'pgvector is not installed'; END IF;
  parts := string_to_array(regexp_replace(v, '[^0-9.]', '', 'g'), '.')::int[];
  IF (parts[1], coalesce(parts[2],0)) < (0, 8) THEN
    IF coalesce(current_setting('qembed.allow_old_pgvector', true), 'off') = 'on' THEN
      RAISE WARNING 'pgvector % < 0.8.0: smoke-test only, NOT a compliant environment', v;
    ELSE
      RAISE EXCEPTION 'pgvector % is below the required minimum 0.8.0', v;
    END IF;
  END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 0. Roles (NOLOGIN here; credentials are provisioned out of band)
-- -----------------------------------------------------------------------------
DO $$
DECLARE r TEXT;
BEGIN
  FOREACH r IN ARRAY ARRAY['qembed_runtime','qembed_dispatcher','qembed_admin',
                           'qembed_retention','qembed_definer','qembed_event_allocator']
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS', r);
    END IF;
  END LOOP;
END $;
ALTER ROLE qembed_event_allocator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO qembed_event_allocator;
-- qembed_definer: NOLOGIN owner of SECURITY DEFINER functions (A2). Subject to
-- RLS; sees data only through explicit policies defined in section 20.

-- SECURITY DEFINER functions use this schema in their fixed search_path.
-- Application and PUBLIC roles must never be able to shadow objects there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM qembed_runtime, qembed_dispatcher, qembed_admin, qembed_retention, qembed_definer, qembed_event_allocator;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM qembed_event_allocator;

-- -----------------------------------------------------------------------------
-- 1. Guards
-- -----------------------------------------------------------------------------
CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only (% forbidden)', TG_TABLE_NAME, TG_OP;
END $$;

-- -----------------------------------------------------------------------------
-- 2. Global registries
-- -----------------------------------------------------------------------------
CREATE TABLE embedding_models (
  id TEXT PRIMARY KEY, provider TEXT NOT NULL, model_name TEXT NOT NULL,
  dimension INTEGER NOT NULL CHECK (dimension > 0),
  distance_metric TEXT NOT NULL CHECK (distance_metric IN ('cosine','l2','ip')),
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tool_definitions (
  id UUID PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tool_versions (
  id UUID PRIMARY KEY, tool_id UUID NOT NULL REFERENCES tool_definitions(id),
  version TEXT NOT NULL,
  risk_level TEXT NOT NULL CHECK (risk_level IN ('R0','R1','R2','R3','R4')),
  input_schema JSONB NOT NULL, output_schema JSONB NOT NULL,
  timeout_ms INTEGER NOT NULL CHECK (timeout_ms > 0),
  idempotent BOOLEAN NOT NULL,
  -- M0/M1: write-capable tools without upstream idempotency are forbidden
  CHECK (risk_level IN ('R0','R1') OR idempotent),
  UNIQUE (tool_id, version), UNIQUE (tool_id, id)
);

-- -----------------------------------------------------------------------------
-- 3. Tenants, principals
-- -----------------------------------------------------------------------------
CREATE TABLE tenants (
  id UUID PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE principals (   -- restricted-global: tenant_id NULL only for PlatformAdmin
  id UUID PRIMARY KEY, tenant_id UUID REFERENCES tenants(id),
  kind TEXT NOT NULL CHECK (kind IN ('TenantOwner','TenantAdmin','Service','PlatformAdmin')),
  key_hash BYTEA NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ,
  CHECK ((kind = 'PlatformAdmin') = (tenant_id IS NULL)),
  UNIQUE (tenant_id, id)
);

-- -----------------------------------------------------------------------------
-- 3a. Owner authentication (AUDIT-002): physical model of the current Rust auth path
--     (Rust migration 20261118000000_owner_authentication.sql, qembed-store/src/auth.rs).
--     Principal = identity of the tenant owner; credential = SHA-256 digest of a high-entropy
--     API token. Raw tokens are never stored. The Rust adapter performs a PRE-AUTH lookup (no
--     tenant Scope exists yet), so these tables carry no tenant RLS policy: access is restricted
--     by column-level grants only (see section 17). principals/callers above are the future model
--     and are NOT used by the Rust auth path.
-- -----------------------------------------------------------------------------
CREATE TABLE owner_principals (
  tenant_id UUID NOT NULL,
  caller_id UUID NOT NULL,
  principal_kind TEXT NOT NULL CHECK (principal_kind = 'tenant_owner'),
  disabled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, caller_id)
);

CREATE TABLE owner_credentials (
  tenant_id UUID NOT NULL,
  caller_id UUID NOT NULL,
  token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, caller_id, token_hash),
  FOREIGN KEY (tenant_id, caller_id)
    REFERENCES owner_principals (tenant_id, caller_id)
    ON DELETE RESTRICT
);

-- Same name/predicate as the Rust index, but UNIQUE: at most one ACTIVE credential per
-- (tenant, digest), so the Rust lookup can never match two principals. Revoked rows are outside
-- the predicate, so a digest of a revoked credential does not block a later one.
CREATE UNIQUE INDEX owner_credentials_active_lookup
  ON owner_credentials (tenant_id, token_hash)
  WHERE revoked_at IS NULL;

-- Digest/identity are immutable and revocation is final (issue a new credential instead).
CREATE FUNCTION owner_credentials_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF (NEW.tenant_id, NEW.caller_id, NEW.token_hash, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.caller_id, OLD.token_hash, OLD.created_at) THEN
    RAISE EXCEPTION 'owner credential identity and digest are immutable';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'owner credential revocation is final';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_owner_credentials_guard BEFORE UPDATE ON owner_credentials
  FOR EACH ROW EXECUTE FUNCTION owner_credentials_guard();

-- -----------------------------------------------------------------------------
-- 4. Objects and versions
-- -----------------------------------------------------------------------------
-- AUDIT-001: physical name and keys follow Rust migration 20261118000001_objects.sql.
-- No FK to tenants(id): the Rust path has no tenants table and never creates tenant rows.
CREATE TABLE objects (
  tenant_id UUID NOT NULL,
  object_id UUID NOT NULL,
  state TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','validating','active','suspended','archived')),  -- AUDIT-003: Rust contract
  published_version_id UUID,
  binding_counter BIGINT NOT NULL DEFAULT 0 CHECK (binding_counter >= 0), -- A9 (future extension, defaulted)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_id),
  UNIQUE (object_id),
  CHECK (state NOT IN ('active','suspended') OR published_version_id IS NOT NULL)
);

-- AUDIT-001: columns/keys follow Rust migration 20261118000001_objects.sql.
-- r3 payload columns (config, chat_model_ref, embedding_model_id, published_at) are nullable
-- extensions: the current Rust INSERT does not supply them. They become mandatory only in a
-- separate change set when the matching Rust adapter exists (AUDIT-010).
CREATE TABLE object_versions (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, object_version_id UUID NOT NULL,
  version_number BIGINT NOT NULL CHECK (version_number > 0),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','superseded')),
  config JSONB, chat_model_ref TEXT,
  embedding_model_id TEXT REFERENCES embedding_models(id),
  published_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status <> 'draft' OR published_at IS NULL),
  PRIMARY KEY (tenant_id, object_id, object_version_id),
  UNIQUE (object_version_id),
  UNIQUE (tenant_id, object_id, version_number),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
    ON DELETE RESTRICT
);
CREATE UNIQUE INDEX uq_ov_one_published ON object_versions (tenant_id, object_id) WHERE status = 'published';

ALTER TABLE objects
  ADD CONSTRAINT objects_published_version_fk
  FOREIGN KEY (tenant_id, object_id, published_version_id)
  REFERENCES object_versions(tenant_id, object_id, object_version_id)
  ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- AUDIT-007: ObjectVersion follows the Rust domain state machine:
-- Draft -> Published -> Superseded. Superseded is terminal; identity and
-- version_number never change. Published content is immutable.
CREATE OR REPLACE FUNCTION object_versions_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $object_version_guard$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'draft' THEN
      RAISE EXCEPTION 'new object versions must start as Draft' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' THEN
      RAISE EXCEPTION 'only draft object versions may be deleted' USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF (NEW.object_version_id, NEW.tenant_id, NEW.object_id, NEW.version_number, NEW.created_at)
     IS DISTINCT FROM
     (OLD.object_version_id, OLD.tenant_id, OLD.object_id, OLD.version_number, OLD.created_at) THEN
    RAISE EXCEPTION 'object version identity is immutable' USING ERRCODE = '55000';
  END IF;

  IF OLD.status = 'draft' THEN
    IF NEW.status NOT IN ('draft', 'published') THEN
      RAISE EXCEPTION 'invalid object version transition: % -> %', OLD.status, NEW.status
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'published' AND NEW.status = 'superseded' THEN
    IF (NEW.config, NEW.chat_model_ref, NEW.embedding_model_id, NEW.published_at)
       IS DISTINCT FROM
       (OLD.config, OLD.chat_model_ref, OLD.embedding_model_id, OLD.published_at) THEN
      RAISE EXCEPTION 'published object version content is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'invalid or terminal object version transition: % -> %', OLD.status, NEW.status
    USING ERRCODE = '23514';
END
$object_version_guard$;

CREATE TRIGGER trg_object_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON object_versions
  FOR EACH ROW EXECUTE FUNCTION object_versions_guard();

-- Object lifecycle transitions mirror qembed-domain::ObjectState::can_transition_to.
-- Pointer-only updates are allowed for atomic publication/replacement; the
-- existing pointer guard verifies that the target is a Published version.
CREATE FUNCTION object_state_transition_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $object_state_guard$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'draft' OR NEW.published_version_id IS NOT NULL THEN
      RAISE EXCEPTION 'new objects must start as Draft without a published version'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF (NEW.tenant_id, NEW.object_id, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.object_id, OLD.created_at) THEN
    RAISE EXCEPTION 'object identity is immutable' USING ERRCODE = '55000';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'draft' AND NEW.state = 'validating')
    OR (OLD.state = 'validating' AND NEW.state = 'draft')
    OR (OLD.state = 'validating' AND NEW.state = 'active')
    OR (OLD.state = 'active' AND NEW.state = 'suspended')
    OR (OLD.state = 'suspended' AND NEW.state = 'active')
    OR (OLD.state = 'active' AND NEW.state = 'archived')
    OR (OLD.state = 'suspended' AND NEW.state = 'archived')
  ) THEN
    RAISE EXCEPTION 'invalid object state transition: % -> %', OLD.state, NEW.state
      USING ERRCODE = '23514';
  END IF;

  IF NEW.published_version_id IS DISTINCT FROM OLD.published_version_id
     AND NOT (
       (OLD.state = 'validating' AND NEW.state = 'active'
        AND OLD.published_version_id IS NULL AND NEW.published_version_id IS NOT NULL)
       OR (OLD.state IN ('active', 'suspended')
           AND NEW.state = OLD.state
           AND NEW.published_version_id IS NOT NULL)
     ) THEN
    RAISE EXCEPTION 'published version pointer may change only during activation or active replacement'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END
$object_state_guard$;
CREATE TRIGGER trg_object_state_transition_guard
  BEFORE INSERT OR UPDATE ON objects FOR EACH ROW
  EXECUTE FUNCTION object_state_transition_guard();

-- -----------------------------------------------------------------------------
-- 5. Callers
-- -----------------------------------------------------------------------------
CREATE TABLE callers (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
  token_hash BYTEA NOT NULL,
  caller_kind TEXT NOT NULL CHECK (caller_kind IN ('Anonymous','Authenticated','Service')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ,
  UNIQUE (tenant_id, token_hash), UNIQUE (tenant_id, id)
);

-- Principal -> Caller delegation. owner_principals remains the Rust authentication
-- identity; callers remains the invocation identity. A principal may delegate to
-- multiple callers. Each grant is an immutable historical record; revocation is final,
-- and a later re-grant creates a new delegation_id.
CREATE TABLE principal_caller_delegations (
  delegation_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  principal_id UUID NOT NULL,
  caller_id UUID NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  revoked_by_principal_id UUID,
  CHECK ((revoked_at IS NULL) = (revoked_by_principal_id IS NULL)),
  CHECK (revoked_by_principal_id IS NULL OR revoked_by_principal_id = principal_id),
  FOREIGN KEY (tenant_id, principal_id)
    REFERENCES owner_principals(tenant_id, caller_id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, caller_id)
    REFERENCES callers(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, revoked_by_principal_id)
    REFERENCES owner_principals(tenant_id, caller_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX principal_caller_delegations_active
  ON principal_caller_delegations(tenant_id, principal_id, caller_id)
  WHERE revoked_at IS NULL;

CREATE FUNCTION principal_caller_delegation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $delegation_guard$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.delegation_id, NEW.tenant_id, NEW.principal_id, NEW.caller_id, NEW.granted_at)
       IS DISTINCT FROM
       (OLD.delegation_id, OLD.tenant_id, OLD.principal_id, OLD.caller_id, OLD.granted_at) THEN
      RAISE EXCEPTION 'delegation identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND
       (NEW.revoked_at, NEW.revoked_by_principal_id)
       IS DISTINCT FROM (OLD.revoked_at, OLD.revoked_by_principal_id) THEN
      RAISE EXCEPTION 'delegation revocation is final' USING ERRCODE = '55000';
    END IF;
  ELSIF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'delegation history is append-only' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$delegation_guard$;
CREATE TRIGGER trg_principal_caller_delegation_guard
  BEFORE UPDATE OR DELETE ON principal_caller_delegations
  FOR EACH ROW EXECUTE FUNCTION principal_caller_delegation_guard();

-- -----------------------------------------------------------------------------
-- 6. Snapshots (A4): canonical_json is the source of truth for the hash
-- -----------------------------------------------------------------------------
-- AUDIT-001: name/keys follow Rust migration 20261118000002_snapshots.sql. AUDIT-004 aligns
-- canonical bytes, SHA-256 digest, JSONB projection, and immutability.
CREATE TABLE snapshots (
  tenant_id UUID NOT NULL, snapshot_id UUID NOT NULL, object_id UUID NOT NULL,
  object_version_id UUID NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  canonical_json BYTEA NOT NULL,
  content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
  json_projection JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, snapshot_id),
  UNIQUE (snapshot_id),
  UNIQUE (tenant_id, object_id, content_hash),
  UNIQUE (tenant_id, object_id, snapshot_id),            -- target of composite FKs from invocations/decisions
  FOREIGN KEY (tenant_id, object_id, object_version_id)
    REFERENCES object_versions(tenant_id, object_id, object_version_id)
    ON DELETE RESTRICT
);

-- Match the projection against the JSON value represented by the exact source bytes.
-- JSONB is query-only; it is never used to reconstruct canonical_json.
CREATE FUNCTION enforce_snapshot_projection() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $snapshot_projection$
BEGIN
  IF NEW.json_projection IS DISTINCT FROM
      convert_from(NEW.canonical_json, 'UTF8')::jsonb THEN
    RAISE EXCEPTION 'snapshot JSONB projection does not match canonical_json'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $snapshot_projection$;
CREATE TRIGGER snapshots_projection_guard
  BEFORE INSERT OR UPDATE ON snapshots
  FOR EACH ROW EXECUTE FUNCTION enforce_snapshot_projection();

CREATE FUNCTION reject_snapshot_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $snapshot_immutable$
BEGIN
  RAISE EXCEPTION 'snapshots are immutable' USING ERRCODE = '55000';
END $snapshot_immutable$;
CREATE TRIGGER snapshots_immutable
  BEFORE UPDATE OR DELETE ON snapshots
  FOR EACH ROW EXECUTE FUNCTION reject_snapshot_mutation();

-- -----------------------------------------------------------------------------
-- 7. Invocations (lease + fencing), idempotency, messages
-- -----------------------------------------------------------------------------
CREATE TABLE object_invocations (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, caller_id UUID NOT NULL,
  snapshot_id UUID NOT NULL, knowledge_revision BIGINT NOT NULL CHECK (knowledge_revision >= 0),
  pool TEXT NOT NULL CHECK (pool IN ('anonymous','authenticated')),
  status TEXT NOT NULL CHECK (status IN
    ('Received','ContextLoading','Processing','ExecutingTool','Verifying',
     'WaitingForInput','WaitingForApproval',
     'Completed','CompletedDegraded','Failed','Cancelled')),
  error_code TEXT, degraded_reason TEXT, trace_id UUID NOT NULL,
  cancel_requested_at TIMESTAMPTZ,
  lease_owner TEXT, lease_until TIMESTAMPTZ, heartbeat_at TIMESTAMPTZ,
  fencing_token BIGINT NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(), finished_at TIMESTAMPTZ,
  version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
  CHECK ((status IN ('Completed','CompletedDegraded','Failed','Cancelled')) = (finished_at IS NOT NULL)),
  CHECK (status <> 'Failed' OR error_code IS NOT NULL),
  CHECK (status <> 'CompletedDegraded' OR degraded_reason IS NOT NULL),
  CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
  CHECK (finished_at IS NULL OR lease_owner IS NULL),
  UNIQUE (tenant_id, object_id, id),
  UNIQUE (tenant_id, object_id, caller_id, id),          -- A6
  UNIQUE (tenant_id, object_id, id, pool),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id),
  FOREIGN KEY (tenant_id, caller_id) REFERENCES callers(tenant_id, id),
  FOREIGN KEY (tenant_id, object_id, snapshot_id) REFERENCES snapshots(tenant_id, object_id, snapshot_id)
);
CREATE INDEX idx_inv_active ON object_invocations (tenant_id, object_id)
  WHERE status NOT IN ('Completed','CompletedDegraded','Failed','Cancelled');
CREATE INDEX idx_inv_lease ON object_invocations (lease_until)
  WHERE status NOT IN ('Completed','CompletedDegraded','Failed','Cancelled');

-- AUDIT-009: Invocation lifecycle and fencing follow qembed-domain::Invocation.
-- State changes and lease reclaim are separate optimistic-version increments.
CREATE FUNCTION invocation_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $invocation_state_guard$
DECLARE
  status_changed BOOLEAN;
  token_changed BOOLEAN;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'Received' OR NEW.version <> 0 OR NEW.fencing_token <> 0
       OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.finished_at IS NOT NULL THEN
      RAISE EXCEPTION 'new invocation must start Received at version/token zero without a lease'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF (NEW.id, NEW.tenant_id, NEW.object_id, NEW.caller_id, NEW.snapshot_id,
      NEW.knowledge_revision, NEW.pool, NEW.trace_id, NEW.started_at)
     IS DISTINCT FROM
     (OLD.id, OLD.tenant_id, OLD.object_id, OLD.caller_id, OLD.snapshot_id,
      OLD.knowledge_revision, OLD.pool, OLD.trace_id, OLD.started_at) THEN
    RAISE EXCEPTION 'invocation identity is immutable' USING ERRCODE = '55000';
  END IF;

  IF OLD.status IN ('Completed','CompletedDegraded','Failed','Cancelled') THEN
    RAISE EXCEPTION 'terminal invocation is immutable' USING ERRCODE = '55000';
  END IF;

  status_changed := NEW.status IS DISTINCT FROM OLD.status;
  token_changed := NEW.fencing_token IS DISTINCT FROM OLD.fencing_token;

  IF status_changed AND NOT (
       (NEW.status IN ('Failed','Cancelled'))
    OR (OLD.status = 'Received' AND NEW.status = 'ContextLoading')
    OR (OLD.status = 'ContextLoading' AND NEW.status = 'Processing')
    OR (OLD.status = 'Processing' AND NEW.status = 'ExecutingTool')
    OR (OLD.status = 'ExecutingTool' AND NEW.status = 'Processing')
    OR (OLD.status = 'Processing' AND NEW.status = 'Verifying')
    OR (OLD.status = 'Verifying' AND NEW.status IN ('Completed','CompletedDegraded'))
  ) THEN
    RAISE EXCEPTION 'invalid invocation state transition: % -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;

  IF NEW.fencing_token < OLD.fencing_token THEN
    RAISE EXCEPTION 'stale invocation fencing token' USING ERRCODE = '40001';
  END IF;

  IF status_changed AND token_changed THEN
    RAISE EXCEPTION 'state transition and lease reclaim must be separate CAS operations'
      USING ERRCODE = '23514';
  END IF;

  IF status_changed OR token_changed THEN
    IF NEW.version::numeric <> OLD.version::numeric + 1 THEN
      RAISE EXCEPTION 'invocation optimistic version must advance exactly once'
        USING ERRCODE = '40001';
    END IF;
  ELSIF NEW.version <> OLD.version THEN
    RAISE EXCEPTION 'invocation version changed without state transition or lease reclaim'
      USING ERRCODE = '40001';
  END IF;

  IF token_changed THEN
    IF NEW.fencing_token <= OLD.fencing_token
       OR OLD.lease_owner IS NULL OR OLD.lease_until IS NULL
       OR OLD.lease_until >= now()
       OR NEW.lease_owner IS NULL OR NEW.lease_until IS NULL THEN
      RAISE EXCEPTION 'fencing token may advance only when reclaiming an expired lease'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.lease_owner IS NOT NULL
        AND OLD.lease_until > now()
        AND NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
        AND NOT (
          status_changed
          AND NEW.status IN ('Completed','CompletedDegraded','Failed','Cancelled')
          AND NEW.lease_owner IS NULL
          AND NEW.lease_until IS NULL
        ) THEN
    -- The current lease holder may release its lease as part of a terminal
    -- transition. This is not a lease steal: the status transition is validated
    -- above and the fencing token must remain unchanged.
    RAISE EXCEPTION 'an active invocation lease cannot be stolen'
      USING ERRCODE = '40001';
  ELSIF OLD.lease_owner IS NOT NULL
        AND OLD.lease_until <= now()
        AND (NEW.lease_owner, NEW.lease_until)
              IS DISTINCT FROM (OLD.lease_owner, OLD.lease_until)
        AND NOT (status_changed AND NEW.status IN ('Completed','CompletedDegraded','Failed','Cancelled')) THEN
    RAISE EXCEPTION 'an expired invocation lease must be reclaimed with a newer fencing token'
      USING ERRCODE = '40001';
  END IF;

  RETURN NEW;
END
$invocation_state_guard$;

CREATE TRIGGER trg_invocation_state_guard
  BEFORE INSERT OR UPDATE ON object_invocations
  FOR EACH ROW EXECUTE FUNCTION invocation_state_guard();


CREATE TABLE invocation_idempotency (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, caller_id UUID NOT NULL,
  idempotency_key TEXT NOT NULL, payload_hash BYTEA NOT NULL, invocation_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, object_id, caller_id, idempotency_key),
  UNIQUE (tenant_id, object_id, invocation_id),
  FOREIGN KEY (tenant_id, object_id, caller_id, invocation_id)
    REFERENCES object_invocations(tenant_id, object_id, caller_id, id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE interaction_messages (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, caller_id UUID NOT NULL,
  invocation_id UUID NOT NULL, role TEXT NOT NULL CHECK (role IN ('user','assistant','tool')),
  content TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (tenant_id, object_id, caller_id, invocation_id)
    REFERENCES object_invocations(tenant_id, object_id, caller_id, id)
);
CREATE INDEX idx_msg_caller ON interaction_messages (tenant_id, caller_id);
CREATE INDEX idx_msg_expiry ON interaction_messages (expires_at);

-- -----------------------------------------------------------------------------
-- 8. Knowledge
-- -----------------------------------------------------------------------------
CREATE TABLE knowledge_revisions (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  current_revision BIGINT NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
  PRIMARY KEY (tenant_id, object_id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);
CREATE TABLE knowledge_revision_log (      -- B1: basis for the reproducibility window
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, revision BIGINT NOT NULL CHECK (revision > 0),
  committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_id, revision),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);

CREATE FUNCTION objects_init_knowledge() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO knowledge_revisions (tenant_id, object_id) VALUES (NEW.tenant_id, NEW.object_id);
  RETURN NEW;
END $$;
CREATE TRIGGER trg_objects_init_knowledge AFTER INSERT ON objects
  FOR EACH ROW EXECUTE FUNCTION objects_init_knowledge();

CREATE TABLE knowledge_documents (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  doc_key TEXT NOT NULL, title TEXT NOT NULL, source_uri TEXT,
  trusted BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL CHECK (status IN ('staged','indexed','live','retired','erased')),
  valid_from_revision BIGINT, valid_to_revision BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (valid_to_revision IS NULL OR (valid_from_revision IS NOT NULL AND valid_to_revision > valid_from_revision)),
  CHECK (status NOT IN ('staged','indexed') OR valid_from_revision IS NULL),
  CHECK (status <> 'live' OR (valid_from_revision IS NOT NULL AND valid_to_revision IS NULL)),
  CHECK (status <> 'retired' OR valid_to_revision IS NOT NULL),
  UNIQUE (tenant_id, object_id, id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);
CREATE UNIQUE INDEX uq_doc_live ON knowledge_documents (tenant_id, object_id, doc_key)
  WHERE valid_from_revision IS NOT NULL AND valid_to_revision IS NULL;

CREATE TABLE knowledge_chunks (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, document_id UUID NOT NULL,
  content TEXT NOT NULL, erased BOOLEAN NOT NULL DEFAULT false,
  position INTEGER NOT NULL, metadata JSONB NOT NULL DEFAULT '{}',
  valid_from_revision BIGINT, valid_to_revision BIGINT,
  content_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED,
  CHECK (valid_to_revision IS NULL OR (valid_from_revision IS NOT NULL AND valid_to_revision > valid_from_revision)),
  CHECK (NOT erased OR content = ''),
  UNIQUE (tenant_id, object_id, id),
  FOREIGN KEY (tenant_id, object_id, document_id)
    REFERENCES knowledge_documents(tenant_id, object_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_chunks_visible ON knowledge_chunks (tenant_id, object_id, valid_from_revision, valid_to_revision);
CREATE INDEX idx_chunks_fts ON knowledge_chunks USING gin (content_tsv);

CREATE FUNCTION knowledge_chunks_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id, NEW.tenant_id, NEW.object_id, NEW.document_id, NEW.position, NEW.metadata)
     IS DISTINCT FROM (OLD.id, OLD.tenant_id, OLD.object_id, OLD.document_id, OLD.position, OLD.metadata)
  THEN RAISE EXCEPTION 'chunk is immutable'; END IF;
  IF NEW.content IS DISTINCT FROM OLD.content AND NOT (NEW.erased AND NOT OLD.erased)
  THEN RAISE EXCEPTION 'chunk content is immutable (only erasure allowed)'; END IF;
  IF (NEW.valid_from_revision, NEW.valid_to_revision) IS DISTINCT FROM (OLD.valid_from_revision, OLD.valid_to_revision)
     AND coalesce(current_setting('qembed.interval_sync', true), '') <> 'on'
  THEN RAISE EXCEPTION 'chunk interval is changed only by revision commit'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_chunks_guard BEFORE UPDATE ON knowledge_chunks
  FOR EACH ROW EXECUTE FUNCTION knowledge_chunks_guard();

CREATE FUNCTION knowledge_documents_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('qembed.interval_sync', 'on', true);
  UPDATE knowledge_chunks
     SET valid_from_revision = NEW.valid_from_revision, valid_to_revision = NEW.valid_to_revision
   WHERE tenant_id = NEW.tenant_id AND object_id = NEW.object_id AND document_id = NEW.id;
  PERFORM set_config('qembed.interval_sync', 'off', true);
  RETURN NEW;
END $$;
CREATE TRIGGER trg_docs_sync AFTER UPDATE OF valid_from_revision, valid_to_revision ON knowledge_documents
  FOR EACH ROW EXECUTE FUNCTION knowledge_documents_sync();

CREATE TABLE knowledge_chunk_embeddings (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, chunk_id UUID NOT NULL,
  model_id TEXT NOT NULL REFERENCES embedding_models(id),
  embedding vector NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, chunk_id, model_id),
  FOREIGN KEY (tenant_id, object_id, chunk_id)
    REFERENCES knowledge_chunks(tenant_id, object_id, id) ON DELETE CASCADE
);

CREATE FUNCTION check_embedding_dim() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d INTEGER;
BEGIN
  SELECT dimension INTO d FROM embedding_models WHERE id = NEW.model_id;
  IF d IS NULL OR vector_dims(NEW.embedding) <> d THEN
    RAISE EXCEPTION 'embedding dimension mismatch for model %', NEW.model_id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_kce_dim BEFORE INSERT OR UPDATE OF embedding, model_id
  ON knowledge_chunk_embeddings FOR EACH ROW EXECUTE FUNCTION check_embedding_dim();
-- HNSW partial expression indexes are created per model by migrator,
-- CREATE INDEX CONCURRENTLY outside this transaction (see runbook; halfvec for dim > 2000).

-- -----------------------------------------------------------------------------
-- 9. Memory
-- -----------------------------------------------------------------------------
CREATE TABLE memories (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, caller_id UUID,
  memory_kind TEXT NOT NULL CHECK (memory_kind IN ('semantic','episodic')),
  claim TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN
    ('Owner','TrustedDocument','User','ThirdParty','Tool','RuntimeInference')),
  verification TEXT NOT NULL CHECK (verification IN ('Unverified','Verified','Observed','Rejected')),
  confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  source_id UUID, invocation_id UUID, supersedes_id UUID,
  verified_by UUID, verified_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((memory_kind = 'episodic') = (caller_id IS NOT NULL)),
  CHECK (memory_kind = 'semantic' OR expires_at IS NOT NULL),
  CHECK (memory_kind = 'semantic' OR verification <> 'Verified'),
  CHECK (verification <> 'Verified' OR (source_kind IN ('Owner','TrustedDocument')
         AND verified_by IS NOT NULL AND verified_at IS NOT NULL)),
  CHECK (verification <> 'Observed' OR source_kind = 'Tool'),
  CHECK (source_kind NOT IN ('User','ThirdParty','RuntimeInference') OR verification IN ('Unverified','Rejected')),
  UNIQUE (tenant_id, object_id, id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id),
  FOREIGN KEY (tenant_id, caller_id) REFERENCES callers(tenant_id, id),
  FOREIGN KEY (tenant_id, verified_by) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, object_id, invocation_id) REFERENCES object_invocations(tenant_id, object_id, id),
  FOREIGN KEY (tenant_id, object_id, supersedes_id) REFERENCES memories(tenant_id, object_id, id)
    ON DELETE SET NULL (supersedes_id)
);
CREATE INDEX idx_mem_caller ON memories (tenant_id, object_id, caller_id);

-- A10: a Verified record is authored by the owner. Owner approval of a User/ThirdParty
-- candidate creates a NEW record (source_kind='Owner', supersedes_id -> candidate).
CREATE FUNCTION memories_verified_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k TEXT;
BEGIN
  IF NEW.verification = 'Verified' THEN
    SELECT kind INTO k FROM principals WHERE tenant_id = NEW.tenant_id AND id = NEW.verified_by;
    IF k IS NULL OR k NOT IN ('TenantOwner','TenantAdmin') THEN
      RAISE EXCEPTION 'Verified requires an owner/admin principal';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_memories_verified BEFORE INSERT OR UPDATE ON memories
  FOR EACH ROW EXECUTE FUNCTION memories_verified_guard();

CREATE TABLE memory_conflicts (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  memory_id UUID NOT NULL, conflicting_memory_id UUID NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open','resolved')), resolution JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (memory_id <> conflicting_memory_id),
  CHECK ((status = 'resolved') = (resolution IS NOT NULL)),
  FOREIGN KEY (tenant_id, object_id, memory_id) REFERENCES memories(tenant_id, object_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, object_id, conflicting_memory_id) REFERENCES memories(tenant_id, object_id, id) ON DELETE CASCADE
);

CREATE TABLE memory_embeddings (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, memory_id UUID NOT NULL,
  model_id TEXT NOT NULL REFERENCES embedding_models(id),
  embedding vector NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, memory_id, model_id),
  FOREIGN KEY (tenant_id, object_id, memory_id) REFERENCES memories(tenant_id, object_id, id) ON DELETE CASCADE
);
CREATE TRIGGER trg_me_dim BEFORE INSERT OR UPDATE OF embedding, model_id
  ON memory_embeddings FOR EACH ROW EXECUTE FUNCTION check_embedding_dim();

-- -----------------------------------------------------------------------------
-- 10. Tool bindings (A9), policy decisions (A5, A6), command payloads, executions (A7)
-- -----------------------------------------------------------------------------
CREATE TABLE object_tools (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, tool_id UUID NOT NULL,
  tool_version_id UUID NOT NULL, permissions JSONB NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  binding_version BIGINT NOT NULL CHECK (binding_version > 0),
  PRIMARY KEY (tenant_id, object_id, tool_id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id),
  FOREIGN KEY (tool_id, tool_version_id) REFERENCES tool_versions(tool_id, id)
);

-- binding_version comes from the per-object counter: strictly monotonic,
-- never reused. DELETE is forbidden (soft-disable via enabled=false).
CREATE FUNCTION object_tools_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v BIGINT;
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.tool_version_id, NEW.permissions, NEW.enabled)
     IS NOT DISTINCT FROM (OLD.tool_version_id, OLD.permissions, OLD.enabled) THEN
    NEW.binding_version := OLD.binding_version;
    RETURN NEW;
  END IF;
  UPDATE objects SET binding_counter = binding_counter + 1
   WHERE tenant_id = NEW.tenant_id AND object_id = NEW.object_id
   RETURNING binding_counter INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'object not found for binding'; END IF;
  NEW.binding_version := v;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_object_tools_bump BEFORE INSERT OR UPDATE ON object_tools
  FOR EACH ROW EXECUTE FUNCTION object_tools_bump();
CREATE TRIGGER trg_object_tools_nodelete BEFORE DELETE OR TRUNCATE ON object_tools
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TABLE policy_decisions (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  invocation_id UUID NOT NULL, caller_id UUID NOT NULL, snapshot_id UUID NOT NULL,
  tool_id UUID NOT NULL, tool_version_id UUID, binding_version BIGINT,
  operation TEXT NOT NULL, arguments_hash BYTEA NOT NULL CHECK (octet_length(arguments_hash) = 32),
  action_hash BYTEA NOT NULL CHECK (octet_length(action_hash) = 32),
  risk_level TEXT NOT NULL CHECK (risk_level IN ('R0','R1','R2','R3','R4')),
  decision TEXT NOT NULL CHECK (decision IN ('Allow','Deny')), reason TEXT,
  policy_version TEXT NOT NULL,
  command_id UUID, issued_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (decision <> 'Allow' OR (command_id IS NOT NULL AND expires_at IS NOT NULL
         AND issued_at IS NOT NULL AND tool_version_id IS NOT NULL AND binding_version IS NOT NULL)),
  CHECK (decision <> 'Deny' OR command_id IS NULL),
  UNIQUE (tenant_id, object_id, id),
  UNIQUE (tenant_id, object_id, invocation_id, id),
  UNIQUE (tenant_id, object_id, invocation_id, id, decision),
  -- One composite key binds every execution claim to the exact immutable Allow decision.
  UNIQUE (tenant_id, object_id, invocation_id, id, decision, command_id,
          caller_id, snapshot_id, tool_id, tool_version_id, binding_version,
          operation, arguments_hash),
  UNIQUE (tenant_id, command_id),
  FOREIGN KEY (tenant_id, object_id, caller_id, invocation_id)
    REFERENCES object_invocations(tenant_id, object_id, caller_id, id),
  FOREIGN KEY (tenant_id, object_id, snapshot_id) REFERENCES snapshots(tenant_id, object_id, snapshot_id),
  FOREIGN KEY (tool_id, tool_version_id) REFERENCES tool_versions(tool_id, id)
);

-- Short-lived protected payload store (never in events/decisions). Encrypted
-- by the application (envelope encryption); deleted at terminal state/TTL.
CREATE TABLE tool_command_payloads (
  tenant_id UUID NOT NULL, command_id UUID NOT NULL,
  payload_ciphertext BYTEA NOT NULL, key_id TEXT NOT NULL,
  arguments_hash BYTEA NOT NULL CHECK (octet_length(arguments_hash) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, command_id),
  FOREIGN KEY (tenant_id, command_id) REFERENCES policy_decisions(tenant_id, command_id) ON DELETE CASCADE
);
CREATE INDEX idx_tcp_expiry ON tool_command_payloads (expires_at);

CREATE TABLE tool_executions (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  invocation_id UUID NOT NULL, caller_id UUID NOT NULL,
  decision_id UUID NOT NULL, decision TEXT NOT NULL DEFAULT 'Allow' CHECK (decision = 'Allow'),
  command_id UUID NOT NULL, tool_id UUID NOT NULL, tool_version_id UUID NOT NULL,
  snapshot_id UUID NOT NULL, binding_version BIGINT NOT NULL, operation TEXT NOT NULL,
  arguments_hash BYTEA NOT NULL CHECK (octet_length(arguments_hash) = 32),
  status TEXT NOT NULL CHECK (status IN ('Authorized','Executing','Succeeded','Failed','Unknown')),
  lease_owner TEXT, lease_until TIMESTAMPTZ, heartbeat_at TIMESTAMPTZ,
  fencing_token BIGINT NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
  external_idempotency_key TEXT,
  reconciliation_state TEXT CHECK (reconciliation_state IN
    ('pending','confirmed_succeeded','confirmed_failed','manual')),
  output JSONB, output_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), finished_at TIMESTAMPTZ,
  CHECK (output IS NULL OR output_expires_at IS NOT NULL OR status = 'Failed'),
  CHECK ((status IN ('Succeeded','Failed')) = (finished_at IS NOT NULL)),
  CHECK (status <> 'Unknown' OR reconciliation_state IS NOT NULL),
  CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
  CHECK ((lease_owner IS NULL) = (heartbeat_at IS NULL)),
  CHECK ((status = 'Executing') = (lease_owner IS NOT NULL)),
  CHECK (status <> 'Authorized' OR (version = 0 AND fencing_token = 0
         AND lease_owner IS NULL AND lease_until IS NULL AND heartbeat_at IS NULL
         AND finished_at IS NULL)),
  UNIQUE (tenant_id, command_id),
  UNIQUE (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, object_id, invocation_id, decision_id, decision,
               command_id, caller_id, snapshot_id, tool_id, tool_version_id,
               binding_version, operation, arguments_hash)
    REFERENCES policy_decisions(tenant_id, object_id, invocation_id, id, decision,
               command_id, caller_id, snapshot_id, tool_id, tool_version_id,
               binding_version, operation, arguments_hash),
  FOREIGN KEY (tenant_id, command_id) REFERENCES policy_decisions(tenant_id, command_id),
  FOREIGN KEY (tenant_id, object_id, caller_id, invocation_id)
    REFERENCES object_invocations(tenant_id, object_id, caller_id, id),
  FOREIGN KEY (tool_id, tool_version_id) REFERENCES tool_versions(tool_id, id)
);
CREATE INDEX idx_te_unknown ON tool_executions (tenant_id) WHERE status = 'Unknown';
CREATE INDEX idx_te_lease ON tool_executions (lease_until) WHERE status = 'Executing';

-- -----------------------------------------------------------------------------
-- 11. Events and outbox_messages (A6: tenant-consistent FK)
-- -----------------------------------------------------------------------------
-- AUDIT-005: exact physical schema from Rust migration 20261118000003_events_outbox.sql.
CREATE TABLE event_stream_counters (
  tenant_id UUID NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id UUID NOT NULL,
  last_stream_version BIGINT NOT NULL CHECK (last_stream_version > 0),
  PRIMARY KEY (tenant_id, aggregate_type, aggregate_id)
);

CREATE TABLE events (
  tenant_id UUID NOT NULL,
  event_id UUID NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id UUID NOT NULL,
  stream_version BIGINT NOT NULL CHECK (stream_version > 0),
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (event_id),
  CONSTRAINT events_stream_version_unique UNIQUE (tenant_id, aggregate_type, aggregate_id, stream_version)
);

-- Allocate stream_version atomically per aggregate. Concurrent writes to the
-- same stream serialize on its counter row; independent streams do not share a
-- lock or counter. The caller cannot choose or reuse a version.
CREATE FUNCTION assign_event_stream_version() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $event_stream_version$
BEGIN
  IF NEW.stream_version IS NOT NULL THEN
    RAISE EXCEPTION 'event stream_version is database-assigned'
      USING ERRCODE = '42501';
  END IF;
  INSERT INTO event_stream_counters
    (tenant_id, aggregate_type, aggregate_id, last_stream_version)
  VALUES (NEW.tenant_id, NEW.aggregate_type, NEW.aggregate_id, 1)
  ON CONFLICT (tenant_id, aggregate_type, aggregate_id)
  DO UPDATE SET last_stream_version = event_stream_counters.last_stream_version + 1
  RETURNING last_stream_version INTO NEW.stream_version;
  RETURN NEW;
END $event_stream_version$;
CREATE TRIGGER events_assign_stream_version
  BEFORE INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION assign_event_stream_version();
GRANT CREATE ON SCHEMA public TO qembed_event_allocator;
ALTER FUNCTION assign_event_stream_version() OWNER TO qembed_event_allocator;
REVOKE CREATE ON SCHEMA public FROM qembed_event_allocator;
REVOKE ALL ON FUNCTION assign_event_stream_version() FROM PUBLIC;

CREATE INDEX events_aggregate_order_idx
  ON events (tenant_id, aggregate_type, aggregate_id, stream_version);

CREATE FUNCTION reject_event_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $event_append_only$
BEGIN
  RAISE EXCEPTION 'events are append-only'
    USING ERRCODE = '55000';
END $event_append_only$;
CREATE TRIGGER events_append_only
  BEFORE UPDATE OR DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE outbox_messages (
  tenant_id UUID NOT NULL,
  delivery_id UUID NOT NULL,
  event_id UUID NOT NULL,
  topic TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, delivery_id),
  UNIQUE (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES events (tenant_id, event_id)
    ON DELETE RESTRICT
);
CREATE INDEX outbox_pending_idx
  ON outbox_messages (created_at, delivery_id)
  WHERE delivered_at IS NULL;

-- -----------------------------------------------------------------------------
-- 12. Budgets, usage, rate limits, kill switches
-- -----------------------------------------------------------------------------
CREATE TABLE object_budgets (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  daily_token_limit BIGINT NOT NULL CHECK (daily_token_limit >= 0),
  daily_cost_limit_micros BIGINT NOT NULL CHECK (daily_cost_limit_micros >= 0),
  anonymous_share_pct SMALLINT NOT NULL DEFAULT 50 CHECK (anonymous_share_pct BETWEEN 0 AND 100),
  per_caller_daily_token_limit BIGINT NOT NULL CHECK (per_caller_daily_token_limit >= 0),
  max_concurrent_invocations INTEGER NOT NULL CHECK (max_concurrent_invocations > 0),
  max_llm_calls INTEGER NOT NULL CHECK (max_llm_calls > 0),
  max_tool_calls INTEGER NOT NULL CHECK (max_tool_calls >= 0),
  max_tokens_per_invocation BIGINT NOT NULL CHECK (max_tokens_per_invocation > 0),
  max_duration_ms INTEGER NOT NULL CHECK (max_duration_ms > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);

CREATE TABLE budget_reservations (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, invocation_id UUID NOT NULL,
  pool TEXT NOT NULL CHECK (pool IN ('anonymous','authenticated')),
  usage_date DATE NOT NULL,   -- UTC date of reservation; used by settlement/sweeper
  reserved_tokens BIGINT NOT NULL CHECK (reserved_tokens >= 0),
  reserved_cost_micros BIGINT NOT NULL CHECK (reserved_cost_micros >= 0),
  actual_tokens BIGINT CHECK (actual_tokens >= 0), actual_cost_micros BIGINT CHECK (actual_cost_micros >= 0),
  status TEXT NOT NULL CHECK (status IN ('Reserved','Settled','Released','Expired')),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant_id, object_id, invocation_id),
  FOREIGN KEY (tenant_id, object_id, invocation_id, pool)   -- pool must match the invocation
    REFERENCES object_invocations(tenant_id, object_id, id, pool) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX idx_resv_sweep ON budget_reservations (expires_at) WHERE status = 'Reserved';
CREATE TABLE provider_call_attempts (
  tenant_id UUID NOT NULL,
  object_id UUID NOT NULL,
  invocation_id UUID NOT NULL,
  state TEXT NOT NULL DEFAULT 'NotStarted'
    CHECK (state IN ('NotStarted','MayHaveBeenSent','ResponseReceived',
                     'ConfirmedNotAccepted','OutcomeUnknown','CancelledBeforeSend')),
  input_tokens BIGINT CHECK (input_tokens >= 0),
  output_tokens BIGINT CHECK (output_tokens >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_id, invocation_id),
  FOREIGN KEY (tenant_id, object_id, invocation_id)
    REFERENCES object_invocations (tenant_id, object_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK ((input_tokens IS NULL) = (output_tokens IS NULL)),
  CHECK (state = 'ResponseReceived' OR (input_tokens IS NULL AND output_tokens IS NULL))
);

-- Every committed reservation gets a durable pre-send marker in the same transaction.
-- Missing attempt rows are treated conservatively by the sweeper (never auto-released).
CREATE FUNCTION create_provider_call_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $provider_attempt_create$
BEGIN
  INSERT INTO provider_call_attempts (tenant_id, object_id, invocation_id, state)
  VALUES (NEW.tenant_id, NEW.object_id, NEW.invocation_id, 'NotStarted');
  RETURN NEW;
END $provider_attempt_create$;
CREATE TRIGGER trg_budget_reservation_provider_attempt
  AFTER INSERT ON budget_reservations FOR EACH ROW
  EXECUTE FUNCTION create_provider_call_attempt();

CREATE FUNCTION provider_call_attempt_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $provider_attempt_guard$
BEGIN
  IF (NEW.tenant_id, NEW.object_id, NEW.invocation_id)
     IS DISTINCT FROM (OLD.tenant_id, OLD.object_id, OLD.invocation_id) THEN
    RAISE EXCEPTION 'provider call attempt identity is immutable' USING ERRCODE = '55000';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'NotStarted' AND NEW.state IN ('MayHaveBeenSent','CancelledBeforeSend'))
    OR (OLD.state = 'MayHaveBeenSent' AND NEW.state IN ('ResponseReceived','ConfirmedNotAccepted','OutcomeUnknown'))
    OR (OLD.state = 'OutcomeUnknown' AND NEW.state IN ('ResponseReceived','ConfirmedNotAccepted'))
  ) THEN
    RAISE EXCEPTION 'invalid provider call attempt transition: % -> %', OLD.state, NEW.state
      USING ERRCODE = '23514';
  END IF;
  IF OLD.state = 'ResponseReceived'
     AND (NEW.input_tokens, NEW.output_tokens) IS DISTINCT FROM (OLD.input_tokens, OLD.output_tokens) THEN
    RAISE EXCEPTION 'persisted provider usage is immutable' USING ERRCODE = '55000';
  END IF;
  IF NEW.state = 'ResponseReceived' AND NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'provider call attempt timestamp cannot move backwards' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $provider_attempt_guard$;
CREATE TRIGGER trg_provider_call_attempt_state_guard
  BEFORE UPDATE ON provider_call_attempts FOR EACH ROW
  EXECUTE FUNCTION provider_call_attempt_state_guard();

CREATE TABLE usage_counters (
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, usage_date DATE NOT NULL,
  pool TEXT NOT NULL CHECK (pool IN ('anonymous','authenticated')),
  consumed_tokens BIGINT NOT NULL DEFAULT 0 CHECK (consumed_tokens >= 0),
  consumed_cost_micros BIGINT NOT NULL DEFAULT 0 CHECK (consumed_cost_micros >= 0),
  reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
  reserved_cost_micros BIGINT NOT NULL DEFAULT 0 CHECK (reserved_cost_micros >= 0),
  PRIMARY KEY (tenant_id, object_id, usage_date, pool),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);

CREATE TABLE caller_usage_counters (   -- per-caller daily tokens (B17)
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, caller_id UUID NOT NULL, usage_date DATE NOT NULL,
  consumed_tokens BIGINT NOT NULL DEFAULT 0 CHECK (consumed_tokens >= 0),
  reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
  PRIMARY KEY (tenant_id, object_id, caller_id, usage_date),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id),
  FOREIGN KEY (tenant_id, caller_id) REFERENCES callers(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE budget_event_dedup (   -- budget_exhausted: at most once per day per object+budget type
  tenant_id UUID NOT NULL, object_id UUID NOT NULL, budget_type TEXT NOT NULL, usage_date DATE NOT NULL,
  PRIMARY KEY (tenant_id, object_id, budget_type, usage_date),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);

CREATE TABLE rate_limit_buckets (   -- global, server-built keys
  bucket_key TEXT PRIMARY KEY, tokens NUMERIC NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL, policy_version TEXT NOT NULL
);
CREATE INDEX idx_rl_cleanup ON rate_limit_buckets (updated_at);

CREATE TABLE kill_switches (   -- restricted-global: tenant_id NULL for platform / global tool
  id UUID PRIMARY KEY,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('platform','tenant','object','tool')),
  tenant_id UUID REFERENCES tenants(id), object_id UUID, tool_id UUID REFERENCES tool_definitions(id),
  enabled BOOLEAN NOT NULL, reason TEXT, changed_by TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((scope_type = 'platform' AND tenant_id IS NULL AND object_id IS NULL AND tool_id IS NULL)
      OR (scope_type = 'tenant'   AND tenant_id IS NOT NULL AND object_id IS NULL AND tool_id IS NULL)
      OR (scope_type = 'object'   AND tenant_id IS NOT NULL AND object_id IS NOT NULL AND tool_id IS NULL)
      OR (scope_type = 'tool'     AND tool_id IS NOT NULL AND object_id IS NULL)),
  UNIQUE NULLS NOT DISTINCT (scope_type, tenant_id, object_id, tool_id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);

-- -----------------------------------------------------------------------------
-- 13. Goals/tasks (M4 contracts), deletion, retention
-- -----------------------------------------------------------------------------
CREATE TABLE object_goals (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL,
  description TEXT NOT NULL, priority SMALLINT NOT NULL, status TEXT NOT NULL,
  constraints JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, object_id, id),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id)
);
CREATE TABLE object_tasks (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, object_id UUID NOT NULL, goal_id UUID,
  status TEXT NOT NULL, checkpoint JSONB, lease_owner TEXT, lease_until TIMESTAMPTZ,
  fencing_token BIGINT NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
  deadline TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, object_id) REFERENCES objects(tenant_id, object_id),
  FOREIGN KEY (tenant_id, object_id, goal_id) REFERENCES object_goals(tenant_id, object_id, id)
);

CREATE TABLE deletion_jobs (
  id UUID PRIMARY KEY, tenant_id UUID NOT NULL, caller_id UUID NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Pending','Running','Done','Failed')),
  progress JSONB NOT NULL DEFAULT '{}', requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  FOREIGN KEY (tenant_id, caller_id) REFERENCES callers(tenant_id, id)
);
CREATE UNIQUE INDEX uq_deletion_active ON deletion_jobs (tenant_id, caller_id)
  WHERE status IN ('Pending','Running');

CREATE TABLE deletion_ledger (
  tenant_id UUID NOT NULL, caller_hash BYTEA NOT NULL, deleted_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, caller_hash)
);
CREATE TABLE retention_log (   -- no tenant_id: privileges only, no tenant policy
  id BIGSERIAL PRIMARY KEY, table_name TEXT NOT NULL, rows_affected BIGINT NOT NULL,
  reason TEXT NOT NULL, executed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 14. Append-only enforcement (UPDATE/DELETE/TRUNCATE) on immutable tables
-- -----------------------------------------------------------------------------
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['snapshots','policy_decisions'] LOOP
    EXECUTE format('CREATE TRIGGER trg_%s_append_only BEFORE UPDATE OR DELETE ON %I
                    FOR EACH ROW EXECUTE FUNCTION forbid_mutation()', t, t);
    EXECUTE format('CREATE TRIGGER trg_%s_no_truncate BEFORE TRUNCATE ON %I
                    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()', t, t);
  END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- 15. RLS (A1): classification + ENABLE/FORCE on every table
-- -----------------------------------------------------------------------------
-- tenant-owned: tenant_id NOT NULL, policy by app.tenant_id
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'objects','object_versions','callers','snapshots','object_invocations',
    'invocation_idempotency','interaction_messages','knowledge_revisions','knowledge_revision_log',
    'knowledge_documents','knowledge_chunks','knowledge_chunk_embeddings',
    'object_tools','policy_decisions',
    'tool_command_payloads','tool_executions','events','outbox_messages','object_budgets',
    'budget_reservations','provider_call_attempts','usage_counters','caller_usage_counters','budget_event_dedup',
    'object_goals','object_tasks','deletion_jobs','deletion_ledger',
    'principal_caller_delegations','event_stream_counters']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I TO qembed_runtime
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $;

-- The trigger's NOLOGIN owner can mutate only the counter table. Runtime has
-- no direct counter privileges; the trigger derives tenant/aggregate identity
-- exclusively from an INSERT already authorized by events RLS.
CREATE POLICY event_stream_counters_allocator ON event_stream_counters
  FOR ALL TO qembed_event_allocator USING (true) WITH CHECK (true);

-- These tables are excluded from the generic tenant-only policy loop because
-- their runtime policy also depends on the parent memory's Caller visibility.
ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;
ALTER TABLE memory_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_embeddings FORCE ROW LEVEL SECURITY;
ALTER TABLE memory_conflicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_conflicts FORCE ROW LEVEL SECURITY;

-- T-27: semantic memory remains tenant-scoped; episodic memory is Caller-scoped.
-- Missing app.caller_id fails closed for episodic rows.
CREATE POLICY tenant_isolation ON memories TO qembed_runtime
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND (memory_kind = 'semantic'
         OR caller_id = NULLIF(current_setting('app.caller_id', true), '')::uuid)
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND (memory_kind = 'semantic'
         OR caller_id = NULLIF(current_setting('app.caller_id', true), '')::uuid)
  );

-- Child tables inherit visibility from their parent memories, closing side channels.
CREATE POLICY tenant_isolation ON memory_embeddings TO qembed_runtime
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_embeddings.tenant_id
         AND m.object_id = memory_embeddings.object_id
         AND m.id = memory_embeddings.memory_id
    )
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_embeddings.tenant_id
         AND m.object_id = memory_embeddings.object_id
         AND m.id = memory_embeddings.memory_id
    )
  );

CREATE POLICY tenant_isolation ON memory_conflicts TO qembed_runtime
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_conflicts.tenant_id
         AND m.object_id = memory_conflicts.object_id
         AND m.id = memory_conflicts.memory_id
    )
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_conflicts.tenant_id
         AND m.object_id = memory_conflicts.object_id
         AND m.id = memory_conflicts.conflicting_memory_id
    )
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_conflicts.tenant_id
         AND m.object_id = memory_conflicts.object_id
         AND m.id = memory_conflicts.memory_id
    )
    AND EXISTS (
      SELECT 1 FROM memories m
       WHERE m.tenant_id = memory_conflicts.tenant_id
         AND m.object_id = memory_conflicts.object_id
         AND m.id = memory_conflicts.conflicting_memory_id
    )
  );

-- restricted-global tables with explicit policies
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;      ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE principals ENABLE ROW LEVEL SECURITY;   ALTER TABLE principals FORCE ROW LEVEL SECURITY;
ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY; ALTER TABLE kill_switches FORCE ROW LEVEL SECURITY;

CREATE POLICY own_tenant ON tenants FOR SELECT TO qembed_runtime
  USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY admin_all ON tenants TO qembed_admin USING (true) WITH CHECK (true);

CREATE POLICY own_tenant ON principals FOR SELECT TO qembed_runtime
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY admin_all ON principals TO qembed_admin USING (true) WITH CHECK (true);
CREATE POLICY definer_auth ON principals FOR SELECT TO qembed_definer USING (true);

CREATE POLICY ks_read ON kill_switches FOR SELECT TO qembed_runtime
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY ks_write ON kill_switches FOR ALL TO qembed_runtime
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY ks_admin ON kill_switches TO qembed_admin USING (true) WITH CHECK (true);

-- dispatcher: delivery only
CREATE POLICY disp_outbox ON outbox_messages TO qembed_dispatcher USING (true) WITH CHECK (true);
CREATE POLICY disp_events ON events FOR SELECT TO qembed_dispatcher USING (true);

-- definer role (owner of SECURITY DEFINER functions): only the tables their bodies touch
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['objects','object_invocations','callers','principal_caller_delegations','budget_reservations',
      'provider_call_attempts','usage_counters','caller_usage_counters','tool_executions','tool_command_payloads',
      'interaction_messages','memories','invocation_idempotency','outbox_messages'] LOOP
    EXECUTE format('CREATE POLICY definer_access ON %I TO qembed_definer USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;

-- admin: tenant provisioning needs to create the initial tenant rows
CREATE POLICY admin_objects ON objects TO qembed_admin USING (true) WITH CHECK (true);
-- r3 (R3-06): trg_objects_init_knowledge runs as the inserting role; admin object
-- provisioning failed with 42501 on knowledge_revisions.
CREATE POLICY admin_knowledge_revisions ON knowledge_revisions FOR SELECT TO qembed_admin USING (true);
CREATE POLICY admin_knowledge_revisions_ins ON knowledge_revisions FOR INSERT TO qembed_admin WITH CHECK (current_revision = 0);

-- Reusable catalog assertion: migrations call this before becoming usable,
-- and regression tests deliberately create an unclassified tenant table to
-- prove the guard aborts rather than silently accepting an incomplete policy set.
CREATE FUNCTION assert_tenant_rls_classification() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $rls_audit$
DECLARE bad_tables TEXT;
        missing_tables TEXT;
        unclassified_tables TEXT;
BEGIN
  -- Positive allowlist: a new tenant-owned table cannot escape the audit by
  -- omitting tenant_id entirely or by being left out of the generic RLS loop.
  SELECT string_agg(expected.table_name, ', ' ORDER BY expected.table_name)
    INTO missing_tables
    FROM unnest(ARRAY[
      'objects','object_versions','callers','principal_caller_delegations',
      'snapshots','object_invocations','invocation_idempotency','interaction_messages',
      'knowledge_revisions','knowledge_revision_log','knowledge_documents','knowledge_chunks',
      'knowledge_chunk_embeddings','memories','memory_conflicts','memory_embeddings',
      'object_tools','policy_decisions','tool_command_payloads','tool_executions',
      'event_stream_counters','events','outbox_messages','object_budgets',
      'budget_reservations','provider_call_attempts','usage_counters','caller_usage_counters',
      'budget_event_dedup','object_goals','object_tasks','deletion_jobs','deletion_ledger'
    ]) AS expected(table_name)
    LEFT JOIN pg_class c ON c.relname=expected.table_name
      AND c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p')
    LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id'
      AND a.attnum>0 AND NOT a.attisdropped
   WHERE c.oid IS NULL OR a.attnum IS NULL OR NOT a.attnotnull
      OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
      OR NOT EXISTS (
        SELECT 1 FROM pg_policy p
         WHERE p.polrelid=c.oid AND p.polname='tenant_isolation'
           AND p.polroles @> ARRAY[(SELECT oid FROM pg_roles WHERE rolname='qembed_runtime')]::oid[]
           AND p.polcmd='*'
      );
  IF missing_tables IS NOT NULL THEN
    RAISE EXCEPTION 'expected tenant-owned tables are missing tenant/RLS classification: %', missing_tables
      USING ERRCODE = '55000';
  END IF;

  -- Negative allowlist: every additional table with tenant_id must be either
  -- tenant-owned under the generic policy or an explicit reviewed exception.
  SELECT string_agg(format('%I', c.relname), ', ' ORDER BY c.relname)
    INTO bad_tables
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id'
      AND a.attnum>0 AND NOT a.attisdropped
   WHERE n.nspname='public' AND c.relkind IN ('r','p')
     AND c.relname NOT IN ('owner_principals','owner_credentials','principals','kill_switches')
     AND (NOT a.attnotnull OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR NOT EXISTS (
       SELECT 1 FROM pg_policy p
        WHERE p.polrelid=c.oid AND p.polname='tenant_isolation'
          AND p.polroles @> ARRAY[(SELECT oid FROM pg_roles WHERE rolname='qembed_runtime')]::oid[]
          AND p.polcmd='*'
     ));
  IF bad_tables IS NOT NULL THEN
    RAISE EXCEPTION 'tenant RLS classification incomplete: %', bad_tables
      USING ERRCODE = '55000';
  END IF;

  -- Every public base table must belong to an explicit tenant-owned,
  -- restricted-global, pre-auth, or global classification. This catches a
  -- newly introduced table that omits tenant_id altogether.
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
    INTO unclassified_tables
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p')
     AND c.relname <> ALL (ARRAY[
       'embedding_models','tool_definitions','tool_versions','tenants',
       'principals','owner_principals','owner_credentials',
       'objects','object_versions','callers','principal_caller_delegations',
       'snapshots','object_invocations','invocation_idempotency','interaction_messages',
       'knowledge_revisions','knowledge_revision_log','knowledge_documents','knowledge_chunks',
       'knowledge_chunk_embeddings','memories','memory_conflicts','memory_embeddings',
       'object_tools','policy_decisions','tool_command_payloads','tool_executions',
       'event_stream_counters','events','outbox_messages','object_budgets',
       'budget_reservations','provider_call_attempts','usage_counters','caller_usage_counters',
       'budget_event_dedup','rate_limit_buckets','kill_switches','object_goals',
       'object_tasks','deletion_jobs','deletion_ledger','retention_log'
     ]);
  IF unclassified_tables IS NOT NULL THEN
    RAISE EXCEPTION 'public tables lack an explicit tenant/global classification: %', unclassified_tables
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id'
      AND a.attnum>0 AND NOT a.attisdropped
    WHERE n.nspname='public' AND c.relname IN ('principals','kill_switches')
      AND (
        a.attnotnull OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
        OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
          AND p.polname=CASE c.relname WHEN 'principals' THEN 'own_tenant' ELSE 'ks_read' END
          AND p.polroles @> ARRAY[(SELECT oid FROM pg_roles WHERE rolname='qembed_runtime')]::oid[]
          AND p.polcmd='r')
      )
  ) THEN
    RAISE EXCEPTION 'restricted-global tenant_id tables lost nullable FORCE-RLS classification'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id'
      AND a.attnum>0 AND NOT a.attisdropped
    WHERE n.nspname='public' AND c.relname IN ('owner_principals','owner_credentials')
      AND (NOT a.attnotnull OR c.relrowsecurity OR c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'pre-auth owner tables lost their explicit column-grant classification'
      USING ERRCODE = '55000';
  END IF;
END $rls_audit$;
REVOKE ALL ON FUNCTION assert_tenant_rls_classification() FROM PUBLIC;
SELECT assert_tenant_rls_classification();


-- -----------------------------------------------------------------------------
-- 16. SECURITY DEFINER functions (owner qembed_definer; fixed search_path)
-- -----------------------------------------------------------------------------
CREATE FUNCTION authenticate_principal(p_key_hash BYTEA)
RETURNS TABLE (principal_id UUID, tenant_id UUID, kind TEXT)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $authenticate_principal$
  SELECT id, tenant_id, kind FROM principals WHERE key_hash = p_key_hash AND revoked_at IS NULL
$authenticate_principal$;

-- These functions trust app.tenant_id and app.principal_id only when set by the
-- authenticated application transaction. The runtime role has no direct DML grant
-- on the delegation table.
CREATE FUNCTION grant_caller_delegation(p_caller_id UUID)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $grant_caller_delegation$
DECLARE
  v_tenant_id UUID := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_principal_id UUID := NULLIF(current_setting('app.principal_id', true), '')::uuid;
  v_delegation_id UUID := gen_random_uuid();
BEGIN
  IF v_tenant_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'tenant and authenticated principal context are required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM owner_principals p
   WHERE p.tenant_id = v_tenant_id AND p.caller_id = v_principal_id
     AND p.disabled_at IS NULL
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'authenticated principal is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM callers c
   WHERE c.tenant_id = v_tenant_id AND c.id = p_caller_id
     AND c.revoked_at IS NULL
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'target caller is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  INSERT INTO principal_caller_delegations
    (delegation_id, tenant_id, principal_id, caller_id)
  VALUES (v_delegation_id, v_tenant_id, v_principal_id, p_caller_id);
  RETURN v_delegation_id;
END
$grant_caller_delegation$;

CREATE FUNCTION revoke_caller_delegation(p_delegation_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $revoke_caller_delegation$
DECLARE
  v_tenant_id UUID := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_principal_id UUID := NULLIF(current_setting('app.principal_id', true), '')::uuid;
BEGIN
  IF v_tenant_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'tenant and authenticated principal context are required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM owner_principals p
     WHERE p.tenant_id = v_tenant_id AND p.caller_id = v_principal_id
       AND p.disabled_at IS NULL
  ) THEN
    RAISE EXCEPTION 'authenticated principal is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  UPDATE principal_caller_delegations
     SET revoked_at = clock_timestamp(), revoked_by_principal_id = v_principal_id
   WHERE delegation_id = p_delegation_id AND tenant_id = v_tenant_id
     AND principal_id = v_principal_id AND revoked_at IS NULL;
  RETURN FOUND;
END
$revoke_caller_delegation$;

-- Resolve an explicit Caller and hold the delegation plus both lifecycle rows
-- against concurrent revocation/disable until the caller's transaction commits.
CREATE FUNCTION resolve_delegated_caller(p_caller_id UUID)
RETURNS TABLE (delegation_id UUID, caller_id UUID, caller_kind TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $resolve_delegated_caller$
DECLARE
  v_tenant_id UUID := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_principal_id UUID := NULLIF(current_setting('app.principal_id', true), '')::uuid;
BEGIN
  IF v_tenant_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'tenant and authenticated principal context are required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT d.delegation_id, c.id, c.caller_kind
    FROM principal_caller_delegations d
    JOIN owner_principals p
      ON p.tenant_id = d.tenant_id AND p.caller_id = d.principal_id
    JOIN callers c
      ON c.tenant_id = d.tenant_id AND c.id = d.caller_id
   WHERE d.tenant_id = v_tenant_id AND d.principal_id = v_principal_id
     AND d.caller_id = p_caller_id AND d.revoked_at IS NULL
     AND p.disabled_at IS NULL AND c.revoked_at IS NULL
   FOR SHARE OF d, p, c;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active delegation for this Principal and Caller'
      USING ERRCODE = '42501';
  END IF;

  -- Bind caller-scoped RLS to the validated delegation for this transaction only.
  PERFORM set_config('app.caller_id', p_caller_id::text, true);
END
$resolve_delegated_caller$;

CREATE FUNCTION resolve_object_tenant(p_object_id UUID)
RETURNS UUID LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT tenant_id FROM objects WHERE object_id = p_object_id
$$;

-- Cross-tenant discovery for background workers (A3): returns identifiers only;
-- the worker then acts under the proper Scope (SET LOCAL app.tenant_id).
CREATE FUNCTION list_expired_invocation_leases(p_limit INT)
RETURNS TABLE (tenant_id UUID, invocation_id UUID, fencing_token BIGINT)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT tenant_id, id, fencing_token FROM object_invocations
   WHERE lease_until < now()
     AND status NOT IN ('Completed','CompletedDegraded','Failed','Cancelled')
   ORDER BY lease_until LIMIT p_limit
$$;

CREATE FUNCTION list_pending_reconciliations(p_limit INT)
RETURNS TABLE (tenant_id UUID, execution_id UUID)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT tenant_id, id FROM tool_executions
   WHERE (status = 'Unknown' AND reconciliation_state = 'pending')
      OR (status = 'Executing' AND lease_until < now())
   LIMIT p_limit
$$;

-- Idempotent sweeper (T-40)
CREATE FUNCTION sweep_expired_reservations(p_limit INT) RETURNS INT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE r RECORD; n INT := 0;
BEGIN
  FOR r IN SELECT br.* FROM budget_reservations br
            JOIN provider_call_attempts pca
              ON pca.tenant_id = br.tenant_id AND pca.object_id = br.object_id
             AND pca.invocation_id = br.invocation_id
            WHERE br.status = 'Reserved' AND br.expires_at < now()
              AND pca.state IN ('NotStarted','ConfirmedNotAccepted','CancelledBeforeSend')
            ORDER BY br.expires_at LIMIT p_limit FOR UPDATE OF pca SKIP LOCKED
  LOOP
    UPDATE budget_reservations SET status = 'Expired' WHERE id = r.id AND status = 'Reserved';
    UPDATE usage_counters
       SET reserved_tokens = reserved_tokens - r.reserved_tokens,
           reserved_cost_micros = reserved_cost_micros - r.reserved_cost_micros
     WHERE tenant_id = r.tenant_id AND object_id = r.object_id
       AND usage_date = r.usage_date AND pool = r.pool;
    -- r3 (R3-04): per-caller reserved tokens were never released on expiry
    UPDATE caller_usage_counters c
       SET reserved_tokens = greatest(0, c.reserved_tokens - r.reserved_tokens)
      FROM object_invocations i
     WHERE i.tenant_id = r.tenant_id AND i.object_id = r.object_id AND i.id = r.invocation_id
       AND c.tenant_id = i.tenant_id AND c.object_id = i.object_id
       AND c.caller_id = i.caller_id AND c.usage_date = r.usage_date;
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;

-- Retention: fixed whitelist, per-table action (A8). Append-only tables are NOT purgeable here.
CREATE FUNCTION retention_purge(p_table TEXT, p_cutoff TIMESTAMPTZ, p_reason TEXT) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE n BIGINT;
BEGIN
  IF p_table = 'interaction_messages' THEN
    DELETE FROM interaction_messages WHERE expires_at < p_cutoff;
  ELSIF p_table = 'memories' THEN
    DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at < p_cutoff;
  ELSIF p_table = 'invocation_idempotency' THEN
    DELETE FROM invocation_idempotency WHERE expires_at < p_cutoff;
  ELSIF p_table = 'tool_command_payloads' THEN
    DELETE FROM tool_command_payloads WHERE expires_at < p_cutoff;
  ELSIF p_table = 'outbox_messages' THEN
    DELETE FROM outbox_messages WHERE delivered_at IS NOT NULL AND created_at < p_cutoff;
  ELSIF p_table = 'tool_executions' THEN   -- nullify output, keep the audit row
    UPDATE tool_executions SET output = NULL, output_expires_at = NULL
     WHERE output IS NOT NULL AND output_expires_at < p_cutoff;
  ELSE
    RAISE EXCEPTION 'table not allowed';
  END IF;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO retention_log (table_name, rows_affected, reason) VALUES (p_table, n, p_reason);
  RETURN n;
END $$;

-- ownership: functions must be owned by qembed_definer
DO $$
DECLARE f TEXT;
BEGIN
  FOREACH f IN ARRAY ARRAY['authenticate_principal(bytea)','grant_caller_delegation(uuid)','revoke_caller_delegation(uuid)','resolve_delegated_caller(uuid)','resolve_object_tenant(uuid)',
     'list_expired_invocation_leases(integer)','list_pending_reconciliations(integer)',
     'sweep_expired_reservations(integer)','retention_purge(text,timestamptz,text)'] LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO qembed_definer', f);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- 17. Grants (least privilege)
-- -----------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- runtime
GRANT SELECT ON embedding_models, tool_definitions, tool_versions, tenants, principals, kill_switches TO qembed_runtime;
-- AUDIT-002: pre-auth lookup for the Rust adapter, read-only and limited to the columns it queries.
GRANT SELECT (tenant_id, caller_id, principal_kind, disabled_at) ON owner_principals TO qembed_runtime;
GRANT SELECT (tenant_id, caller_id, token_hash, revoked_at) ON owner_credentials TO qembed_runtime;
GRANT SELECT ON principal_caller_delegations TO qembed_runtime;
GRANT SELECT, INSERT, UPDATE ON
  objects, object_versions, callers, object_invocations, invocation_idempotency,
  interaction_messages, knowledge_revisions, knowledge_documents, knowledge_chunks,
  knowledge_chunk_embeddings, memories, memory_conflicts, memory_embeddings, object_tools,
  tool_command_payloads, tool_executions, object_budgets, budget_reservations,
  provider_call_attempts, usage_counters, caller_usage_counters, budget_event_dedup, object_goals, object_tasks,
  deletion_jobs TO qembed_runtime;
GRANT INSERT, SELECT ON knowledge_revision_log, snapshots, policy_decisions, events,
  outbox_messages, deletion_ledger TO qembed_runtime;                   -- append-only/event records: no UPDATE
GRANT SELECT, INSERT, UPDATE ON event_stream_counters TO qembed_event_allocator;
GRANT INSERT, UPDATE, DELETE ON kill_switches TO qembed_runtime;
GRANT DELETE ON object_versions, interaction_messages, memories, memory_embeddings,
  knowledge_chunk_embeddings, tool_command_payloads TO qembed_runtime;    -- drafts / caller deletion / payload TTL
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_buckets TO qembed_runtime;
GRANT EXECUTE ON FUNCTION authenticate_principal(bytea), grant_caller_delegation(uuid),
  revoke_caller_delegation(uuid), resolve_delegated_caller(uuid), resolve_object_tenant(uuid),
  list_expired_invocation_leases(integer), list_pending_reconciliations(integer),
  sweep_expired_reservations(integer) TO qembed_runtime;

-- dispatcher: only delivery
GRANT SELECT ON events TO qembed_dispatcher;
GRANT SELECT ON outbox_messages TO qembed_dispatcher;
GRANT UPDATE (delivered_at) ON outbox_messages TO qembed_dispatcher;

-- admin
GRANT SELECT, INSERT, UPDATE ON tenants, principals, kill_switches, objects,
  embedding_models, tool_definitions, tool_versions TO qembed_admin;
GRANT SELECT, INSERT ON knowledge_revisions TO qembed_admin;          -- r3 (R3-06)
GRANT SELECT, INSERT ON owner_principals TO qembed_admin;  -- AUDIT-002: provision principals
GRANT UPDATE (disabled_at) ON owner_principals TO qembed_admin;  -- only lifecycle mutation; identity is immutable
GRANT SELECT, INSERT, UPDATE ON owner_credentials TO qembed_admin;  -- provision / revoke (guard protects identity/digest; no DELETE)

-- retention
GRANT EXECUTE ON FUNCTION retention_purge(text,timestamptz,text) TO qembed_retention;

-- definer: privileges needed by function bodies (narrow to column grants in review)
GRANT SELECT ON principals, owner_principals, objects, object_invocations, callers TO qembed_definer;
GRANT UPDATE (disabled_at) ON owner_principals TO qembed_definer; -- row lock for invocation-time resolution
GRANT UPDATE (revoked_at) ON callers TO qembed_definer;          -- row lock for invocation-time resolution
GRANT SELECT, INSERT, UPDATE ON principal_caller_delegations TO qembed_definer;
GRANT SELECT, UPDATE ON budget_reservations, provider_call_attempts, usage_counters, tool_executions TO qembed_definer;
GRANT SELECT, DELETE ON interaction_messages, memories, invocation_idempotency,
  tool_command_payloads, outbox_messages TO qembed_definer;
GRANT SELECT, UPDATE ON caller_usage_counters TO qembed_definer;   -- r3: sweeper releases per-caller reservations
GRANT INSERT ON retention_log TO qembed_definer;
GRANT USAGE, SELECT ON SEQUENCE retention_log_id_seq TO qembed_definer;

-- -----------------------------------------------------------------------------
-- 18. Migration audit: fail if any public table lacks RLS/FORCE, outside the allowlist
-- -----------------------------------------------------------------------------
DO $$
DECLARE bad TEXT;
BEGIN
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
     AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
     AND c.relname NOT IN ('embedding_models','tool_definitions','tool_versions',
                           'rate_limit_buckets','retention_log',
                           'owner_principals','owner_credentials');   -- AUDIT-002/006: pre-auth lookup has no Scope; enforce its narrow column grants instead of tenant RLS.
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'RLS/FORCE missing on: %', bad; END IF;
END $$;


-- =============================================================================
-- v2.3.3 finalization guards (RT-039..RT-046)
-- These guards close claim-integrity holes found in the v2.3.2 static review.
-- They do NOT replace Rust-side RFC 8785/JCS canonicalization.
-- =============================================================================

-- AUDIT-004 supersedes the former r3 projection trigger above: Rust stores
-- canonical_json + content_hash + json_projection only. The active guard is
-- snapshots_projection_guard, defined alongside the Rust-shaped table.
-- A policy decision must pin the same snapshot/caller as its invocation.
CREATE FUNCTION policy_decision_invocation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE i object_invocations%ROWTYPE;
BEGIN
  SELECT * INTO i FROM object_invocations
   WHERE tenant_id=NEW.tenant_id AND object_id=NEW.object_id AND id=NEW.invocation_id;
  IF NOT FOUND OR (i.caller_id,i.snapshot_id) IS DISTINCT FROM (NEW.caller_id,NEW.snapshot_id) THEN
    RAISE EXCEPTION 'policy decision claims differ from invocation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_policy_decision_invocation_guard
  BEFORE INSERT ON policy_decisions FOR EACH ROW
  EXECUTE FUNCTION policy_decision_invocation_guard();

-- A published version cannot be superseded while the object still points to it (checked at COMMIT, r3).
CREATE OR REPLACE FUNCTION object_versions_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $object_version_guard_r3$
BEGIN
  -- New rows are always Draft. This branch must precede every OLD-row check:
  -- OLD is not populated for INSERT, and treating it like an UPDATE rejects
  -- every legitimate ObjectVersion creation as an identity mutation.
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'draft' THEN
      RAISE EXCEPTION 'new object versions must start as Draft' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' THEN
      RAISE EXCEPTION 'only draft object versions may be deleted' USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF (NEW.object_version_id, NEW.tenant_id, NEW.object_id, NEW.version_number, NEW.created_at)
     IS DISTINCT FROM
     (OLD.object_version_id, OLD.tenant_id, OLD.object_id, OLD.version_number, OLD.created_at) THEN
    RAISE EXCEPTION 'object version identity is immutable' USING ERRCODE = '55000';
  END IF;

  IF OLD.status = 'draft' THEN
    IF NEW.status NOT IN ('draft', 'published') THEN
      RAISE EXCEPTION 'invalid object version transition: % -> %', OLD.status, NEW.status
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'published' AND NEW.status = 'superseded' THEN
    IF (NEW.config, NEW.chat_model_ref, NEW.embedding_model_id, NEW.published_at)
       IS NOT DISTINCT FROM
       (OLD.config, OLD.chat_model_ref, OLD.embedding_model_id, OLD.published_at) THEN
      -- R3-01: defer the published-pointer check to COMMIT so republish can
      -- supersede the old version, publish the replacement, and move the pointer
      -- atomically in one transaction.
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'published object version content is immutable' USING ERRCODE = '55000';
  END IF;

  RAISE EXCEPTION 'invalid or terminal object version transition: % -> %', OLD.status, NEW.status
    USING ERRCODE = '23514';
END
$object_version_guard_r3$;

-- r3 (R3-01): deferred pointer check. Re-publication transaction order:
--   1) UPDATE old version  published -> superseded
--   2) UPDATE new version  draft     -> published
--   3) UPDATE objects SET published_version_id = <new>
-- At COMMIT no object may still point to a superseded version.
CREATE FUNCTION object_version_superseded_pointer_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM objects o WHERE o.tenant_id = NEW.tenant_id
             AND o.object_id = NEW.object_id AND o.published_version_id = NEW.object_version_id) THEN
    RAISE EXCEPTION 'cannot supersede the currently published object version (pointer not moved before COMMIT)';
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER trg_ov_superseded_pointer_check
  AFTER UPDATE ON object_versions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (OLD.status = 'published' AND NEW.status = 'superseded')
  EXECUTE FUNCTION object_version_superseded_pointer_check();

-- RT-040: a tool execution must be an exact projection of the Allow decision,
-- not merely share its decision_id/command_id. This includes all scope claims.
CREATE FUNCTION tool_execution_claims_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE d policy_decisions%ROWTYPE;
BEGIN
  SELECT * INTO d FROM policy_decisions
   WHERE tenant_id=NEW.tenant_id AND id=NEW.decision_id;
  IF NOT FOUND OR d.decision <> 'Allow'
     OR (d.tenant_id,d.object_id,d.invocation_id,d.caller_id,d.snapshot_id,
         d.tool_id,d.tool_version_id,d.binding_version,d.operation,d.arguments_hash,d.command_id)
        IS DISTINCT FROM
        (NEW.tenant_id,NEW.object_id,NEW.invocation_id,NEW.caller_id,NEW.snapshot_id,
         NEW.tool_id,NEW.tool_version_id,NEW.binding_version,NEW.operation,NEW.arguments_hash,NEW.command_id) THEN
    RAISE EXCEPTION 'tool execution claims differ from Allow decision';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_tool_execution_claims_guard
  BEFORE INSERT OR UPDATE OF tenant_id,object_id,invocation_id,caller_id,decision_id,
    command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,decision
  ON tool_executions FOR EACH ROW EXECUTE FUNCTION tool_execution_claims_guard();

-- RT-043: payload bytes are bound to the exact Allow decision arguments hash.
CREATE FUNCTION tool_payload_hash_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE h BYTEA;
BEGIN
  SELECT arguments_hash INTO h FROM policy_decisions
   WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id AND decision='Allow';
  IF h IS NULL OR h IS DISTINCT FROM NEW.arguments_hash THEN
    RAISE EXCEPTION 'command payload hash differs from Allow decision';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_tool_payload_hash_guard
  BEFORE INSERT OR UPDATE OF tenant_id,command_id,arguments_hash ON tool_command_payloads
  FOR EACH ROW EXECUTE FUNCTION tool_payload_hash_guard();

-- RT-044: Verified is created as a NEW Owner-authored row. An UPDATE may not
-- promote an existing candidate or mutate an already verified record.
CREATE OR REPLACE FUNCTION memories_verified_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE k TEXT;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF OLD.verification='Verified' THEN
      -- r3 (R3-02): the only permitted change is the referential action
      -- ON DELETE SET NULL (supersedes_id) fired by deleting the superseded candidate.
      -- pg_trigger_depth() > 1 means we run inside the RI trigger, not a direct UPDATE.
      IF pg_trigger_depth() > 1 AND OLD.supersedes_id IS NOT NULL AND NEW.supersedes_id IS NULL
         AND (to_jsonb(NEW) - 'supersedes_id') = (to_jsonb(OLD) - 'supersedes_id') THEN
        RETURN NEW;
      END IF;
      RAISE EXCEPTION 'verified memory is immutable';
    END IF;
    IF NEW.verification='Verified' THEN
      RAISE EXCEPTION 'verification requires a new Owner memory row';
    END IF;
  END IF;
  IF NEW.verification='Verified' THEN
    IF NEW.source_kind <> 'Owner' OR NEW.supersedes_id IS NULL
       OR NEW.verified_by IS NULL OR NEW.verified_at IS NULL THEN
      RAISE EXCEPTION 'Verified requires a new Owner row superseding a candidate';
    END IF;
    SELECT kind INTO k FROM principals WHERE tenant_id=NEW.tenant_id AND id=NEW.verified_by;
    IF k IS DISTINCT FROM 'TenantOwner' THEN
      RAISE EXCEPTION 'Verified requires TenantOwner principal';
    END IF;
  END IF;
  RETURN NEW;
END $$;

-- RT-046: object pointer may reference only a published version belonging to
-- the same tenant/object. DEFERRABLE FK remains for transactional publication.
CREATE FUNCTION object_published_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st TEXT;
BEGIN
  IF NEW.published_version_id IS NULL THEN
    IF NEW.state IN ('active','suspended') THEN RAISE EXCEPTION 'active object requires published version'; END IF;
    RETURN NEW;
  END IF;
  SELECT status INTO st FROM object_versions
   WHERE tenant_id=NEW.tenant_id AND object_id=NEW.object_id AND object_version_id=NEW.published_version_id;
  IF st IS DISTINCT FROM 'published' THEN
    RAISE EXCEPTION 'published_version_id must point to a published version';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_object_published_pointer_guard
  BEFORE INSERT OR UPDATE OF state,published_version_id,tenant_id,object_id ON objects
  FOR EACH ROW EXECUTE FUNCTION object_published_pointer_guard();

-- Knowledge chunks cannot be inserted with invented active intervals. A chunk
-- created for staged/indexed docs is interval-free; live/retired docs must match.
CREATE FUNCTION knowledge_chunk_interval_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE d knowledge_documents%ROWTYPE;
BEGIN
  SELECT * INTO d FROM knowledge_documents
   WHERE tenant_id=NEW.tenant_id AND object_id=NEW.object_id AND id=NEW.document_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'knowledge document not found'; END IF;
  IF d.status IN ('staged','indexed') THEN
    IF NEW.valid_from_revision IS NOT NULL OR NEW.valid_to_revision IS NOT NULL THEN
      RAISE EXCEPTION 'staged/indexed document chunks must have NULL revision interval';
    END IF;
  ELSIF (NEW.valid_from_revision,NEW.valid_to_revision) IS DISTINCT FROM
        (d.valid_from_revision,d.valid_to_revision) THEN
    RAISE EXCEPTION 'chunk interval must match parent document';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_knowledge_chunk_interval_insert_guard
  BEFORE INSERT ON knowledge_chunks FOR EACH ROW
  EXECUTE FUNCTION knowledge_chunk_interval_insert_guard();

-- ToolExecution owns an independent optimistic version and lease fence.
-- The initial Authorized -> Executing CAS acquires the lease and advances both
-- counters atomically. Heartbeats keep the same owner/token/version. An expired
-- execution cannot be stolen and replayed: it must become Unknown for reconciliation.
CREATE FUNCTION tool_execution_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  status_changed BOOLEAN;
  token_changed BOOLEAN;
  heartbeat_only BOOLEAN;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'Authorized' OR NEW.version <> 0 OR NEW.fencing_token <> 0
       OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.heartbeat_at IS NOT NULL OR NEW.finished_at IS NOT NULL THEN
      RAISE EXCEPTION 'new tool execution must start Authorized at version/token zero without a lease'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status IN ('Succeeded','Failed') THEN
    -- retention_purge may only null output bytes and their expiry on terminal rows.
    IF current_user = 'qembed_definer'
       AND NEW.output IS NULL AND NEW.output_expires_at IS NULL
       AND (to_jsonb(NEW) - 'output' - 'output_expires_at')
         = (to_jsonb(OLD) - 'output' - 'output_expires_at') THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'terminal tool execution is immutable' USING ERRCODE = '55000';
  END IF;

  IF (NEW.id, NEW.tenant_id, NEW.object_id, NEW.invocation_id, NEW.caller_id,
      NEW.decision_id, NEW.decision, NEW.command_id, NEW.tool_id, NEW.tool_version_id,
      NEW.snapshot_id, NEW.binding_version, NEW.operation, NEW.arguments_hash,
      NEW.created_at, NEW.external_idempotency_key)
     IS DISTINCT FROM
     (OLD.id, OLD.tenant_id, OLD.object_id, OLD.invocation_id, OLD.caller_id,
      OLD.decision_id, OLD.decision, OLD.command_id, OLD.tool_id, OLD.tool_version_id,
      OLD.snapshot_id, OLD.binding_version, OLD.operation, OLD.arguments_hash,
      OLD.created_at, OLD.external_idempotency_key) THEN
    RAISE EXCEPTION 'tool execution identity is immutable' USING ERRCODE = '55000';
  END IF;

  status_changed := NEW.status IS DISTINCT FROM OLD.status;
  token_changed := NEW.fencing_token IS DISTINCT FROM OLD.fencing_token;

  IF status_changed AND NOT (
       (OLD.status = 'Authorized' AND NEW.status IN ('Executing','Failed'))
    OR (OLD.status = 'Executing' AND NEW.status IN ('Succeeded','Failed','Unknown'))
    OR (OLD.status = 'Unknown' AND NEW.status IN ('Succeeded','Failed'))
  ) THEN
    RAISE EXCEPTION 'invalid tool execution state transition: % -> %', OLD.status, NEW.status
      USING ERRCODE = '23514';
  END IF;

  IF status_changed THEN
    IF NEW.version::numeric <> OLD.version::numeric + 1 THEN
      RAISE EXCEPTION 'tool execution version must advance exactly once per state transition'
        USING ERRCODE = '40001';
    END IF;
  ELSIF NEW.version <> OLD.version THEN
    RAISE EXCEPTION 'tool execution version changed without a state transition'
      USING ERRCODE = '40001';
  END IF;

  IF OLD.status = 'Authorized' AND NEW.status = 'Executing' THEN
    IF NEW.fencing_token::numeric <> OLD.fencing_token::numeric + 1
       OR NEW.lease_owner IS NULL OR NEW.lease_until <= clock_timestamp()
       OR NEW.heartbeat_at IS NULL OR NEW.finished_at IS NOT NULL
       OR NEW.reconciliation_state IS NOT NULL THEN
      RAISE EXCEPTION 'claim must acquire a live lease and advance the execution fencing token'
        USING ERRCODE = '23514';
    END IF;
  ELSIF token_changed THEN
    RAISE EXCEPTION 'tool execution fencing token may change only on initial lease acquisition'
      USING ERRCODE = '40001';
  END IF;

  IF OLD.status = 'Executing' AND NEW.status IN ('Succeeded','Failed') THEN
    IF OLD.lease_until <= clock_timestamp() OR OLD.lease_owner IS NULL
       OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.heartbeat_at IS NOT NULL THEN
      RAISE EXCEPTION 'an expired or unowned execution lease cannot commit a result'
        USING ERRCODE = '40001';
    END IF;
  ELSIF OLD.status = 'Executing' AND NEW.status = 'Unknown' THEN
    IF OLD.lease_until > clock_timestamp()
       OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.heartbeat_at IS NOT NULL
       OR NEW.reconciliation_state IS DISTINCT FROM 'pending' THEN
      RAISE EXCEPTION 'an execution becomes Unknown only after lease expiry and enters pending reconciliation'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.status = 'Unknown' AND NEW.status IN ('Succeeded','Failed') THEN
    IF NEW.reconciliation_state IS NULL
       OR NEW.reconciliation_state NOT IN ('confirmed_succeeded','confirmed_failed')
       OR (NEW.status = 'Succeeded') <> (NEW.reconciliation_state = 'confirmed_succeeded') THEN
      RAISE EXCEPTION 'Unknown can become terminal only through matching confirmed reconciliation'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.status = 'Authorized' AND NEW.status = 'Failed' THEN
    IF NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
       OR NEW.heartbeat_at IS NOT NULL THEN
      RAISE EXCEPTION 'an unclaimed execution cannot finish with a lease'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF OLD.status = 'Executing' AND NEW.status = 'Executing' THEN
    heartbeat_only :=
      (to_jsonb(NEW) - 'lease_until' - 'heartbeat_at')
      = (to_jsonb(OLD) - 'lease_until' - 'heartbeat_at');
    IF NOT heartbeat_only OR OLD.lease_until <= clock_timestamp()
       OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
       OR NEW.fencing_token <> OLD.fencing_token
       OR NEW.lease_until <= OLD.lease_until
       OR NEW.lease_until <= clock_timestamp()
       OR NEW.heartbeat_at IS NULL OR NEW.heartbeat_at < OLD.heartbeat_at THEN
      RAISE EXCEPTION 'heartbeat must extend the current live lease without changing execution state'
        USING ERRCODE = '40001';
    END IF;
  ELSIF NOT status_changed AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'tool execution fields are immutable outside a state transition or lease heartbeat'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END $$;
CREATE TRIGGER trg_tool_execution_state_guard
  BEFORE INSERT OR UPDATE ON tool_executions FOR EACH ROW
  EXECUTE FUNCTION tool_execution_state_guard();

-- RT-042: explicitly ensure definer remains non-login, non-superuser, no bypass.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qembed_definer'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'qembed_definer must be NOLOGIN NOSUPERUSER NOBYPASSRLS';
  END IF;
END $$;

COMMIT;
