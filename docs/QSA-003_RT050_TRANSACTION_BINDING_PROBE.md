# QSA-003 / RT-050 — transaction-binding feasibility probe

**Status:** Prototype only; no production DDL, no RLS migration, and no Rust API change.

## What the probe exercises

The companion workflow first builds and loads the pinned pgsodium source on PostgreSQL 19, then runs a test-only verifier with a generated Ed25519 keypair. The private key is held only by the privileged test session; the runtime role receives no signing or key-table privileges.

The signed payload contains tenant, Principal and Caller IDs plus:

- PostgreSQL backend PID;
- `pg_current_xact_id()` transaction identifier;
- current database OID;
- a provisioned deployment identifier and exact audience;
- issuer, key ID, issued-at, expiry and nonce.

The test-only `SECURITY DEFINER` verifier pins its `search_path` with `pg_temp` last. It verifies the detached signature before trusting claims, resolves the key ID only against a private verification-key table, and compares the signed binding to the current backend, transaction, database and provisioned deployment configuration.

## Negative and positive cases

The workflow asserts that:

1. a correctly signed token is accepted in the transaction for which it was issued;
2. forged legacy `app.tenant_id`, `app.principal_id` and `app.caller_id` settings do not alter the verified claims;
3. a modified signature is rejected;
4. a correctly signed token for another backend PID is rejected;
5. a correctly signed token for another database OID is rejected;
6. a correctly signed token for another deployment/audience is rejected;
7. an expired token is rejected;
8. a token from a committed or rolled-back transaction is rejected in the next transaction on the same backend;
9. a savepoint rollback preserves the valid outer-transaction context;
10. `pg_current_xact_id()` can be obtained inside a `READ ONLY` transaction;
11. a token from another independent connection/backend is rejected;
12. the runtime role cannot read verification-key metadata or execute the signing function.

Catalog assertions verify that the test verifier is `SECURITY DEFINER` and has a fixed safe search path with `pg_temp` last.

## RLS verification cost and InitPlan

The probe creates two test-only RLS policies over identical 10,000-row tables (5,000 rows for the signed tenant, 5,000 for another tenant):

- direct predicate: `tenant_id = qsa003_probe.context_tenant_id()`;
- statement-level predicate: `tenant_id = (SELECT qsa003_probe.context_tenant_id())`.

The second form produced an explicit PostgreSQL `InitPlan`, evaluating the context function once for the statement rather than once per scanned row.

Observed on the PostgreSQL 19 CI container, without a tenant index:

| Policy form | Execution time | Shared buffer hits |
|---|---:|---:|
| Direct verifier call | 855.463 ms | 30,064 |
| Uncorrelated scalar subquery / InitPlan | 1.143 ms | 67 |

This is approximately 748x in this small test and is not a general production benchmark. It demonstrates that RLS policy shape is critical: production policies must preserve an equivalent one-verification-per-statement plan shape. The production policy migration and workload-specific benchmark are still outstanding.

## pgsodium preload requirement

The CI environment preloads pgsodium through `shared_preload_libraries` and installs the test-only `tests/pgsodium_getkey_test.sh` provider. This was necessary because pgsodium defines `pgsodium.enable_event_trigger` during shared preload; without preload, its DDL event trigger failed on table creation with an unrecognized-setting error. The preload path also requires a getkey script and loads a root key into server memory. The probe's provider creates only an ephemeral key inside the disposable CI container; it is not a production key-management recommendation.

Production adoption must explicitly evaluate the global preload/restart requirement, secure root-key provisioning, rotation, recovery and operational ownership. The Ed25519 verification probe itself uses raw public-key verification and does not use the pgsodium root key.

## What this does not prove

This is a feasibility experiment, not an implementation of RT-050:

- Token issuance is simulated in a privileged SQL test session. It does not validate a real external Context Issuer, its authentication, or its private-key isolation.
- The deployment ID is a provisioned test value. Production must define how it is securely provisioned and bound to the exact PostgreSQL cluster/database; database OID alone is not a cluster identity.
- The probe verifies replay rejection after both COMMIT and ROLLBACK on the same backend, confirms that a savepoint rollback preserves the valid outer-transaction context, and checks that `pg_current_xact_id()` can be obtained in a `READ ONLY` transaction. Retry orchestration and full connection-pool lifecycle integration remain outstanding.
- The RLS tables/policies are test fixtures only. The probe does not replace identity GUCs in production policies, prove end-to-end tenant isolation against arbitrary SQL, or establish performance on production data/indexes/concurrency.
- It does not test Caller delegation lookup/revocation races, key rotation/revocation, issuer outage, token canonicalization across Rust and SQL, or a complete Rust transaction API.
- It does not establish that `pg_current_xact_id()` is operationally acceptable for every read-only workload; it intentionally tests the function's actual behavior on the PostgreSQL 19 target.

A green run is evidence for the narrow verifier/binding predicate only. QSA-003 remains `DOCUMENTED_RISK`; RT-050 remains proposed until the missing cases, issuer/Rust integration, RLS migration and explicit owner approval are complete.