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
8. a token from a committed transaction is rejected in the next transaction on the same backend;
9. a token from another independent connection/backend is rejected;
10. the runtime role cannot read verification-key metadata or execute the signing function.

Catalog assertions verify that the test verifier is `SECURITY DEFINER` and has a fixed safe search path with `pg_temp` last.

## What this does not prove

This is a feasibility experiment, not an implementation of RT-050:

- Token issuance is simulated in a privileged SQL test session. It does not validate a real external Context Issuer, its authentication, or its private-key isolation.
- The deployment ID is a provisioned test value. Production must define how it is securely provisioned and bound to the exact PostgreSQL cluster/database; database OID alone is not a cluster identity.
- The probe verifies replay rejection after both COMMIT and ROLLBACK on the same backend, and checks that `pg_current_xact_id()` can be obtained in a `READ ONLY` transaction. Savepoint behavior, retry orchestration, and full connection-pool lifecycle integration remain outstanding.
- The probe does not replace identity GUCs in production RLS policies and does not prove end-to-end tenant isolation against arbitrary SQL.
- It does not test Caller delegation lookup/revocation races, key rotation/revocation, issuer outage, token canonicalization across Rust and SQL, or a complete Rust transaction API.
- It does not establish that `pg_current_xact_id()` is operationally acceptable for every read-only workload; it intentionally tests the function's actual behavior on the PostgreSQL 19 target.

A green run is evidence for the narrow verifier/binding predicate only. QSA-003 remains `DOCUMENTED_RISK`; RT-050 remains proposed until the missing cases, issuer/Rust integration, RLS migration and explicit owner approval are complete.