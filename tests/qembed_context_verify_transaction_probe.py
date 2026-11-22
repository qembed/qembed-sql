#!/usr/bin/env python3
"""External JCS/Ed25519 issuer probe for the qctx1 PostgreSQL token contract."""

import ctypes
import ctypes.util
import datetime as dt
import uuid

import psycopg2
import rfc8785
from psycopg2 import Binary

ISSUER = "urn:qembed:context-issuer:probe"
DEPLOYMENT = "probe-deployment-1"
KEY_ID = "external-test-key-1"
STAGED_KEY_ID = "external-staged-key"
AUDIENCE_PREFIX = "urn:qembed:postgres:deployment:"
TENANT_A = "10000000-0000-0000-0000-000000000001"
TENANT_B = "10000000-0000-0000-0000-000000000002"
PRINCIPAL = "20000000-0000-0000-0000-000000000001"
CALLER = "30000000-0000-0000-0000-000000000001"


def connect():
    return psycopg2.connect(dbname="postgres", user="postgres", host="/var/run/postgresql")


def load_sodium():
    library = ctypes.util.find_library("sodium")
    if not library:
        raise RuntimeError("libsodium shared library not found")
    sodium = ctypes.CDLL(library)
    sodium.sodium_init.restype = ctypes.c_int
    sodium.crypto_sign_keypair.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
    ]
    sodium.crypto_sign_keypair.restype = ctypes.c_int
    sodium.crypto_sign_detached.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulonglong,
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    sodium.crypto_sign_detached.restype = ctypes.c_int
    if sodium.sodium_init() < 0:
        raise RuntimeError("libsodium initialization failed")
    return sodium


def make_signer(sodium):
    public_key = (ctypes.c_ubyte * 32)()
    secret_key = (ctypes.c_ubyte * 64)()
    if sodium.crypto_sign_keypair(public_key, secret_key) != 0:
        raise RuntimeError("Ed25519 keypair generation failed")

    def sign(payload):
        message = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        signature = (ctypes.c_ubyte * 64)()
        signature_len = ctypes.c_ulonglong()
        result = sodium.crypto_sign_detached(
            signature, ctypes.byref(signature_len), message, len(payload), secret_key
        )
        if result != 0 or signature_len.value != 64:
            raise RuntimeError("Ed25519 signing failed")
        return bytes(signature)

    return bytes(public_key), secret_key, sign


def utc_text(value):
    # Match time::format_description::well_known::Rfc3339 used by Rust:
    # UTC with no fractional part when microseconds are zero, otherwise trim
    # trailing fractional zeroes.
    value = value.astimezone(dt.timezone.utc)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = f"{value.microsecond:06d}".rstrip("0")
    if fraction:
        text += "." + fraction
    return text + "Z"


def make_envelope(payload, signature):
    return f"qctx1:{payload.hex()}:{signature.hex()}"


def issue_token(cursor, sign, overrides=None):
    cursor.execute(
        "SELECT pg_backend_pid(), pg_current_xact_id()::text, "
        "(SELECT oid::text FROM pg_database WHERE datname = current_database())"
    )
    backend_pid, transaction_id, database_oid = cursor.fetchone()
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "version": "1",
        "tenant_id": TENANT_A,
        "principal_id": PRINCIPAL,
        "caller_id": CALLER,
        "backend_pid": str(backend_pid),
        "transaction_id": str(transaction_id),
        "database_oid": str(database_oid),
        "deployment_id": DEPLOYMENT,
        "issuer": ISSUER,
        "audience": f"{AUDIENCE_PREFIX}{DEPLOYMENT}:database:{database_oid}",
        "key_id": KEY_ID,
        "issued_at": utc_text(now),
        "expires_at": utc_text(now + dt.timedelta(seconds=30)),
        "nonce": str(uuid.uuid4()),
    }
    if overrides:
        claims.update(overrides)

    # RFC 8785 JCS, not Python's json.dumps(sort_keys=True): the Rust issuer
    # signs serde_jcs bytes and PostgreSQL verifies those exact original bytes.
    payload = rfc8785.dumps(claims)
    signature = sign(payload)
    return payload, signature, claims, make_envelope(payload, signature)


def verify(cursor, token):
    cursor.execute("SELECT qembed_crypto.verified_context(%s)", (token,))
    return cursor.fetchone()[0]


def assert_invalid(
    cursor, sign, label, overrides=None, payload_override=None, signature_override=None
):
    if payload_override is not None:
        payload = payload_override
        signature = signature_override
        token = make_envelope(payload, signature)
    else:
        _, _, _, token = issue_token(cursor, sign, overrides)
    result = verify(cursor, token)
    if result is not None:
        raise AssertionError(f"invalid context accepted: {label}")


def main():
    sodium = load_sodium()
    public_key, secret_key, sign = make_signer(sodium)
    del secret_key  # The private key remains only in the external issuer process.

    admin = connect()
    admin.autocommit = True
    with admin.cursor() as cursor:
        for role_name, expected in (
            ("qembed_key_control_plane", (False, False, False, False, False, False, True)),
            ("qembed_key_registry_owner", (False, False, False, False, False, False, False)),
            ("qembed_key_audit_exporter", (False, False, False, False, False, False, True)),
            ("qembed_runtime", (False, False, False, False, False, False, False)),
        ):
            cursor.execute(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
                "rolbypassrls, rolinherit, rolcanlogin FROM pg_roles WHERE rolname = %s",
                (role_name,),
            )
            if cursor.fetchone() != expected:
                raise AssertionError(f"database role {role_name} has unsafe attributes")

        cursor.execute("SELECT oid::text FROM pg_database WHERE datname = current_database()")
        database_oid = cursor.fetchone()[0]
        audience = f"{AUDIENCE_PREFIX}{DEPLOYMENT}:database:{database_oid}"

        cursor.execute("SET SESSION AUTHORIZATION qembed_key_control_plane")
        cursor.execute(
            "SELECT has_table_privilege(current_user, "
            "'qembed_crypto.verification_keys', 'SELECT'), "
            "has_table_privilege(current_user, "
            "'qembed_crypto.verification_keys', 'INSERT'), "
            "has_table_privilege(current_user, "
            "'qembed_crypto.key_lifecycle_audit', 'SELECT'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.stage_verification_key(text,bytea,text,text,text,text,uuid,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.list_verification_keys(text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.get_key_lifecycle_operation(uuid)', 'EXECUTE')"
        )
        can_read_keys, can_insert_keys, can_read_audit, can_stage, can_list, can_read_operation = cursor.fetchone()
        if can_read_keys or can_insert_keys or can_read_audit or not can_stage or not can_list or not can_read_operation:
            raise AssertionError("control plane must use narrow management/read functions, not direct table access")

        primary_stage_request_id = str(uuid.uuid4())
        cursor.execute(
            "SELECT qembed_crypto.stage_verification_key(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                KEY_ID, Binary(public_key), ISSUER, audience, DEPLOYMENT,
                "operator:test-operator", primary_stage_request_id, "test-only key staging",
            ),
        )
        # Repeating the same request ID and payload is idempotent.
        cursor.execute(
            "SELECT qembed_crypto.stage_verification_key(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                KEY_ID, Binary(public_key), ISSUER, audience, DEPLOYMENT,
                "operator:test-operator", primary_stage_request_id, "test-only key staging",
            ),
        )
        try:
            cursor.execute(
                "SELECT qembed_crypto.stage_verification_key(%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    KEY_ID, Binary(public_key), ISSUER, audience, DEPLOYMENT,
                    "operator:test-operator", primary_stage_request_id, "different payload must fail",
                ),
            )
            raise AssertionError("idempotency key must be bound to the original request payload")
        except psycopg2.errors.RaiseException:
            pass
        cursor.execute(
            "SELECT qembed_crypto.stage_verification_key(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                STAGED_KEY_ID, Binary(public_key), ISSUER, audience, DEPLOYMENT,
                "operator:test-operator", str(uuid.uuid4()), "test-only staged key",
            ),
        )
        try:
            cursor.execute(
                "SELECT qembed_crypto.activate_verification_key(%s, %s, %s, %s, %s)",
                (
                    STAGED_KEY_ID, "operator:same-subject", "operator:same-subject",
                    str(uuid.uuid4()), "same-subject activation must fail",
                ),
            )
            raise AssertionError("key activation must require a distinct approver")
        except psycopg2.errors.RaiseException:
            pass

        try:
            cursor.execute(
                "INSERT INTO qembed_crypto.verification_keys "
                "(key_id, public_key, issuer, audience, deployment_id) "
                "VALUES (%s, %s, %s, %s, %s)",
                ("forbidden-direct-insert", Binary(public_key), ISSUER, audience, DEPLOYMENT),
            )
            raise AssertionError("control plane must not insert directly into the key registry")
        except psycopg2.errors.InsufficientPrivilege:
            pass

        cursor.execute(
            "SELECT qembed_crypto.activate_verification_key(%s, %s, %s, %s, %s)",
            (
                KEY_ID, "operator:test-operator", "approver:test-approver",
                str(uuid.uuid4()), "test-only key activation",
            ),
        )
        cursor.execute(
            "SELECT key_id, status FROM qembed_crypto.list_verification_keys(%s) "
            "WHERE key_id IN (%s, %s) ORDER BY key_id",
            (DEPLOYMENT, KEY_ID, STAGED_KEY_ID),
        )
        key_rows = cursor.fetchall()
        if {row[0]: row[1] for row in key_rows} != {KEY_ID: "active", STAGED_KEY_ID: "staged"}:
            raise AssertionError("control-plane metadata reader returned incorrect key states")
        cursor.execute(
            "SELECT operation, new_state, audit_export_status "
            "FROM qembed_crypto.get_key_lifecycle_operation(%s)",
            (primary_stage_request_id,),
        )
        if cursor.fetchone() != ("stage", "staged", "pending"):
            raise AssertionError("control-plane audit reader returned incorrect lifecycle/export evidence")
        cursor.execute("RESET SESSION AUTHORIZATION")
        cursor.execute(
            "SELECT event_id FROM qembed_crypto.key_lifecycle_audit ORDER BY event_id LIMIT 1"
        )
        audit_event_id = cursor.fetchone()[0]
        if audit_event_id is None:
            raise AssertionError("key lifecycle audit should contain the staged/activated events")
        try:
            cursor.execute(
                "UPDATE qembed_crypto.key_lifecycle_audit SET reason = 'tampered' "
                "WHERE event_id = %s",
                (audit_event_id,),
            )
            raise AssertionError("key lifecycle audit must be append-only")
        except psycopg2.errors.RaiseException:
            pass
    admin.close()

    exporter = connect()
    exporter.autocommit = True
    with exporter.cursor() as cursor:
        cursor.execute("SET SESSION AUTHORIZATION qembed_key_audit_exporter")
        cursor.execute(
            "SELECT has_table_privilege(current_user, "
            "'qembed_crypto.key_lifecycle_audit', 'SELECT'), "
            "has_table_privilege(current_user, "
            "'qembed_crypto.key_lifecycle_audit_outbox', 'SELECT'), "
            "has_table_privilege(current_user, "
            "'qembed_crypto.key_lifecycle_audit_outbox', 'UPDATE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.list_pending_key_audit_exports(integer)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.mark_key_audit_exported(bigint,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.record_key_audit_export_failure(bigint,text)', 'EXECUTE')"
        )
        can_read_audit, can_read_outbox, can_update_outbox, can_list, can_mark, can_record_failure = cursor.fetchone()
        if can_read_audit or can_read_outbox or can_update_outbox or not can_list or not can_mark or not can_record_failure:
            raise AssertionError("audit exporter must use only its restricted outbox functions")

        cursor.execute(
            "SELECT event_id, request_id, operation "
            "FROM qembed_crypto.list_pending_key_audit_exports(%s)",
            (100,),
        )
        pending = cursor.fetchall()
        if len(pending) != 3:
            raise AssertionError(f"expected three transactional audit outbox events, got {len(pending)}")

        delivered_event_id = pending[0][0]
        cursor.execute(
            "SELECT qembed_crypto.mark_key_audit_exported(%s, %s)",
            (delivered_event_id, "test-sink-receipt-1"),
        )
        delivered_at = cursor.fetchone()[0]
        cursor.execute(
            "SELECT qembed_crypto.mark_key_audit_exported(%s, %s)",
            (delivered_event_id, "test-sink-receipt-1"),
        )
        if cursor.fetchone()[0] != delivered_at:
            raise AssertionError("audit export acknowledgement must be idempotent")

        failed_event_id = pending[1][0]
        cursor.execute(
            "SELECT qembed_crypto.record_key_audit_export_failure(%s, %s)",
            (failed_event_id, "temporary test sink outage"),
        )
        if cursor.fetchone()[0] != 1:
            raise AssertionError("audit export failure should increment the retry counter")

        cursor.execute(
            "SELECT event_id, attempt_count FROM qembed_crypto.list_pending_key_audit_exports(%s)",
            (100,),
        )
        pending_after_delivery = cursor.fetchall()
        if len(pending_after_delivery) != 2 or (failed_event_id, 1) not in pending_after_delivery:
            raise AssertionError("outbox should retain failed delivery for retry and hide acknowledged event")
        cursor.execute("RESET SESSION AUTHORIZATION")
    exporter.close()

    connection = connect()
    cursor = connection.cursor()
    try:
        payload, signature, claims, token = issue_token(cursor, sign)
        cursor.execute("SELECT set_config('app.context_token', %s, true)", (token,))
        cursor.execute(
            "SELECT set_config('app.tenant_id', %s, true), "
            "set_config('app.principal_id', %s, true), "
            "set_config('app.caller_id', %s, true)",
            (TENANT_B, TENANT_B, TENANT_B),
        )
        cursor.execute("SET ROLE qembed_runtime")

        if verify(cursor, token) != claims:
            raise AssertionError("valid RFC 8785/JCS token was not accepted")

        assert_invalid(cursor, sign, "staged key", overrides={"key_id": STAGED_KEY_ID})
        cursor.execute(
            "SELECT qembed_crypto.current_tenant_id(), "
            "qembed_crypto.current_principal_id(), qembed_crypto.current_caller_id()"
        )
        if tuple(str(value) for value in cursor.fetchone()) != (TENANT_A, PRINCIPAL, CALLER):
            raise AssertionError("typed claim accessors returned incorrect signed identities")

        cursor.execute(
            "SELECT count(*), bool_and(tenant_id = %s::uuid) "
            "FROM qembed_crypto.tenant_rows",
            (TENANT_A,),
        )
        row_count, only_signed_tenant = cursor.fetchone()
        if row_count != 5 or not only_signed_tenant:
            raise AssertionError("RLS trusted a forged identity GUC instead of signed tenant claim")

        cursor.execute(
            "EXPLAIN (FORMAT JSON) SELECT count(*) FROM qembed_crypto.tenant_rows"
        )
        rls_plan = cursor.fetchone()[0]
        if "InitPlan" not in str(rls_plan):
            raise AssertionError(f"RLS did not evaluate the signed context once as an InitPlan: {rls_plan}")

        cursor.execute(
            "SELECT has_table_privilege(current_user, "
            "'qembed_crypto.verification_keys', 'SELECT'), "
            "has_table_privilege(current_user, "
            "'qembed_crypto.key_lifecycle_audit', 'SELECT'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.qembed_context_verify_detached(bytea,bytea,bytea)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.stage_verification_key(text,bytea,text,text,text,text,uuid,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.activate_verification_key(text,text,text,uuid,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.retire_verification_key(text,interval,text,text,uuid,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.revoke_verification_key(text,text,uuid,text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.list_verification_keys(text)', 'EXECUTE'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.get_key_lifecycle_operation(uuid)', 'EXECUTE')"
        )
        privileges = cursor.fetchone()
        if any(privileges):
            raise AssertionError("runtime has key registry, audit, low-level verifier, management, metadata-reader or audit-export privileges")

        tampered = bytearray(signature)
        tampered[0] ^= 1
        assert_invalid(
            cursor, sign, "modified signature",
            payload_override=payload, signature_override=bytes(tampered)
        )
        assert_invalid(
            cursor, sign, "modified payload",
            payload_override=payload + b" ", signature_override=signature
        )
        if verify(cursor, token.replace("qctx1:", "qctx2:", 1)) is not None:
            raise AssertionError("unknown envelope version was accepted")
        for malformed in (
            "qctx1:not-hex:" + ("00" * 64),
            "qctx1:" + payload.hex()[:-1] + ":" + signature.hex(),
            "qctx1:" + payload.hex() + ":00",
            "QCTX1:" + payload.hex() + ":" + signature.hex(),
        ):
            if verify(cursor, malformed) is not None:
                raise AssertionError("malformed token envelope was accepted")
        assert_invalid(cursor, sign, "malformed signed JSON", payload_override=b"not-json", signature_override=sign(b"not-json"))
        assert_invalid(cursor, sign, "unknown claim", {"unexpected_claim": "not-allowed"})
        assert_invalid(cursor, sign, "unknown key", {"key_id": "not-registered"})
        assert_invalid(cursor, sign, "wrong backend", {"backend_pid": str(int(claims["backend_pid"]) + 1)})
        assert_invalid(cursor, sign, "wrong transaction", {"transaction_id": str(int(claims["transaction_id"]) + 1)})
        assert_invalid(cursor, sign, "wrong database", {"database_oid": str(int(database_oid) + 1)})
        other_deployment = "another-deployment"
        assert_invalid(cursor, sign, "wrong deployment", {
            "deployment_id": other_deployment,
            "audience": f"{AUDIENCE_PREFIX}{other_deployment}:database:{database_oid}",
        })
        assert_invalid(cursor, sign, "wrong issuer", {"issuer": "urn:attacker:issuer"})
        assert_invalid(cursor, sign, "wrong version", {"version": "2"})
        assert_invalid(cursor, sign, "invalid nonce", {"nonce": "not-a-uuid"})
        expired_now = dt.datetime.now(dt.timezone.utc)
        assert_invalid(cursor, sign, "expired token", {
            "issued_at": utc_text(expired_now - dt.timedelta(minutes=2)),
            "expires_at": utc_text(expired_now - dt.timedelta(minutes=1)),
        })

        # Verify PostgreSQL accepts the maximum envelope size implied by the
        # protocol's 8 KiB payload bound. Restore the valid token immediately.
        max_payload_token = "qctx1:" + ("00" * 8192) + ":" + ("00" * 64)
        cursor.execute("SELECT length(set_config('app.context_token', %s, true))", (max_payload_token,))
        if cursor.fetchone()[0] != len(max_payload_token):
            raise AssertionError("PostgreSQL truncated the maximum-size context token")
        cursor.execute("SELECT set_config('app.context_token', %s, true)", (token,))

        cursor.execute("SAVEPOINT rt050_savepoint")
        cursor.execute("SELECT set_config('app.caller_id', %s, true)", (TENANT_B,))
        cursor.execute("ROLLBACK TO SAVEPOINT rt050_savepoint")
        if verify(cursor, token) != claims:
            raise AssertionError("savepoint rollback invalidated the outer transaction context")

        cursor.execute("RESET ROLE")
        connection.commit()

        # A committed token must fail in the next transaction on the same backend.
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, token) is not None:
            raise AssertionError("committed token replayed in the next transaction")
        cursor.execute("RESET ROLE")
        connection.commit()

        # A token from a rolled-back transaction must fail in the following transaction.
        _, _, rollback_claims, rollback_token = issue_token(cursor, sign)
        cursor.execute("SELECT set_config('app.context_token', %s, true)", (rollback_token,))
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, rollback_token) != rollback_claims:
            raise AssertionError("valid token in rollback test transaction was rejected")
        cursor.execute("RESET ROLE")
        connection.rollback()
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, rollback_token) is not None:
            raise AssertionError("rolled-back token replayed in the next transaction")
        cursor.execute("RESET ROLE")
        connection.commit()

        # A second backend must reject the original committed token.
        other = connect()
        other_cursor = other.cursor()
        other_cursor.execute("SET ROLE qembed_runtime")
        if verify(other_cursor, token) is not None:
            raise AssertionError("token from another backend was accepted")
        other_cursor.execute("RESET ROLE")
        other.rollback()
        other_cursor.close()
        other.close()

        # pg_current_xact_id() and the signed context must work in READ ONLY.
        connection.set_session(readonly=True)
        _, _, read_only_claims, read_only_token = issue_token(cursor, sign)
        cursor.execute("SELECT set_config('app.context_token', %s, true)", (read_only_token,))
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, read_only_token) != read_only_claims:
            raise AssertionError("read-only transaction context was rejected")
        cursor.execute("SELECT count(*) FROM qembed_crypto.tenant_rows")
        if cursor.fetchone()[0] != 5:
            raise AssertionError("read-only RLS query returned wrong tenant rows")
        cursor.execute("RESET ROLE")
        connection.commit()

        print(
            "PASS: qctx1 envelope, RFC 8785/JCS, typed claims, signature, transaction/backend "
            "binding, replay, savepoint, READ ONLY, RLS, least privilege, and GUC capacity"
        )
    finally:
        cursor.close()
        connection.close()

    cleanup = connect()
    cleanup.autocommit = True
    with cleanup.cursor() as cursor:
        cursor.execute("DROP SCHEMA qembed_crypto CASCADE")
        cursor.execute("DROP ROLE qembed_runtime")
    cleanup.close()


if __name__ == "__main__":
    main()
