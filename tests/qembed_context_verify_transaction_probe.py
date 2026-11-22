#!/usr/bin/env python3
"""External test issuer for the minimal Ed25519 PostgreSQL verifier."""

import ctypes
import ctypes.util
import datetime as dt
import json
import uuid

import psycopg2
from psycopg2 import Binary

ISSUER = "urn:qembed:context-issuer:probe"
DEPLOYMENT = "probe-deployment-1"
KEY_ID = "external-test-key-1"
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
    return value.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def issue_token(cursor, sign, overrides=None):
    cursor.execute(
        "SELECT pg_backend_pid(), pg_current_xact_id()::text, "
        "(SELECT oid::text FROM pg_database WHERE datname = current_database())"
    )
    backend_pid, transaction_id, database_oid = cursor.fetchone()
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
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
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return payload, sign(payload), claims


def verify(cursor, payload, signature):
    cursor.execute(
        "SELECT qembed_crypto.verified_context(%s, %s)",
        (Binary(payload), Binary(signature)),
    )
    return cursor.fetchone()[0]


def assert_invalid(cursor, sign, label, overrides=None, payload_override=None, signature_override=None):
    if payload_override is not None:
        payload, signature = payload_override, signature_override
    else:
        payload, signature, _ = issue_token(cursor, sign, overrides)
    result = verify(cursor, payload, signature)
    if result is not None:
        raise AssertionError(f"invalid context accepted: {label}")


def main():
    sodium = load_sodium()
    public_key, secret_key, sign = make_signer(sodium)
    del secret_key  # The private key remains only in the external issuer process.

    admin = connect()
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute("SELECT oid::text FROM pg_database WHERE datname = current_database()")
        database_oid = cursor.fetchone()[0]
        audience = f"{AUDIENCE_PREFIX}{DEPLOYMENT}:database:{database_oid}"
        cursor.execute(
            "INSERT INTO qembed_crypto.verification_keys "
            "(key_id, public_key, issuer, audience, deployment_id) VALUES (%s, %s, %s, %s, %s)",
            (KEY_ID, Binary(public_key), ISSUER, audience, DEPLOYMENT),
        )
    admin.close()

    connection = connect()
    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN")
        payload, signature, claims = issue_token(cursor, sign)
        cursor.execute(
            "SELECT set_config('app.context_payload', %s, true), "
            "set_config('app.context_signature', %s, true)",
            (payload.hex(), signature.hex()),
        )
        cursor.execute(
            "SELECT set_config('app.tenant_id', %s, true), "
            "set_config('app.principal_id', %s, true), "
            "set_config('app.caller_id', %s, true)",
            (TENANT_B, TENANT_B, TENANT_B),
        )
        cursor.execute("SET ROLE qembed_runtime")

        if verify(cursor, payload, signature) != claims:
            raise AssertionError("valid externally issued context was not accepted")
        cursor.execute(
            "SELECT count(*), min(tenant_id)::text, max(tenant_id)::text "
            "FROM qembed_crypto.tenant_rows"
        )
        row_count, min_tenant, max_tenant = cursor.fetchone()
        if row_count != 5 or min_tenant != TENANT_A or max_tenant != TENANT_A:
            raise AssertionError("RLS trusted a forged identity GUC instead of signed tenant claim")

        cursor.execute(
            "SELECT has_table_privilege(current_user, "
            "'qembed_crypto.verification_keys', 'SELECT'), "
            "has_function_privilege(current_user, "
            "'qembed_crypto.qembed_context_verify_detached(bytea,bytea,bytea)', 'EXECUTE')"
        )
        can_read_keys, can_call_low_level = cursor.fetchone()
        if can_read_keys or can_call_low_level:
            raise AssertionError("runtime can read verification keys or invoke low-level C verifier")

        tampered = bytearray(signature)
        tampered[0] ^= 1
        assert_invalid(cursor, sign, "modified signature", payload_override=payload, signature_override=bytes(tampered))
        assert_invalid(cursor, sign, "wrong backend", {"backend_pid": str(int(claims["backend_pid"]) + 1)})
        assert_invalid(cursor, sign, "wrong transaction", {"transaction_id": str(int(claims["transaction_id"]) + 1)})
        assert_invalid(cursor, sign, "wrong database", {"database_oid": str(int(database_oid) + 1)})
        other_deployment = "another-deployment"
        assert_invalid(cursor, sign, "wrong deployment", {
            "deployment_id": other_deployment,
            "audience": f"{AUDIENCE_PREFIX}{other_deployment}:database:{database_oid}",
        })
        assert_invalid(cursor, sign, "wrong issuer", {"issuer": "urn:attacker:issuer"})
        expired_now = dt.datetime.now(dt.timezone.utc)
        assert_invalid(cursor, sign, "expired token", {
            "issued_at": utc_text(expired_now - dt.timedelta(minutes=2)),
            "expires_at": utc_text(expired_now - dt.timedelta(minutes=1)),
        })

        cursor.execute("SAVEPOINT rt050_savepoint")
        cursor.execute("SELECT set_config('app.caller_id', %s, true)", (TENANT_B,))
        cursor.execute("ROLLBACK TO SAVEPOINT rt050_savepoint")
        if verify(cursor, payload, signature) != claims:
            raise AssertionError("savepoint rollback invalidated the outer transaction context")

        cursor.execute("RESET ROLE")
        connection.commit()

        # A committed token must fail in the next transaction on the same backend.
        cursor.execute("BEGIN")
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, payload, signature) is not None:
            raise AssertionError("committed token replayed in the next transaction")
        cursor.execute("RESET ROLE")
        connection.commit()

        # A token from a rolled-back transaction must fail in the following transaction.
        cursor.execute("BEGIN")
        rollback_payload, rollback_signature, rollback_claims = issue_token(cursor, sign)
        if verify(cursor, rollback_payload, rollback_signature) != rollback_claims:
            raise AssertionError("valid token in rollback test transaction was rejected")
        connection.rollback()
        cursor.execute("BEGIN")
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, rollback_payload, rollback_signature) is not None:
            raise AssertionError("rolled-back token replayed in the next transaction")
        cursor.execute("RESET ROLE")
        connection.commit()

        # A second backend must reject the original committed token.
        other = connect()
        other_cursor = other.cursor()
        other_cursor.execute("BEGIN")
        other_cursor.execute("SET ROLE qembed_runtime")
        if verify(other_cursor, payload, signature) is not None:
            raise AssertionError("token from another backend was accepted")
        other_cursor.execute("RESET ROLE")
        other.rollback()
        other_cursor.close()
        other.close()

        # pg_current_xact_id() and the signed context must work in READ ONLY.
        cursor.execute("BEGIN READ ONLY")
        read_only_payload, read_only_signature, read_only_claims = issue_token(cursor, sign)
        cursor.execute(
            "SELECT set_config('app.context_payload', %s, true), "
            "set_config('app.context_signature', %s, true)",
            (read_only_payload.hex(), read_only_signature.hex()),
        )
        cursor.execute("SET ROLE qembed_runtime")
        if verify(cursor, read_only_payload, read_only_signature) != read_only_claims:
            raise AssertionError("read-only transaction context was rejected")
        cursor.execute("SELECT count(*) FROM qembed_crypto.tenant_rows")
        if cursor.fetchone()[0] != 5:
            raise AssertionError("read-only RLS query returned wrong tenant rows")
        cursor.execute("RESET ROLE")
        connection.commit()

        print("PASS: external issuer, signature, transaction/backend binding, replay, savepoint, READ ONLY, RLS, and least privilege")
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
