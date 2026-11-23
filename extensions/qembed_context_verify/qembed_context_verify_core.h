#ifndef QEMBED_CONTEXT_VERIFY_CORE_H
#define QEMBED_CONTEXT_VERIFY_CORE_H

#include <stdbool.h>
#include <stddef.h>

#include <sodium.h>

#define QEMBED_CONTEXT_MAX_MESSAGE_BYTES 8192U

/*
 * Shared production/fuzzing boundary. Keep all length checks here so the
 * libFuzzer target exercises the exact verifier primitive used by PostgreSQL.
 */
static inline bool
qembed_context_verify_detached_bytes(const unsigned char *signature,
                                     size_t signature_len,
                                     const unsigned char *message,
                                     size_t message_len,
                                     const unsigned char *public_key,
                                     size_t public_key_len)
{
    if (signature == NULL || message == NULL || public_key == NULL ||
        signature_len != crypto_sign_BYTES ||
        public_key_len != crypto_sign_PUBLICKEYBYTES ||
        message_len > QEMBED_CONTEXT_MAX_MESSAGE_BYTES)
        return false;

    return crypto_sign_verify_detached(signature, message,
                                       (unsigned long long) message_len,
                                       public_key) == 0;
}

#endif
