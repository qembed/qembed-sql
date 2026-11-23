#include <stddef.h>
#include <stdint.h>

#include "qembed_context_verify_core.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char empty_message = 0;
    const size_t signature_len = size < crypto_sign_BYTES ? size : crypto_sign_BYTES;
    const size_t key_offset = crypto_sign_BYTES;
    const size_t available_after_signature =
        size > key_offset ? size - key_offset : 0;
    const size_t public_key_len =
        available_after_signature < crypto_sign_PUBLICKEYBYTES
            ? available_after_signature
            : crypto_sign_PUBLICKEYBYTES;
    const size_t message_offset = key_offset + crypto_sign_PUBLICKEYBYTES;
    const size_t message_len = size > message_offset ? size - message_offset : 0;
    const unsigned char *signature = data;
    const unsigned char *public_key =
        available_after_signature == 0 ? &empty_message : data + key_offset;
    const unsigned char *message =
        message_len == 0 ? &empty_message : data + message_offset;

    (void) qembed_context_verify_detached_bytes(
        signature, signature_len, message, message_len,
        public_key, public_key_len);
    return 0;
}
