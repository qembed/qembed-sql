#include "postgres.h"
#include "fmgr.h"
#include "utils/bytea.h"
#include "varatt.h"

#include "qembed_context_verify_core.h"

PG_MODULE_MAGIC;

PGDLLEXPORT void _PG_init(void);
PG_FUNCTION_INFO_V1(qembed_context_verify_detached);

void
_PG_init(void)
{
    if (sodium_init() < 0)
        ereport(ERROR,
                (errmsg("qembed_context_verify: libsodium initialization failed")));
}

Datum
qembed_context_verify_detached(PG_FUNCTION_ARGS)
{
    bytea *signature = PG_GETARG_BYTEA_PP(0);
    bytea *message = PG_GETARG_BYTEA_PP(1);
    bytea *public_key = PG_GETARG_BYTEA_PP(2);
    const Size signature_len = VARSIZE_ANY_EXHDR(signature);
    const Size message_len = VARSIZE_ANY_EXHDR(message);
    const Size public_key_len = VARSIZE_ANY_EXHDR(public_key);

    PG_RETURN_BOOL(qembed_context_verify_detached_bytes(
        (const unsigned char *) VARDATA_ANY(signature), signature_len,
        (const unsigned char *) VARDATA_ANY(message), message_len,
        (const unsigned char *) VARDATA_ANY(public_key), public_key_len));
}
