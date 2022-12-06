#pragma once
#include "cdef.h"

#include <stdint.h>


__BEGIN_DECLS
/*
 * Encrypt a single buffer, outputting the entire cipher text at once
 *
 * Given a (valid) set of credentials and a plain text buffer and size,
 * this function obtains a new data key from the Ubiq service and uses
 * it and the assigned algorithm to encrypt the plain text buffer.
 *
 * A pointer to the encrypted cipher text is returned in *ctbuf and the
 * number of bytes of cipher text is returned in *ctlen.
 *
 * The function returns 0 on success or a negative error number on failure.
 * In the case of success, *ctbuf will point to memory allocated with
 * malloc(3), and the caller is responsible for releasing the memory with
 * free(3).
 */
int
ubiq_platform_encrypt(
    const void * const key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen);

/* Opaque encryption object */
struct ubiq_platform_encryption;

/*
 * Create an encryption object that can be used to encrypt some number
 * of separate plain texts under the same key.
 *
 * Given a (valid) set of credentials and a desired number of uses of the
 * newly obtained key, this function will obtain a new data key from the
 * Ubiq service with permission to use it some number of times with the
 * assigned algorithm. The number of times the key may be used may be
 * reduced by the server.
 *
 * This function returns 0 on success or a negative error number on failure.
 * In the case of success, the encryption object is returned in *enc, and
 * must be destroyed by ubiq_platform_encryption_destroy() to avoid leaking
 * resources.
 */
int
ubiq_platform_encryption_create(
    const void* const key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    struct ubiq_platform_encryption ** const enc);

/*
 * Destroy an encryption object.
 *
 * This function releases resources associated with a previously created
 * encryption object. The most recent call on the object must either be
 * ubiq_platform_encryption_create() or ubiq_platform_encryption_end().
 */
void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * const enc);

/*
 * Begin encryption of a plain text using the specified encryption object.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to the initial portion of the
 * cipher text in *ctbuf and the number of bytes pointed to by that pointer
 * in *ctlen. The caller is responsible for freeing that pointer using
 * free(3).
 */
int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * const enc,
    void ** const ptbuf, size_t * const ptlen);

/*
 * Encrypt a portion of plain text.
 *
 * This function should be called repeatedly to process the plain text. Each
 * call may generate some amount of cipher text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the cipher text
 * in *ctbuf and the number of bytes pointed to by that pointer in *ctlen.
 * The caller is responsible for freeing that pointer using free(3).
 */
int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * const enc,
    const void * ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen);

/*
 * Complete an encryption of a plain text.
 *
 * Once all of the plain text has been processed by the calls to update(),
 * this function must be called to finalize the encryption.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the cipher text
 * in *ctbuf and the number of bytes pointed to by that pointer in *ctlen.
 * The caller is responsible for freeing that pointer using free(3).
 *
 * After this function is called, the caller can call begin() again to start
 * an encryption a different plain text under the same key or destroy() to
 * release the encryption object.
 */
int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen);

__END_DECLS

