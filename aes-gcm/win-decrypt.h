#pragma once
#include "cdef.h"

#include <stddef.h>

__BEGIN_DECLS

/*
 * Decrypt a single buffer, outputting the entire plain text at once
 *
 * Given a (valid) set of credentials and a cipher text buffer and size,
 * this function obtains data key associated with the cipher text from the
 * Ubiq service and uses it and the assigned algorithm to decrypt the cipher
 * text buffer.
 *
 * A pointer to the decrypted cipher text is returned in *ptbuf and the
 * number of bytes of plain text is returned in *ptlen.
 *
 * The function returns 0 on success or a negative error number on failure.
 * In the case of success, *ptbuf will point to memory allocated with
 * malloc(3), and the caller is responsible for releasing the memory with
 * free(3).
 */
int
ubiq_platform_decrypt(
    const void * key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    const void * const ctbuf, const size_t ctlen,
    void ** ptbuf, size_t * ptlen);

/* Opaque decryption object */
struct ubiq_platform_decryption;

/*
 * Create a decryption object that can be used to decrypt any number
 * of separate cipher texts.
 *
 * This function returns 0 on success or a negative error number on failure.
 * In the case of success, the decryption object is returned in *dec, and
 * must be destroyed by ubiq_platform_decryption_destroy() to avoid leaking
 * resources.
 */
int
ubiq_platform_decryption_create(
    const void * key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    struct ubiq_platform_decryption ** const dec);

/*
 * Destroy a decryption object.
 *
 * This function releases resources associated with a previously created
 * decryption object. The most recent call on the object must either be
 * ubiq_platform_decryption_create() or ubiq_platform_decryption_end().
 */
void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const dec);

/*
 * Begin decryption of a cipher text using the specified decryption object.
 *
 * The function returns 0 on success or a negative error number on failure.
 * The caller should treat the ptbuf and ptlen pointers as if data were
 * returned in them and *ptbuf needed to be released with free(3); however,
 * in practice, the function returns NULL and 0 in these parameters.
 */
int
ubiq_platform_decryption_begin(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen);

/*
 * Decrypt a portion of cipher text.
 *
 * This function should be called repeatedly to process the cipher text. Each
 * call may generate some amount of plain text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the plain text
 * in *ptbuf and the number of bytes pointed to by that pointer in *ptlen.
 * The caller is responsible for freeing that pointer using free(3).
 */
int
ubiq_platform_decryption_update(
    struct ubiq_platform_decryption * const dec,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen);

/*
 * Complete an decryption of a plain text.
 *
 * Once all of the cipher text has been processed by the calls to update(),
 * this function must be called to finalize the encryption. Note that for
 * some algorithms, this function may indicate that the decryption can't be
 * trusted as authentic. In that case the function has completed successfully,
 * but the caller should discard the plain text.
 *
 * The function returns 0 on success or a negative error number on failure.
 * On success, the function returns a pointer to a portion of the plain text
 * in *ptbuf and the number of bytes pointed to by that pointer in *ptlen.
 * The caller is responsible for freeing that pointer using free(3).
 *
 * After this function is called, the caller can call begin() again to start
 * an decryption a different cihper text or destroy() to release the decryption
 * object.
 */
int
ubiq_platform_decryption_end(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen);

__END_DECLS

