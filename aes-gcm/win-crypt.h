#pragma once
#include "cdef.h"

#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

struct ubiq_platform_algorithm
{
    unsigned int id;
    const char * name;

    struct {
        unsigned int key, iv, tag;
    } len;
};


/* returned string/data must be freed via free() */
int ubiq_support_base64_encode(char ** const, const void * const, const size_t);
int ubiq_support_base64_decode(void ** const, const char * const, const size_t);


struct ubiq_support_hash_context;

int ubiq_support_digest_init(
    const char * const,
    struct ubiq_support_hash_context ** const);
void ubiq_support_digest_update(
    struct ubiq_support_hash_context * const,
    const void * const, const size_t);
/* returned pointer must be freed via free() */
int ubiq_support_digest_finalize(
    struct ubiq_support_hash_context * const,
    void ** const, size_t * const);


int ubiq_support_hmac_init(
    const char * const,
    const void * const, const size_t,
    struct ubiq_support_hash_context ** const);
void ubiq_support_hmac_update(
    struct ubiq_support_hash_context * const,
    const void * const, const size_t);
/* returned pointer must be freed via free() */
int ubiq_support_hmac_finalize(
    struct ubiq_support_hash_context * const,
    void ** const, size_t * const);


int ubiq_support_getrandom(void * const, const size_t);


struct ubiq_support_cipher_context;

void ubiq_support_cipher_destroy(
    struct ubiq_support_cipher_context * const);

int ubiq_platform_algorithm_init(void);
void ubiq_platform_algorithm_exit(void);
int
ubiq_platform_algorithm_get_byid(
    const unsigned int,
    const struct ubiq_platform_algorithm ** const);
int
ubiq_platform_algorithm_get_byname(
    const char * const,
    const struct ubiq_platform_algorithm ** const);


int ubiq_support_encryption_init(
    const struct ubiq_platform_algorithm * const,
    const void * const, const size_t, /* key */
    const void * const, const size_t, /* iv */
    const void * const, const size_t, /* aad */
    struct ubiq_support_cipher_context ** const);
/* returned pointer must be freed via free() */
int ubiq_support_encryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* pt */
    void ** const, size_t * const /* ct */);
/* returned pointers must be freed via free() */
int ubiq_support_encryption_finalize(
    struct ubiq_support_cipher_context * const,
    void ** const, size_t * const, /* ct */
    void ** const, size_t * const /* tag */);

int ubiq_support_decryption_init(
    const struct ubiq_platform_algorithm * const,
    const void * const, const size_t, /* key */
    const void * const, const size_t, /* iv */
    const void * const, const size_t, /* aad */
    struct ubiq_support_cipher_context ** const);
/* returned pointer must be freed via free() */
int ubiq_support_decryption_update(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* ct */
    void ** const, size_t * const /* pt */);
/* returned pointer must be freed via free() */
int ubiq_support_decryption_finalize(
    struct ubiq_support_cipher_context * const,
    const void * const, const size_t, /* tag */
    void ** const, size_t * const /* pt */);

/*
 * this function takes a pem encoding of a private key encrypted
 * with a password and uses it to decrypt the input. the plain text
 * is returned via a pointer that must be freed via free()
 */
int ubiq_support_asymmetric_decrypt(
    const char * const, const char * const, /* private key pem, password */
    const void * const, const size_t, /* input */
    void ** const, size_t * const /* output */);

__END_DECLS

/*
 * local variables:
 * mode: c
 * end:
 */
