#include "win-encrypt.h"


#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>

#include "win-crypt.h"

struct ubiq_platform_encryption
{
    struct {
    	void * buf;
    	size_t len;
    } key;

    struct {
    	void * buf;
    	size_t len;
    } iv;

    struct {
    	void * buf;
    	size_t len;
    } tag;

    struct {
    	void * buf;
    	size_t len;
    } aad;

    const struct ubiq_platform_algorithm * algo;
    struct ubiq_support_cipher_context * ctx;
};

void
ubiq_platform_encryption_destroy(
    struct ubiq_platform_encryption * const e)
{
    free(e->key.buf);
    free(e->iv.buf);
    free(e->tag.buf);
    free(e->aad.buf);

    if (e->ctx) {
        ubiq_support_cipher_destroy(e->ctx);
    }

    free(e);
}

static
int
ubiq_platform_encryption_new(
    struct ubiq_platform_encryption ** const enc)
{
    struct ubiq_platform_encryption * e;
    int res;

    res = -ENOMEM;
    e = calloc(1, sizeof(*e));
    if(e == NULL)
    {
	    return res;
    }

    *enc = e;
    res = 0;
    return res;
}

int ubiq_platform_encryption_create(
    const void* const key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    struct ubiq_platform_encryption ** const enc)
{
    struct ubiq_platform_encryption * e;
    int res;

    res = ubiq_platform_encryption_new(&e);
    if(res == 0)
    {
		res = ubiq_platform_algorithm_get_byid(1, &e->algo);
        e->key.len = keylen;
        e->key.buf = calloc(1, keylen);
        memcpy(e->key.buf, key, keylen);
        e->iv.len = ivlen;
        e->iv.buf = calloc(1, ivlen);
        memcpy(e->iv.buf, iv, ivlen);
        e->tag.len = taglen;
        e->tag.buf = calloc(1, taglen);
        memcpy(e->tag.buf, tag, taglen);
        e->aad.len = aadlen;
        e->aad.buf = calloc(1, aadlen);
        memcpy(e->aad.buf, aad, aadlen);

    }

    if (res == 0) {
        *enc = e;
    } else {
        ubiq_platform_encryption_destroy(e);
    }

    return res;
}

int
ubiq_platform_encryption_begin(
    struct ubiq_platform_encryption * const enc,
    void ** const ptbuf, size_t * const ptlen)
{
    int res;

    if (enc->ctx) {
        /* encryption already in progress */
        res = -EINPROGRESS;
    } else {
        *ptbuf = NULL;
        *ptlen = 0;
		res = ubiq_support_encryption_init(
			enc->algo,
			enc->key.buf, enc->key.len,
			enc->iv.buf, enc->iv.len,
			enc->aad.buf, enc->aad.len,
			&enc->ctx);
		if (res == 0) {
		}
    }

    return res;
}

int
ubiq_platform_encryption_update(
    struct ubiq_platform_encryption * const enc,
    const void * const ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        res = ubiq_support_encryption_update(
            enc->ctx, ptbuf, ptlen, ctbuf, ctlen);
    }

    return res;
}

int
ubiq_platform_encryption_end(
    struct ubiq_platform_encryption * const enc,
    void ** const ctbuf, size_t * const ctlen)
{
    int res;

    res = -ESRCH;
    if (enc->ctx) {
        void * tagbuf;
        size_t taglen;

        tagbuf = NULL;
        taglen = 0;
        res = ubiq_support_encryption_finalize(
            enc->ctx, ctbuf, ctlen, &tagbuf, &taglen);
        if (res == 0) {
            enc->ctx = NULL;
        }

        if (res == 0 && tagbuf && taglen) {
            void * buf;

            res = -ENOMEM;
            buf = realloc(*ctbuf, *ctlen + taglen);
            if (buf) {
                memcpy((char *)buf + *ctlen, tagbuf, taglen);
                *ctbuf = buf;
                *ctlen += taglen;
                res = 0;
            } else {
                free(*ctbuf);
            }

            free(tagbuf);
        }
    }

    return res;
}

int
ubiq_platform_encrypt(
    const void * key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    const void * ptbuf, const size_t ptlen,
    void ** const ctbuf, size_t * const ctlen)
{
    struct ubiq_platform_encryption * enc;
    int res;

    struct {
        void * buf;
        size_t len;
    } pre, upd, end;

    pre.buf = upd.buf = end.buf = NULL;

    enc = NULL;
    res = ubiq_platform_encryption_create(key, keylen, iv, ivlen, tag, taglen, aad, aadlen, &enc);

    if (res == 0) {
        res = ubiq_platform_encryption_begin(enc, &pre.buf, &pre.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_update(
            enc, ptbuf, ptlen, &upd.buf, &upd.len);
    }

    if (res == 0) {
        res = ubiq_platform_encryption_end(
            enc, &end.buf, &end.len);
    }

    if (enc) {
        ubiq_platform_encryption_destroy(enc);
    }

    if (res == 0) {
        *ctlen = pre.len + upd.len + end.len;
        *ctbuf = malloc(*ctlen);

        memcpy(*ctbuf, pre.buf, pre.len);
        memcpy((char *)*ctbuf + pre.len, upd.buf, upd.len);
        memcpy((char *)*ctbuf + pre.len + upd.len, end.buf, end.len);
    }

    free(end.buf);
    free(upd.buf);

    return res;
}
