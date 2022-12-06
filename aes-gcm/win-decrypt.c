#include "win-decrypt.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <Windows.h>

#include "win-crypt.h"

struct ubiq_platform_decryption
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
    void * buf;
    size_t len;
};

int
ubiq_platform_decryption_create(
    const void * key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    struct ubiq_platform_decryption ** const dec)
{
    struct ubiq_platform_decryption * d;
    int res;

    res = -ENOMEM;
    d = calloc(1, sizeof(*d));
    if(d == NULL)
    {
	    return res;
    }
    res = ubiq_platform_algorithm_get_byid(1, &d->algo);
    if(res == 0)
    {
		d->key.len = keylen;
		d->key.buf = calloc(1, keylen);
		memcpy(d->key.buf, key, keylen);
		d->iv.len = ivlen;
		d->iv.buf = calloc(1, ivlen);
		memcpy(d->iv.buf, iv, ivlen);
		d->tag.len = taglen;
		d->tag.buf = calloc(1, taglen);
		memcpy(d->tag.buf, tag, taglen);
		d->aad.len = aadlen;
		d->aad.buf = calloc(1, aadlen);
		memcpy(d->aad.buf, aad, aadlen);
		*dec = d;
    }
    return res;
}

static
void
ubiq_platform_decryption_reset(
    struct ubiq_platform_decryption * const d)
{
    if (d->key.len) {

        free(d->key.buf);
        free(d->iv.buf);
        free(d->tag.buf);
        free(d->aad.buf);

        d->key.buf = NULL;
        d->key.len = 0;
        d->iv.buf = NULL;
        d->iv.len = 0;
        d->tag.buf = NULL;
        d->tag.len = 0;
        d->aad.buf = NULL;
        d->aad.len = 0;

        d->algo = NULL;
        if (d->ctx) {
            ubiq_support_cipher_destroy(d->ctx);
        }
    }
}

void
ubiq_platform_decryption_destroy(
    struct ubiq_platform_decryption * const d)
{
    ubiq_platform_decryption_reset(d);

    free(d->buf);

    free(d);
}

int
ubiq_platform_decryption_begin(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen)
{
    int res;

    if (dec->ctx) {
        res = -EINPROGRESS;
    } else {
        *ptbuf = NULL;
        *ptlen = 0;

        res = 0;
    }

    return res;
}

int
ubiq_platform_decryption_update(
    struct ubiq_platform_decryption * const dec,
    const void * const ctbuf, const size_t ctlen,
    void ** const ptbuf, size_t * const ptlen)
{
    void * buf;
    size_t off;
    int res;

    off = 0;
    res = 0;

    /*
     * this function works by appending incoming
     * cipher text to an internal buffer. when enough
     * data has been received to get the initialization
     * vector and the encrypted data key, the encrypted
     * data key is sent to the server for decryption
     * and then decryption can begin in earnest.
     */

    buf = realloc(dec->buf, dec->len + ctlen);
    if (!buf) {
        return -ENOMEM;
    }

    dec->buf = buf;
    memcpy((char *)dec->buf + dec->len, ctbuf, ctlen);
    dec->len += ctlen;

    if (!dec->ctx) {
		/*
		 * if the key is present now, create the
		 * decryption context
		 */
		if (res == 0 && dec->key.len) {
			res = ubiq_support_decryption_init(
				dec->algo,
				dec->key.buf, dec->key.len,
				dec->iv.buf, dec->iv.len,
				dec->aad.buf, dec->aad.len,
				&dec->ctx);
			if (res == 0) {
			}
		}
    }

    if (res == 0 && dec->ctx) {
        /*
         * decrypt whatever data is available, but always leave
         * enough data in the buffer to form a complete tag. the
         * tag is not part of the cipher text, but there's no
         * indication of when the tag will arrive. the code just
         * has to assume that the last bytes are the tag.
         */

        const int declen = dec->len - (off + dec->algo->len.tag);

        if (declen > 0) {
            res = ubiq_support_decryption_update(
                dec->ctx,
                (char *)dec->buf + off, declen,
                ptbuf, ptlen);
            if (res == 0) {
                memmove(dec->buf,
                        (char *)dec->buf + off + declen,
                        dec->algo->len.tag);
                dec->len = dec->algo->len.tag;
            }
        }
    }

    return res;
}

int
ubiq_platform_decryption_end(
    struct ubiq_platform_decryption * const dec,
    void ** const ptbuf, size_t * const ptlen)
{
    int res;

    res = -ESRCH;
    if (dec->ctx) {
        const int sz = dec->len - dec->algo->len.tag;

        if (sz != 0) {
            /*
             * if sz < 0, then the update function was never even
             * provided with enough data to form a tag. based on
             * the logic in the update function, it should not be
             * possible for sz to be greater than 0
             */
            res = -ENODATA;
        } else {
            res = ubiq_support_decryption_finalize(
                dec->ctx,
                dec->buf, dec->len,
                ptbuf, ptlen);
            if (res == 0) {
                free(dec->buf);
                dec->buf = NULL;
                dec->len = 0;

                dec->ctx = NULL;
            }
        }
    }

    return res;
}

int
ubiq_platform_decrypt(
    const void * key, const size_t keylen,
    const void* const iv, const size_t ivlen,
    const void* const tag, const size_t taglen,
    const void* const aad, const size_t aadlen,
    const void * ptbuf, const size_t ptlen,
    void ** ctbuf, size_t * ctlen)
{
    struct ubiq_platform_decryption * dec;
    int res;

    struct {
        void * buf;
        size_t len;
    } pre, upd, end;

    pre.buf = upd.buf = end.buf = NULL;

    dec = NULL;
    res = ubiq_platform_decryption_create(key, keylen, iv, ivlen, tag, taglen, aad, aadlen, &dec);

    if (res == 0) {
        res = ubiq_platform_decryption_begin(
            dec, &pre.buf, &pre.len);
    }

    if (res == 0) {
        res = ubiq_platform_decryption_update(
            dec, ptbuf, ptlen, &upd.buf, &upd.len);
    }

    if (res == 0) {
        res = ubiq_platform_decryption_end(
            dec, &end.buf, &end.len);
    }

    if (dec) {
        ubiq_platform_decryption_destroy(dec);
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
    free(pre.buf);

    return res;
}
