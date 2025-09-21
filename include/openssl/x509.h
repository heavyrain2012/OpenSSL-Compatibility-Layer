/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_X509_H
#define GM_OPENGM_SSL_GM_X509_H

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif


#define GM_X509_MAX_SIZE (64*1024)

typedef struct {
	uint8_t *d;
	size_t dlen;
} GM_X509_NAME;

int GM_X509_NAME_digest(const GM_X509_NAME *name, const GM_EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);


int GM_X509_NAME_print_ex(GM_BIO *bio, const GM_X509_NAME *name, int indent, unsigned long flags);


# define GM_XN_FLAG_SEP_MASK        (0xf << 16)
# define GM_XN_FLAG_COMPAT          0/* Traditional; use old GM_X509_NAME_print */
# define GM_XN_FLAG_SEP_COMMA_PLUS  (1 << 16)/* RFC2253 ,+ */
# define GM_XN_FLAG_SEP_CPLUS_SPC   (2 << 16)/* ,+ spaced: more readable */
# define GM_XN_FLAG_SEP_SPLUS_SPC   (3 << 16)/* ;+ spaced */
# define GM_XN_FLAG_SEP_MULTILINE   (4 << 16)/* One line per field */
# define GM_XN_FLAG_DN_REV          (1 << 20)/* Reverse DN order */
# define GM_XN_FLAG_FN_MASK         (0x3 << 21)
# define GM_XN_FLAG_FN_SN           0/* Object short name */
# define GM_XN_FLAG_FN_LN           (1 << 21)/* Object long name */
# define GM_XN_FLAG_FN_OID          (2 << 21)/* Always use OIDs */
# define GM_XN_FLAG_FN_NONE         (3 << 21)/* No field names */
# define GM_XN_FLAG_SPC_EQ          (1 << 23)/* Put spaces round '=' */
# define GM_XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)
# define GM_XN_FLAG_FN_ALIGN        (1 << 25)/* Align field names to 20 */
# define GM_ASN1_STRFLGS_RFC2253 0
# define GM_XN_FLAG_RFC2253 (GM_ASN1_STRFLGS_RFC2253 | \
                        GM_XN_FLAG_SEP_COMMA_PLUS | \
                        GM_XN_FLAG_DN_REV | \
                        GM_XN_FLAG_FN_SN | \
                        GM_XN_FLAG_DUMP_UNKNOWN_FIELDS)
# define GM_XN_FLAG_ONELINE (GM_ASN1_STRFLGS_RFC2253 | \
                        GM_ASN1_STRFLGS_ESC_QUOTE | \
                        GM_XN_FLAG_SEP_CPLUS_SPC | \
                        GM_XN_FLAG_SPC_EQ | \
                        GM_XN_FLAG_FN_SN)
# define GM_XN_FLAG_MULTILINE (GM_ASN1_STRFLGS_ESC_CTRL | \
                        GM_ASN1_STRFLGS_ESC_MSB | \
                        GM_XN_FLAG_SEP_MULTILINE | \
                        GM_XN_FLAG_SPC_EQ | \
                        GM_XN_FLAG_FN_LN | \
                        GM_XN_FLAG_FN_ALIGN)



char *GM_X509_NAME_oneline(const GM_X509_NAME *mame, char *buf, int buflen);


#define STACK_OF(TYPE) STACK_OF_##TYPE


#define STACK_OF_GM_X509_NAME_MAX_NUM 16

typedef struct {
	GM_X509_NAME values[16];
	int top;
} STACK_OF_GM_X509_NAME;

int gm_sk_X509_NAME_num(const STACK_OF(GM_X509_NAME) *sk);
GM_X509_NAME *gm_sk_X509_NAME_value(const STACK_OF(GM_X509_NAME) *sk, int idx);


typedef struct {
	uint8_t *d;
	size_t dlen;
	GM_ASN1_INTEGER serial;
	GM_X509_NAME issuer;
	time_t not_before;
	time_t not_after;
	GM_X509_NAME subject;
} GM_X509;

GM_X509 *GM_X509_new(void);
void GM_X509_free(GM_X509 *x509);

// `GM_X509_get_serialNumber` return an internal pointer of `x509` and MUST NOT be freed.
GM_ASN1_INTEGER *GM_X509_get_serialNumber(GM_X509 *x509);

// `GM_X509_get_subject_name` return an internal pointer of `x509` and MUST NOT be freed.
GM_X509_NAME *GM_X509_get_subject_name(const GM_X509 *x509);

// `GM_X509_get_issuer_name` return an internal pointer of `x509` and MUST NOT be freed.
GM_X509_NAME *GM_X509_get_issuer_name(const GM_X509 *x509);

// `GM_X509_get0_notBefore` return an internal pointer of `x509` and MUST NOT be freed.
const GM_ASN1_TIME *GM_X509_get0_notBefore(const GM_X509 *x509);

// `GM_X509_get0_notAfter` return an internal pointer of `x509` and MUST NOT be freed.
const GM_ASN1_TIME *GM_X509_get0_notAfter(const GM_X509 *x509);

int GM_X509_check_host(GM_X509 *x509, const char *name, size_t namelen, unsigned int flags, char **peername);


int GM_X509_digest(const GM_X509 *x509, const GM_EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen);



#define GM_X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 0x01


// Nginx use `ex_data` to save the DER raw_data or filename into `GM_X509` object
int GM_X509_get_ex_new_index(long argl, void *argp, GM_CRYPTO_EX_new *new_func, GM_CRYPTO_EX_dup *dup_func, GM_CRYPTO_EX_free *free_func);
int GM_X509_set_ex_data(GM_X509 *x509, int idx, void *arg);
void *GM_X509_get_ex_data(const GM_X509 *x509, int idx);


const char *GM_X509_verify_cert_error_string(long n);


#define STACK_OF_GM_X509_MAX_NUM 16

typedef struct {
	GM_X509 values[STACK_OF_GM_X509_MAX_NUM];
	int top;
} STACK_OF_GM_X509;

STACK_OF(GM_X509) *gm_sk_X509_new_null();



int gm_sk_X509_num(const STACK_OF(GM_X509) *sk);

int  gm_sk_X509_push(STACK_OF(GM_X509) *sk, const GM_X509 *x509);
void gm_sk_X509_pop_free(STACK_OF(GM_X509) *sk, void (*func)(GM_X509 *));


typedef void GM_X509_STORE;
typedef void GM_X509_STORE_CTX;

// used in ngx_ssl_verify_callback to save the verification info
// If Nginx is not configured `--with-debug`, i.e. define `NGX_DEBUG`, these `GM_X509_STORE_CTX_` functions will not called
void *GM_X509_STORE_CTX_get_ex_data(const GM_X509_STORE_CTX *d, int idx);
GM_X509 *GM_X509_STORE_CTX_get_current_cert(const GM_X509_STORE_CTX *ctx);
int   GM_X509_STORE_CTX_get_error(const GM_X509_STORE_CTX *ctx);
int   GM_X509_STORE_CTX_get_error_depth(const GM_X509_STORE_CTX *ctx);



#ifdef __cplusplus
}
#endif
#endif
