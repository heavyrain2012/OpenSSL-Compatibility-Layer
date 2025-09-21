/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/x509.h>


GM_X509 *GM_X509_new(void)
{
	GM_X509 *x509;

	if (!(x509 = (GM_X509 *)malloc(sizeof(GM_X509)))) {
		gm_error_print();
		return NULL;
	}
	memset(x509, 0, sizeof(GM_X509));

	if (!(x509->d = (uint8_t *)malloc(GM_X509_MAX_SIZE))) {
		free(x509);
		gm_error_print();
		return NULL;
	}
	return x509;
}

void GM_X509_free(GM_X509 *x509)
{
	if (x509) {
		if (x509->d) {
			free(x509->d);
		}
		free(x509);
	}
}

// `GM_X509_get_serialNumber` return an internal pointer of `x509` and MUST NOT be freed.
GM_ASN1_INTEGER *GM_X509_get_serialNumber(GM_X509 *x509)
{
	if (!x509) {
		gm_error_print();
		return NULL;
	}
	return &x509->serial;
}

// `GM_X509_get_subject_name` return an internal pointer of `x509` and MUST NOT be freed.
GM_X509_NAME *GM_X509_get_subject_name(const GM_X509 *x509)
{
	if (!x509) {
		gm_error_print();
		return NULL;
	}
	return (GM_X509_NAME *)&x509->subject;
}

// `GM_X509_get_issuer_name` return an internal pointer of `x509` and MUST NOT be freed.
GM_X509_NAME *GM_X509_get_issuer_name(const GM_X509 *x509)
{
	if (!x509) {
		gm_error_print();
		return NULL;
	}
	return (GM_X509_NAME *)&x509->issuer;
}

// `GM_X509_get0_notBefore` return an internal pointer of `x509` and MUST NOT be freed.
const GM_ASN1_TIME *GM_X509_get0_notBefore(const GM_X509 *x509)
{
	if (!x509) {
		gm_error_print();
		return NULL;
	}
	return &x509->not_before;
}

// `GM_X509_get0_notAfter` return an internal pointer of `x509` and MUST NOT be freed.
const GM_ASN1_TIME *GM_X509_get0_notAfter(const GM_X509 *x509)
{
	if (!x509) {
		gm_error_print();
		return NULL;
	}
	return &x509->not_after;
}

int GM_X509_NAME_print_ex(GM_BIO *bio, const GM_X509_NAME *name, int indent, unsigned long flags)
{
	gm_x509_name_print(bio,0, indent, "GM_X509_NAME", name->d, name->dlen);
	return 1;
}

// TODO:			
// `GM_X509_NAME_oneline` return a string and might be freed by `GM_OPENGM_SSL_free`
char *GM_X509_NAME_oneline(const GM_X509_NAME *mame, char *buf, int buflen)
{
	if (!buf) {
		return strdup("GM_X509_NAME_oneline() called");
	} else {
		strncpy(buf, "GM_X509_NAME_oneline() called", buflen);
		return buf;
	}
}

int GM_X509_NAME_digest(const GM_X509_NAME *name, const GM_EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen)
{
	GM_SM3_CTX sm3_ctx;

	if (!name || !dgst || !dgstlen) {
		gm_error_print();
		return 0;
	}
	if (!name->d || !name->dlen) {
		gm_error_print();
		return 0;
	}

	gm_sm3_init(&sm3_ctx);
	gm_sm3_update(&sm3_ctx, name->d, name->dlen);
	gm_sm3_finish(&sm3_ctx, dgst);
	*dgstlen = 32;
	return 1;
}

void *GM_X509_STORE_CTX_get_ex_data(const GM_X509_STORE_CTX *ctx, int idx)
{
	return NULL;
}

GM_X509 *GM_X509_STORE_CTX_get_current_cert(const GM_X509_STORE_CTX *ctx)
{
	return NULL;
}

int GM_X509_STORE_CTX_get_error(const GM_X509_STORE_CTX *ctx)
{
	return 0;
}

int GM_X509_STORE_CTX_get_error_depth(const GM_X509_STORE_CTX *ctx)
{
	return 0;
}

void *GM_X509_get_ex_data(const GM_X509 *x509, int idx)
{
	return NULL;
}

int GM_X509_check_host(GM_X509 *x509, const char *name, size_t namelen, unsigned int flags, char **peername)
{
	return 0;
}

int GM_X509_digest(const GM_X509 *x509, const GM_EVP_MD *md, unsigned char *dgst, unsigned int *dgstlen)
{
	GM_SM3_CTX sm3_ctx;

	if (!x509 || !dgst || !dgstlen) {
		gm_error_print();
		return 0;
	}
	if (!x509->d || !x509->dlen) {
		gm_error_print();
		return 0;
	}

	gm_sm3_init(&sm3_ctx);
	gm_sm3_update(&sm3_ctx, x509->d, x509->dlen);
	gm_sm3_finish(&sm3_ctx, dgst);
	*dgstlen = 32;
	return 1;
}

int GM_X509_set_ex_data(GM_X509 *d, int idx, void *arg)
{
	return 1;
}

int GM_X509_get_ex_new_index(long argl, void *argp, GM_CRYPTO_EX_new *new_func, GM_CRYPTO_EX_dup *dup_func, GM_CRYPTO_EX_free *free_func)
{
	return 1;
}

GM_X509_NAME *gm_sk_X509_NAME_value(const STACK_OF(GM_X509_NAME) *sk, int idx)
{
	return NULL;
}

int gm_sk_X509_NAME_num(const STACK_OF(GM_X509_NAME) *sk)
{
	if (!sk) {
		gm_error_print();
		return 0;
	}
	return sk->top;
}

STACK_OF(GM_X509) *gm_sk_X509_new_null()
{
	STACK_OF(GM_X509) *sk;

	if (!(sk = (STACK_OF(GM_X509) *)malloc(sizeof(*sk)))) {
		gm_error_print();
		return NULL;
	}

	sk->top = 0;
	return sk;
}

int gm_sk_X509_num(const STACK_OF(GM_X509) *sk)
{
	if (!sk) {
		gm_error_print();
		return 0;
	}
	return sk->top;
}

int gm_sk_X509_push(STACK_OF(GM_X509) *sk, const GM_X509 *x509)
{
	if (!sk || !x509) {
		gm_error_print();
		return 0;
	}
	if (sk->top >= STACK_OF_GM_X509_MAX_NUM) {
		gm_error_print();
		return 0;
	}

	sk->values[sk->top] = *x509;
	sk->top += 1;
	return 1;
}

void gm_sk_X509_pop_free(STACK_OF(GM_X509) *sk, void (*func)(GM_X509 *))
{
	if (!sk) {
		gm_error_print();
	}
	if (sk->top > 0) {
		sk->top -= 1;
	}
}
