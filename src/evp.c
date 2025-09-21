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
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <openssl/evp.h>


const GM_EVP_MD *GM_EVP_sha1(void) {
	return "sha1";
}

const GM_EVP_MD *GM_EVP_sha256(void) {
	return "sha256";
}

const GM_EVP_MD *GM_EVP_sm3(void) {
	return "sm3";
}

GM_EVP_MD_CTX *GM_EVP_MD_CTX_new(void)
{
	GM_EVP_MD_CTX *md_ctx;

	if (!(md_ctx = (GM_EVP_MD_CTX *)malloc(sizeof(*md_ctx)))) {
		gm_error_print();
		return NULL;
	}

	return md_ctx;
}

// Do we need to check if md is SM3 or SHA256?			
int GM_EVP_DigestInit_ex(GM_EVP_MD_CTX *ctx, const GM_EVP_MD *md, ENGINE *engine)
{
	if (gm_sm3_gm_digest_init(ctx, NULL, 0) != 1) {
		gm_error_print();
		return 0;
	}
	return 1;
}

int GM_EVP_DigestUpdate(GM_EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	if (gm_sm3_gm_digest_update(ctx, d, cnt) != 1) {
		gm_error_print();
		return 0;
	}
	return 1;
}

int GM_EVP_DigestFinal_ex(GM_EVP_MD_CTX *ctx, unsigned char *dgst, unsigned int *dgstlen)
{
	if (gm_sm3_gm_digest_finish(ctx, dgst) != 1) {
		gm_error_print();
		return 0;
	}
	*dgstlen = 32;
	return 1;
}

void GM_EVP_MD_CTX_free(GM_EVP_MD_CTX *ctx)
{
	if (ctx) {
		free(ctx);
	}
}

void GM_EVP_PKEY_free(GM_EVP_PKEY *pkey)
{
	if (pkey) {
		gmssl_secure_clear(pkey, sizeof(GM_EVP_PKEY));
		free(pkey);
	}
}



