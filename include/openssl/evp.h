/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_EVP_H
#define GM_OPENGM_SSL_GM_EVP_H

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef void ENGINE;


// make `const GM_EVP_MD *` into `const char *` string
typedef char GM_EVP_MD;

typedef GM_SM3_GM_DIGEST_CTX GM_EVP_MD_CTX;


#define GM_EVP_MAX_MD_SIZE 64

const GM_EVP_MD *GM_EVP_sm3(void);
const GM_EVP_MD *GM_EVP_sha1(void);
const GM_EVP_MD *GM_EVP_sha256(void);

GM_EVP_MD_CTX *GM_EVP_MD_CTX_new(void);
int GM_EVP_DigestInit_ex(GM_EVP_MD_CTX *ctx, const GM_EVP_MD *type, ENGINE *engine);
int GM_EVP_DigestUpdate(GM_EVP_MD_CTX *ctx, const void *d, size_t cnt);
int GM_EVP_DigestFinal_ex(GM_EVP_MD_CTX *ctx, unsigned char *md,unsigned int *s);
void GM_EVP_MD_CTX_free(GM_EVP_MD_CTX *ctx);

#define GM_EVP_MD_CTX_create() GM_EVP_MD_CTX_new()
#define GM_EVP_MD_CTX_destroy(ctx) GM_EVP_MD_CTX_free(ctx);




typedef struct {
	GM_SM2_KEY signkey;
	GM_SM2_KEY kenckey;
} GM_EVP_PKEY;

void GM_EVP_PKEY_free(GM_EVP_PKEY *key);




#ifdef __cplusplus
}
#endif
#endif
