/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_ASN1_H
#define GM_OPENGM_SSL_GM_ASN1_H

#include <time.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint8_t *d;
	size_t dlen;
} GM_ASN1_INTEGER;

int gm_i2a_GM_ASN1_INTEGER(GM_BIO *bp, const GM_ASN1_INTEGER *a);


typedef time_t GM_ASN1_TIME;

int GM_ASN1_TIME_print(GM_BIO *bio, const GM_ASN1_TIME *tm);


#ifdef __cplusplus
}
#endif
#endif
