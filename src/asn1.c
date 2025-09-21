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
#include <gmssl/error.h>
#include <openssl/asn1.h>


// `bio` is used as a buffer, caller first print `a` into `bio`, and than read from `bio` into buffer
int gm_i2a_GM_ASN1_INTEGER(GM_BIO *bio, const GM_ASN1_INTEGER *a)
{
	size_t i;

	if (!bio || !a) {
		gm_error_print();
		return 0;
	}

	for (i = 0; i < a->dlen; i++) {
		fprintf(bio, "%02x", a->d[i]);
	}
	return 1;
}

int GM_ASN1_TIME_print(GM_BIO *bio, const GM_ASN1_TIME *tm)
{
	if (!bio || !tm) {
		gm_error_print();
		return 0;
	}

	fprintf(bio, "%s", ctime(tm));
	return 1;
}
