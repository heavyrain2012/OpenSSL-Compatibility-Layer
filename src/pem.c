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
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/pem.h>


GM_DH *GM_PEM_read_bio_DHparams(GM_BIO *bio, GM_DH **dh, gm_pem_password_cb *cb, void *u)
{
	gm_error_print();
	return NULL;
}

GM_EVP_PKEY *GM_PEM_read_bio_Parameters(GM_BIO *bio, GM_EVP_PKEY **pkey)
{
	gm_error_print();
	return NULL;
}

GM_EVP_PKEY *GM_PEM_read_bio_PrivateKey(GM_BIO *bio, GM_EVP_PKEY **pp, gm_pem_password_cb *cb, void *u)
{
	GM_EVP_PKEY *pkey = NULL;
	char pass[1024] = {0};

	if (!bio || !cb || !u) {
		gm_error_print();
		return NULL;
	}

	cb(pass, sizeof(pass), 0, u);

	if (!(pkey = (GM_EVP_PKEY *)malloc(sizeof(*pkey)))) {
		gm_error_print();
		return NULL;
	}

	if (gm_sm2_private_key_info_decrypt_from_pem(&pkey->signkey, pass, bio) != 1) {
		gm_error_print();
		GM_EVP_PKEY_free(pkey);
		return NULL;
	}
	if (gm_sm2_private_key_info_decrypt_from_pem(&pkey->kenckey, pass, bio) != 1) {
		gm_error_print();
		GM_EVP_PKEY_free(pkey);
		return NULL;
	}

	if (pp) {
		if (*pp) {
			GM_EVP_PKEY_free(*pp);
		}
		*pp = pkey;
	}
	return pkey;
}

GM_X509 *GM_PEM_read_bio_X509(GM_BIO *bio, GM_X509 **pp, gm_pem_password_cb *cb, void *u)
{
	GM_X509 *x509;
	int ret;

	if (!bio) {
		gm_error_print();
		return NULL;
	}

	if (!(x509 = GM_X509_new())) {
		gm_error_print();
		return NULL;
	}
	if ((ret = gm_x509_cert_from_pem(x509->d, &x509->dlen, GM_X509_MAX_SIZE, bio)) != 1) {
		if (ret) {
			gm_error_print();
		}
		GM_X509_free(x509);
		return NULL;
	}

	if (gm_x509_cert_get_details(x509->d, x509->dlen,
		NULL,
		(const uint8_t **)&x509->serial.d, &x509->serial.dlen,
		NULL,
		(const uint8_t **)&x509->issuer.d, &x509->issuer.dlen,
		&x509->not_before, &x509->not_after,
		(const uint8_t **)&x509->subject.d, &x509->subject.dlen,
		NULL,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL,
		NULL,
		NULL, NULL) != 1) {
		GM_X509_free(x509);
		gm_error_print();
		return NULL;
	}

	if (pp) {
		if (*pp) {
			GM_X509_free(*pp);
		}
		*pp = x509;
	}
	return x509;
}

// `GM_PEM_read_bio_GM_X509_AUX` do more checks than `GM_PEM_read_bio_X509`
GM_X509 *GM_PEM_read_bio_GM_X509_AUX(GM_BIO *bio, GM_X509 **pp, gm_pem_password_cb *cb, void *u)
{
	GM_X509 *x509;
	if (!(x509 = GM_PEM_read_bio_X509(bio, pp, cb, u))) {
		gm_error_print();
		return NULL;
	}
	return x509;
}

int GM_PEM_write_bio_X509(GM_BIO *bio, GM_X509 *x509)
{
	if (!bio || !x509) {
		gm_error_print();
		return 0;
	}
	if (gm_x509_cert_to_pem(x509->d, x509->dlen, bio) != 1) {
		gm_error_print();
		return 0;
	}
	return 1;
}
