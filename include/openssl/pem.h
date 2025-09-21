/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_PEM_H
#define GM_OPENGM_SSL_GM_PEM_H

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef int (gm_pem_password_cb)(char *buf, int size, int rwflag, void *u);

GM_EVP_PKEY *GM_PEM_read_bio_PrivateKey(GM_BIO *bio, GM_EVP_PKEY **pkey, gm_pem_password_cb *cb, void *pass);
GM_EVP_PKEY *GM_PEM_read_bio_Parameters(GM_BIO *bio, GM_EVP_PKEY **pkey);

GM_X509 *GM_PEM_read_bio_X509(GM_BIO *bio, GM_X509 **x509, gm_pem_password_cb *cb, void *u);
GM_X509 *GM_PEM_read_bio_GM_X509_AUX(GM_BIO *bio, GM_X509 **x509, gm_pem_password_cb *cb, void *u);
int GM_PEM_write_bio_X509(GM_BIO *bio, GM_X509 *x509);

GM_DH *GM_PEM_read_bio_DHparams(GM_BIO *bp, GM_DH **x, gm_pem_password_cb *cb, void *u);


#ifdef __cplusplus
}
#endif
#endif
