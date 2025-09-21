/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_BIO_H
#define GM_OPENGM_SSL_GM_BIO_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void GM_BIO_METHOD;

const GM_BIO_METHOD *GM_BIO_s_mem(void);


typedef FILE GM_BIO;

GM_BIO *GM_BIO_new(const GM_BIO_METHOD *meth);
GM_BIO *GM_BIO_new_mem_buf(const void *buf, int len);
GM_BIO *GM_BIO_new_file(const char *filename, const char *mode);
int GM_BIO_read(GM_BIO *bio, void *buf, int len);
int GM_BIO_write(GM_BIO *bio, const void *buf, int len);
int GM_BIO_pending(GM_BIO *bio);
int GM_BIO_reset(GM_BIO *bio);
int GM_BIO_get_mem_data(GM_BIO *bio, char **pp);
int GM_BIO_free(GM_BIO *bio);


#ifdef __cplusplus
}
#endif
#endif
