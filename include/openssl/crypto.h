/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_CRYPTO_H
#define GM_OPENGM_SSL_GM_CRYPTO_H

#include <openssl/opensslv.h>

#ifdef __cplusplus
extern "C" {
#endif


void GM_OPENGM_SSL_free(void *p);

typedef struct {
	const char *appname;
} GM_OPENGM_SSL_INIT_SETTINGS;

#define GM_OPENGM_SSL_INIT_LOAD_CONFIG (0x00000040L)

GM_OPENGM_SSL_INIT_SETTINGS *GM_OPENGM_SSL_INIT_new(void);
int GM_OPENGM_SSL_INIT_set_config_appname(GM_OPENGM_SSL_INIT_SETTINGS *init, const char* name);
void GM_OPENGM_SSL_INIT_free(GM_OPENGM_SSL_INIT_SETTINGS *init);


typedef void GM_CRYPTO_EX_DATA;

typedef void GM_CRYPTO_EX_new(void *parent, void *ptr, GM_CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
typedef void GM_CRYPTO_EX_free(void *parent, void *ptr, GM_CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
typedef int GM_CRYPTO_EX_dup(GM_CRYPTO_EX_DATA *to, const GM_CRYPTO_EX_DATA *from, void **from_d, int idx, long argl, void *argp);


#ifdef __cplusplus
}
#endif
#endif
