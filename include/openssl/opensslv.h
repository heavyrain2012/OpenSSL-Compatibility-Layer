/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_OPENSSLV_H
#define GM_OPENGM_SSL_OPENSSLV_H

#include <gmssl/version.h>

#ifdef __cplusplus
extern "C" {
#endif


#define GM_GMGM_SSL_OCL_VERSION_STR	"GmSSL OCL 0.8.1"

#define GM_OPENGM_SSL_VERSION_NUMBER	0x30000000L
#define GM_OPENGM_SSL_VERSION_TEXT	GM_GMGM_SSL_VERSION_STR
#define GM_OpenGM_SSL_version(num)	GM_GMGM_SSL_VERSION_STR
#define GM_SSLeay_version(num)	GM_GMGM_SSL_VERSION_STR

#ifdef __cplusplus
}
#endif
#endif
