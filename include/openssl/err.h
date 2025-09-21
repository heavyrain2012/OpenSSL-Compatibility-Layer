/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_ERR_H
#define GM_OPENGM_SSL_GM_ERR_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


unsigned long GM_ERR_get_error(void);
unsigned long GM_ERR_peek_error(void);
unsigned long GM_ERR_peek_last_error(void);
unsigned long GM_ERR_peek_error_data(const char **data, int *flags);
unsigned long GM_ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags);
void GM_ERR_error_string_n(unsigned long e, char *buf, size_t len);
void GM_ERR_clear_error(void);

#define GM_PEM_R_NO_START_LINE	1

// from openssl/err.h
#define GM_ERR_LIB_NONE            1
#define GM_ERR_LIB_PEM             9

int GM_ERR_GET_LIB(unsigned long e);
int GM_ERR_GET_REASON(unsigned long e);

// who use this?
# define GM_ERR_TXT_STRING          0x02



#ifdef __cplusplus
}
#endif
#endif
