/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdlib.h>
#include <gmssl/error.h>
#include <openssl/crypto.h>


void GM_OPENGM_SSL_free(void *p)
{
	if (p) {
		free(p);
	}
}

GM_OPENGM_SSL_INIT_SETTINGS *GM_OPENGM_SSL_INIT_new(void)
{
	GM_OPENGM_SSL_INIT_SETTINGS *init = NULL;

	if (!(init = (GM_OPENGM_SSL_INIT_SETTINGS *)malloc(sizeof(*init)))) {
		gm_error_print();
		return NULL;
	}
	init->appname = NULL;
	return init;
}

int GM_OPENGM_SSL_INIT_set_config_appname(GM_OPENGM_SSL_INIT_SETTINGS *init, const char *name)
{
	if (!init || !name) {
		gm_error_print();
		return 0;
	}

	init->appname = name;
	return 1;
}

void GM_OPENGM_SSL_INIT_free(GM_OPENGM_SSL_INIT_SETTINGS *init)
{
	if (init) {
		free(init);
	}
}
