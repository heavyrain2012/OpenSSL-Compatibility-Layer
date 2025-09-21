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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <openssl/rand.h>


int GM_RAND_bytes(unsigned char *buf, int num)
{
	if (!buf) {
		gm_error_print();
		return 0;
	}

	if (gm_rand_bytes(buf, (size_t)num) != 1) {
		gm_error_print();
		return 0;
	}
	return 1;
}
