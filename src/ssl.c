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
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>


int GM_OPENGM_SSL_init_ssl(uint64_t opts, const GM_OPENGM_SSL_INIT_SETTINGS *settings)
{
	return 1;
}

// The default timeout of OpenSSL is 300s (5 minutes)
// When a `SSL` is timeout, the SESSION data will be removed, client have to do a full Handshake with server.
// GmSSL 3.1 does not support GM_SSL_SESSION and timeout, so timeout is always 0
long GM_SSL_CTX_set_timeout(GM_SSL_CTX *ctx, long timeout_seconds)
{
	return 0;
}

long GM_SSL_CTX_get_timeout(GM_SSL_CTX *ctx)
{
	return 0;
}

// a typical cipher list is ""HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";"
// so we omit the input `str`
int GM_SSL_CTX_set_cipher_list(GM_SSL_CTX *ctx, const char *str)
{
	const int ciphers[] = {
		GM_TLS_cipher_ecdhe_gm_sm4_cbc_sm3,
	};

	if (!ctx || !str) {
		gm_error_print();
		return 0;
	}

	if (gm_tls_ctx_set_cipher_suites(ctx, ciphers, sizeof(ciphers)/sizeof(ciphers[0])) != 1) {
		gm_error_print();
		return 0;
	}

	return 1;
}

// GmSSL does not support options
uint64_t GM_SSL_CTX_set_options(GM_SSL_CTX *ctx, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t GM_SSL_CTX_clear_options(GM_SSL_CTX *ctx, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t GM_SSL_set_options(SSL *ssl, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

uint64_t GM_SSL_clear_options(SSL *ssl, uint64_t options)
{
	uint64_t bitmask = 0;
	return bitmask;
}

// GmSSL does not support different mode (such as GM_SSL_MODE_ENABLE_PARTIAL_WRITE)
long GM_SSL_CTX_set_mode(GM_SSL_CTX *ctx, long mode)
{
	return 0;
}

int GM_SSL_CTX_set_min_proto_version(GM_SSL_CTX *ctx, int version)
{
	return 1;
}

int GM_SSL_CTX_set_max_proto_version(GM_SSL_CTX *ctx, int version)
{
	return 1;
}

void GM_SSL_CTX_set_cert_cb(GM_SSL_CTX *c, int (*cert_cb)(SSL *ssl, void *arg), void *arg)
{
}

// `GM_SSL_CTX_set_read_ahead` is useful in DTLS, GmSSL does not support read ahead
long GM_SSL_CTX_set_read_ahead(GM_SSL_CTX *ctx, int yes)
{
	return 1; // How about return 0	?			
}

void GM_SSL_CTX_set_verify(GM_SSL_CTX *ctx, int mode, GM_SSL_verify_cb verify_callback)
{
}

void GM_SSL_set_verify(SSL *ssl, int mode, GM_SSL_verify_cb verify_callback)
{
}

void GM_SSL_CTX_set_verify_depth(GM_SSL_CTX *ctx, int depth)
{
}

void GM_SSL_set_verify_depth(SSL *ssl, int depth)
{
}

int GM_SSL_CTX_load_verify_locations(GM_SSL_CTX *ctx, const char *CAfile, const char *CApath)
{
	int verify_depth = 4;
	gm_tls_ctx_set_ca_certificates(ctx, CAfile, verify_depth);
	return 1;
}

STACK_OF(GM_X509_NAME) *GM_SSL_load_client_CA_file(const char *file)
{
	return (STACK_OF(GM_X509_NAME) *)"Not implemented";
}

void GM_SSL_CTX_set_client_CA_list(GM_SSL_CTX *ctx, STACK_OF(GM_X509_NAME) *list)
{
}

// Nginx use `GM_SSL_get1_peer_certificate` to get client_verify certificate
// `GM_SSL_get1_peer_certificate` works fine when caller is the server.
// But if the caller is the client, `GM_SSL_get1_peer_certificate` only returns the signing cert
GM_X509 *GM_SSL_get1_peer_certificate(const SSL *ssl)
{
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *cert;
	size_t certlen;
	GM_X509 *x509;

	if (ssl->is_client) {
		certs = ssl->server_certs;
		certslen = ssl->server_certs_len;
	} else {
		certs = ssl->client_certs;
		certslen = ssl->client_certs_len;
	}

	if (gm_x509_cert_from_der(&cert, &certlen, &certs, &certslen) != 1) {
		gm_error_print();
		return NULL;
	}
	if (certlen > GM_X509_MAX_SIZE) {
		gm_error_print();
		return NULL;
	}
	if (!(x509 = GM_X509_new())) {
		gm_error_print();
		return NULL;
	}

	memcpy(x509->d, cert, certlen);
	x509->dlen = certlen;
	return x509;
}

// Sometimes even is handshake is success, `GM_SSL_get_verify_result` still return error for some reasons
// 	* GM_SSL_CTX_set_verify use `GM_SSL_VERIFY_NONE`
//	* The server hostname does not match the certificate subject
// In Ngnix, `GM_SSL_get_verify_result` is typically used with client_verify, so we assume GmSSL will handle
// all the verification. We assume that is handshake is ok, verify result is ok
long GM_SSL_get_verify_result(const SSL *ssl)
{
	return GM_X509_V_OK;
}

const char *GM_X509_verify_cert_error_string(long n)
{
	if (n) {
		return "error";
	} else {
		return "ok";
	}
}

// TODO: gm_sk_X509_NAME_new, push ... have not been implemented yet!
STACK_OF(GM_X509_NAME) *GM_SSL_CTX_get_client_CA_list(const GM_SSL_CTX *ctx)
{
	if (!ctx) {
		gm_error_print();
		return NULL;
	}

	// TODO: parse ctx->cacerts, ctx->cacertslen to parse every CA certs
	// and then get subject, and push into STACK_OF(GM_X509_NAME)

	return NULL;
}

// GmSSL 3.1 always verify peer's certificate
int GM_SSL_CTX_get_verify_mode(const GM_SSL_CTX *ctx)
{
	return GM_SSL_VERIFY_PEER;
}

const GM_SSL_METHOD *SSLv23_method(void)
{
	return NULL;
}

GM_SSL_CTX *GM_SSL_CTX_new(const GM_SSL_METHOD *method)
{
	GM_TLS_CTX *ctx;
	const int is_client = 0;

	if (!(ctx = (GM_TLS_CTX *)malloc(sizeof(GM_TLS_CTX)))) {
		gm_error_print();
		return NULL;
	}

	if (gm_tls_ctx_init(ctx, GM_TLS_protocol_tlcp, is_client) != 1) {
		gm_error_print();
		free(ctx); // try do free  			
		return NULL;
	}

	return ctx;
}

void GM_SSL_CTX_free(GM_SSL_CTX *ctx)
{
	if (ctx) {
		gmssl_secure_clear(ctx, sizeof(*ctx));
		free(ctx);				
	}
}

int GM_SSL_CTX_use_certificate(GM_SSL_CTX *ctx, GM_X509 *x509)
{
	if (ctx->certs) {
		free(ctx->certs);			
	}
	if (!(ctx->certs = (uint8_t *)malloc(x509->dlen))) {
		gm_error_print();
		return 0;
	}
	memcpy(ctx->certs, x509->d, x509->dlen);
	ctx->certslen = x509->dlen;
	return 1;
}

// `GM_SSL_CTX_set0_chain` is a macro of `GM_SSL_CTX_ctrl` in OpenSSL
int _GM_SSL_CTX_set0_chain(GM_SSL_CTX *ctx, STACK_OF(GM_X509) *sk)
{
	size_t total_len = ctx->certslen;
	int i;

	if (!ctx || !sk) {
		gm_error_print();
		return 0;
	}

	for (i = 0; i < sk->top; i++) {
		total_len += sk->values[i].dlen;
	}

	if (!(ctx->certs = realloc(ctx->certs, total_len))) {
		gm_error_print();
		return 0;
	}

	for (i = 0; i < sk->top; i++) {
		memcpy(ctx->certs + ctx->certslen, sk->values[i].d, sk->values[i].dlen);
		ctx->certslen += sk->values[i].dlen;
	}

	return 1;
}

int GM_SSL_CTX_use_PrivateKey(GM_SSL_CTX *ctx, GM_EVP_PKEY *pkey)
{
	if (!ctx || !pkey) {
		gm_error_print();
		return 0;
	}
	ctx->signkey = pkey->signkey;
	ctx->kenckey = pkey->kenckey;
	return 1;
}

// `GM_SSL_CTX_set1_group_list` is a macro os `GM_SSL_CTX_ctrl` in OpenSSL
int _GM_SSL_CTX_set1_group_list(GM_SSL_CTX *ctx, char *list)
{
	if (strcmp(list, "sm2p256v1") != 0) {
		gm_error_print();
		return 0;
	}
	return 1;
}

// `GM_SSL_CTX_set_tmp_dh` is a macro os `GM_SSL_CTX_ctrl` in OpenSSL
long _GM_SSL_CTX_set_tmp_dh(GM_SSL_CTX *ctx, GM_DH *dh)
{
	return 0;
}

int GM_SSL_CTX_set0_tmp_dh_pkey(GM_SSL_CTX *ctx, GM_EVP_PKEY *dhpkey)
{
	return 0;
}

// OpenSSL use `GM_X509_STORE` as the database of CA certificates
GM_X509_STORE *GM_SSL_CTX_get_cert_store(const GM_SSL_CTX *ctx)
{
	return NULL;
}

int GM_SSL_CTX_get_ex_new_index(long argl, void *argp,
	GM_CRYPTO_EX_new *new_func,
	GM_CRYPTO_EX_dup *dup_func,
	GM_CRYPTO_EX_free *free_func)
{
	return 1;
}

int GM_SSL_CTX_set_ex_data(GM_SSL_CTX *ctx, int idx, void *arg)
{
	return 1;
}

void *GM_SSL_CTX_get_ex_data(const GM_SSL_CTX *d, int idx)
{
	return NULL;
}

long _GM_SSL_CTX_set_session_cache_mode(GM_SSL_CTX *ctx, long mode)
{
	return 0;
}

int GM_SSL_CTX_set_session_id_context(GM_SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
	return 1;
}

void GM_SSL_CTX_sess_set_new_cb(GM_SSL_CTX *ctx, int (*new_session_cb)(SSL *, GM_SSL_SESSION *))
{
}

long _GM_SSL_CTX_sess_set_cache_size(GM_SSL_CTX *ctx, long t)
{
	return 1;
}

int GM_SSL_CTX_remove_session(GM_SSL_CTX *ctx, GM_SSL_SESSION *c)
{
	return 1;
}

void GM_SSL_CTX_sess_set_get_cb(GM_SSL_CTX *ctx,
	GM_SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *))
{
}

void GM_SSL_CTX_sess_set_remove_cb(GM_SSL_CTX *ctx,
	void (*remove_session_cb)(GM_SSL_CTX *ctx, GM_SSL_SESSION *))
{
}

int GM_SSL_session_reused(const SSL *ssl)
{
	return 0;
}

int GM_SSL_set_session(SSL *ssl, GM_SSL_SESSION *session)
{
	return 1;
}

GM_SSL_SESSION *GM_SSL_get1_session(SSL *ssl)
{
	return NULL;
}

GM_SSL_SESSION *GM_SSL_get0_session(const SSL *ssl)
{
	return NULL;
}

void GM_SSL_SESSION_free(GM_SSL_SESSION *session)
{
	if (session) {
		free(session);
	}
}

const unsigned char *GM_SSL_SESSION_get_id(const GM_SSL_SESSION *s, unsigned int *len)
{
	return NULL;
}

int i2d_GM_SSL_SESSION(GM_SSL_SESSION *in, unsigned char **pp)
{
	return 0;
}

GM_SSL_SESSION *d2i_GM_SSL_SESSION(GM_SSL_SESSION **a, const unsigned char **pp, long length)
{
	return NULL;
}

SSL *GM_SSL_new(GM_SSL_CTX *ctx)
{
	SSL *ssl;

	if (!(ssl = (SSL *)malloc(sizeof(*ssl)))) {
		gm_error_print();
		return NULL;
	}
	if (gm_tls_init(ssl, ctx) != 1) {
		gm_error_print();
		free(ssl); //FIXME 			
		return NULL;
	}
	return ssl;
}

void GM_SSL_free(SSL *ssl)
{
	if (ssl) {
		gmssl_secure_clear(ssl, sizeof(*ssl));
		free(ssl);//FIXME			
	}
}

int GM_SSL_is_server(const SSL *ssl)
{
	if (ssl->is_client) {
		return 0;
	} else {
		return 1;
	}
}

const char *GM_SSL_get_version(const SSL *ssl)
{
	if (!ssl) {
		gm_error_print();
		return NULL;
	}
	return gm_tls_protocol_name(ssl->protocol);
}

const char *GM_SSL_get_cipher_name(const SSL *ssl)
{
	if (!ssl) {
		gm_error_print();
		return NULL;
	}
	return gm_tls_cipher_suite_name(ssl->cipher_suite);
}

char *GM_SSL_get_shared_ciphers(const SSL *ssl, char *buf, int buflen)
{
	if (!ssl) {
		gm_error_print();
		return NULL;
	}
	strncpy(buf, gm_tls_cipher_suite_name(GM_TLS_cipher_ecdhe_gm_sm4_cbc_sm3), buflen);
	return buf;
}

void GM_SSL_set_connect_state(SSL *ssl)
{
	ssl->is_client = 1;
}

void GM_SSL_set_accept_state(SSL *ssl)
{
	ssl->is_client = 0;
}

int GM_SSL_set_fd(SSL *ssl, int fd)
{
	int opts;

	if (gm_tls_set_socket(ssl, fd) != 1) {
		gm_error_print();
		return 0;
	}

	opts = fcntl(ssl->sock, F_GETFL, 0);
	opts &= ~O_NONBLOCK;
	fcntl(ssl->sock, F_SETFL, opts);

	return 1;
}

int GM_SSL_do_handshake(SSL *ssl)
{
	int opts;

	if (gm_tls_do_handshake(ssl) != 1) {
		gm_error_print();
		return 0;
	}

	opts = fcntl(ssl->sock, F_GETFL, 0);
	opts |= O_NONBLOCK;
	fcntl(ssl->sock, F_SETFL, opts);

	return 1;
}

int GM_SSL_read(SSL *ssl, void *buf, int num)
{
	int ret;
	size_t outlen;

	ret = gm_tls_recv(ssl, buf, num, &outlen);
	if (ret > 0) {
		return (int)outlen;
	} else if (ret == -EAGAIN) {
		return -2;
	} else {
		return ret;
	}
}

int GM_SSL_write(SSL *ssl, const void *buf, int num)
{
	int ret;
	size_t outlen;

	ret = gm_tls_send(ssl, buf, num, &outlen);

	if (ret > 0) {
		return (int)outlen;
	} else if (ret == -EAGAIN) {
		return -3;
	} else {
		return ret;
	}
}

int GM_SSL_in_init(const SSL *ssl)
{
	return 0;
}

void GM_SSL_set_quiet_shutdown(SSL *ssl, int mode)
{
}

void GM_SSL_set_shutdown(SSL *ssl, int mode)
{
}

int GM_SSL_get_ex_data_GM_X509_STORE_CTX_idx(void)
{
	return 0;
}

// OpenSSL return GM_SSL_SENT_SHUTDOWN, GM_SSL_RECEIVED_SHUTDOWN
int GM_SSL_get_shutdown(const SSL *ssl)
{
	return 1;
}

int GM_SSL_shutdown(SSL *ssl)
{
	// when client Ctrl+c close connections, the socket is closed, so server shutdown will not return 1
	if (gm_tls_shutdown(ssl) != 1) {
		gm_error_print();
		return 0;
	}
	return 1;
}

int GM_SSL_get_ex_new_index(long argl, void *argp,
	GM_CRYPTO_EX_new *new_func,
	GM_CRYPTO_EX_dup *dup_func,
	GM_CRYPTO_EX_free *free_func)
{
	return 1;
}

int GM_SSL_set_ex_data(SSL *ssl, int idx, void *arg)
{
	return 1;
}

void *GM_SSL_get_ex_data(const SSL *ssl, int idx)
{
	return NULL;
}

int GM_SSL_get_error(const SSL *ssl, int ret)
{
	switch (ret) {
	case -2: return GM_SSL_ERROR_WANT_READ;
	case -3: return GM_SSL_ERROR_WANT_WRITE;
	}
	return GM_SSL_ERROR_NONE;
}

void GM_SSL_CTX_set_info_callback(GM_SSL_CTX *ctx,
	void (*callback) (const SSL *ssl, int type, int val))
{
}

GM_BIO *GM_SSL_get_rbio(const SSL *ssl)
{
	return NULL;
}

GM_BIO *GM_SSL_get_wbio(const SSL *ssl)
{
	return NULL;
}

long GM_BIO_set_write_buffer_size(GM_BIO *bio, long size)
{
	return 1;
}

const GM_SSL_CIPHER *GM_SSL_get_current_cipher(const SSL *ssl)
{
	return NULL;
}

char *GM_SSL_CIPHER_description(const GM_SSL_CIPHER *cipher, char *buf, int size)
{
	return "GM_SSL_CIPHER_description()";
}

int GM_SSL_use_certificate(SSL *ssl, GM_X509 *x509)
{
	return 1;
}

int GM_SSL_use_PrivateKey(SSL *ssl, GM_EVP_PKEY *pkey)
{
	return 1;
}

int GM_SSL_set0_chain(SSL *ssl, STACK_OF(GM_X509) *sk)
{
	return 1;
}
