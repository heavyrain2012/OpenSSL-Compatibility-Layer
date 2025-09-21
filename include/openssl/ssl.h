/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GM_OPENGM_SSL_GM_SSL_H
#define GM_OPENGM_SSL_GM_SSL_H

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/dh.h>
#include <openssl/pem.h>

#include <gmssl/tls.h>

#ifdef __cplusplus
extern "C" {
#endif


int GM_OPENGM_SSL_init_ssl(uint64_t opts, const GM_OPENGM_SSL_INIT_SETTINGS *settings);


typedef void GM_SSL_METHOD;

const GM_SSL_METHOD *SSLv23_method(void);


typedef GM_TLS_CTX		GM_SSL_CTX;
typedef GM_TLS_CONNECT	SSL;

// init GM_TLS_CTX as 'server' by default
GM_SSL_CTX *GM_SSL_CTX_new(const GM_SSL_METHOD *method);
void GM_SSL_CTX_free(GM_SSL_CTX *ctx);

int GM_SSL_CTX_use_certificate(GM_SSL_CTX *ctx, GM_X509 *x509);


int _GM_SSL_CTX_set0_chain(GM_SSL_CTX *ctx, STACK_OF(GM_X509) *sk);
#define GM_SSL_CTX_set0_chain(ctx,sk) _GM_SSL_CTX_set0_chain(ctx,sk)


int GM_SSL_CTX_use_PrivateKey(GM_SSL_CTX *ctx, GM_EVP_PKEY *pkey);
long GM_SSL_CTX_get_timeout(GM_SSL_CTX *ctx);

// the origina `GM_SSL_CTX_set1_group_list` is a macro of `GM_SSL_CTX_ctrl`
int _GM_SSL_CTX_set1_group_list(GM_SSL_CTX *ctx, char *list);
#define GM_SSL_CTX_set1_curves_list(ctx,list) GM_SSL_CTX_set1_group_list(ctx,list)
#define GM_SSL_CTX_set1_group_list(ctx,list) _GM_SSL_CTX_set1_group_list(ctx,list)



// called by ngx_ssl_session_id_context
STACK_OF(GM_X509_NAME) *GM_SSL_CTX_get_client_CA_list(const GM_SSL_CTX *ctx);


// nginx-1.18
long _GM_SSL_CTX_set_tmp_dh(GM_SSL_CTX *ctx, GM_DH *dh);
#define GM_SSL_CTX_set_tmp_dh(ctx,dh) _GM_SSL_CTX_set_tmp_dh(ctx,dh)


int GM_SSL_CTX_set0_tmp_dh_pkey(GM_SSL_CTX *ctx, GM_EVP_PKEY *pkey); // function


int  GM_SSL_CTX_get_ex_new_index(long argl, void *argp, GM_CRYPTO_EX_new *new_func, GM_CRYPTO_EX_dup *dup_func, GM_CRYPTO_EX_free *free_func);
int  GM_SSL_CTX_set_ex_data(GM_SSL_CTX *ctx, int idx, void *arg);
void *GM_SSL_CTX_get_ex_data(const GM_SSL_CTX *d, int idx);


typedef int GM_SSL_SESSION;

#define GM_SSL_SESS_CACHE_OFF			0x0000
#define GM_SSL_SESS_CACHE_CLIENT			0x0001
#define GM_SSL_SESS_CACHE_SERVER			0x0002
#define GM_SSL_SESS_CACHE_BOTH			(GM_SSL_SESS_CACHE_CLIENT|GM_SSL_SESS_CACHE_SERVER)
#define GM_SSL_SESS_CACHE_NO_AUTO_CLEAR		0x0080
#define GM_SSL_SESS_CACHE_NO_INTERNAL_LOOKUP	0x0100
#define GM_SSL_SESS_CACHE_NO_INTERNAL_STORE	0x0200
#define GM_SSL_SESS_CACHE_NO_INTERNAL		(GM_SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|GM_SSL_SESS_CACHE_NO_INTERNAL_STORE)
#define GM_SSL_SESS_CACHE_UPDATE_TIME		0x0400


int GM_SSL_set_session(SSL *ssl, GM_SSL_SESSION *session);
int GM_SSL_session_reused(const SSL *ssl);
GM_SSL_SESSION *GM_SSL_get1_session(SSL *ssl);
GM_SSL_SESSION *GM_SSL_get0_session(const SSL *ssl);


void GM_SSL_SESSION_free(GM_SSL_SESSION *session);
const unsigned char *GM_SSL_SESSION_get_id(const GM_SSL_SESSION *s, unsigned int *len);
int i2d_GM_SSL_SESSION(GM_SSL_SESSION *in, unsigned char **pp);
GM_SSL_SESSION *d2i_GM_SSL_SESSION(GM_SSL_SESSION **a, const unsigned char **pp, long length);




#define GM_SSL_SENT_SHUTDOWN 2
#define GM_SSL_RECEIVED_SHUTDOWN 1
#define GM_SSL_CB_ACCEPT_LOOP 1



SSL *GM_SSL_new(GM_SSL_CTX *ctx);
void GM_SSL_free(SSL *ssl);
int  GM_SSL_is_server(const SSL *ssl);
const char *GM_SSL_get_version(const SSL *ssl);
const char *GM_SSL_get_cipher_name(const SSL *s);
char *GM_SSL_get_shared_ciphers(const SSL *s, char *buf, int size);
void GM_SSL_set_connect_state(SSL *ssl);
void GM_SSL_set_accept_state(SSL *ssl);
int  GM_SSL_set_fd(SSL *ssl, int fd);
int  GM_SSL_do_handshake(SSL *ssl);
int  GM_SSL_read(SSL *ssl, void *buf, int num);
int  GM_SSL_write(SSL *ssl, const void *buf, int num);
int  GM_SSL_in_init(const SSL *ssl);
void GM_SSL_set_quiet_shutdown(SSL *ssl, int mode);
void GM_SSL_set_shutdown(SSL *ssl, int mode);
int  GM_SSL_get_shutdown(const SSL *ssl);
int  GM_SSL_shutdown(SSL *ssl);
int  GM_SSL_get_error(const SSL *ssl, int ret);

int GM_SSL_get_ex_new_index(long argl, void *argp,
	GM_CRYPTO_EX_new *new_func,
	GM_CRYPTO_EX_dup *dup_func,
	GM_CRYPTO_EX_free *free_func);
int GM_SSL_set_ex_data(SSL *ssl, int idx, void *arg);
void *GM_SSL_get_ex_data(const SSL *ssl, int idx);



# define GM_SSL_ERROR_NONE                  0
# define GM_SSL_ERROR_SSL                   1
# define GM_SSL_ERROR_WANT_READ             2
# define GM_SSL_ERROR_WANT_WRITE            3
# define GM_SSL_ERROR_WANT_GM_X509_LOOKUP      4
# define GM_SSL_ERROR_SYSCALL               5
# define GM_SSL_ERROR_ZERO_RETURN           6
# define GM_SSL_ERROR_WANT_CONNECT          7
# define GM_SSL_ERROR_WANT_ACCEPT           8
# define GM_SSL_ERROR_WANT_ASYNC            9
# define GM_SSL_ERROR_WANT_ASYNC_JOB       10
# define GM_SSL_ERROR_WANT_CLIENT_HELLO_CB 11
# define GM_SSL_ERROR_WANT_RETRY_VERIFY    12


long _GM_SSL_CTX_set_session_cache_mode(GM_SSL_CTX *ctx, long mode);
#define GM_SSL_CTX_set_session_cache_mode(ctx,mode) _GM_SSL_CTX_set_session_cache_mode(ctx,mode)
int  GM_SSL_CTX_set_session_id_context(GM_SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len); // func
void GM_SSL_CTX_sess_set_new_cb(GM_SSL_CTX *ctx, int (*new_session_cb)(SSL *, GM_SSL_SESSION *)); // func
void GM_SSL_CTX_sess_set_get_cb(GM_SSL_CTX *ctx, GM_SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *));
void GM_SSL_CTX_sess_set_remove_cb(GM_SSL_CTX *ctx, void (*remove_session_cb)(GM_SSL_CTX *ctx, GM_SSL_SESSION *));

long _GM_SSL_CTX_sess_set_cache_size(GM_SSL_CTX *ctx, long t);
#define GM_SSL_CTX_sess_set_cache_size(ctx,t) _GM_SSL_CTX_sess_set_cache_size(ctx,t)


int GM_SSL_CTX_remove_session(GM_SSL_CTX *ctx, GM_SSL_SESSION *c);


// Nginx use `GM_SSL_CTX_set_info_callback` to change the SSL handshake buffer size
// Nginx use GM_SSL_get_rbio(ssl) != GM_SSL_get_wbio(ssl) to check if current state is handshake
// But GmSSL does not use FILE as SSL/TLS bio, nor GmSSL support caller-defined buffer size
// So `GM_SSL_CTX_set_info_callback` and `GM_BIO_set_write_buffer_size` will do nothing
// `GM_SSL_get_rbio` and `GM_SSL_get_wbio` will return NULL
void GM_SSL_CTX_set_info_callback(GM_SSL_CTX *ctx,
	void (*callback) (const SSL *ssl, int type, int val));
GM_BIO *GM_SSL_get_rbio(const SSL *ssl);
GM_BIO *GM_SSL_get_wbio(const SSL *ssl);
long GM_BIO_set_write_buffer_size(GM_BIO *bio, long size);


typedef void GM_SSL_CIPHER;

const GM_SSL_CIPHER *GM_SSL_get_current_cipher(const SSL *ssl);
char *GM_SSL_CIPHER_description(const GM_SSL_CIPHER *cipher, char *buf, int size);





long GM_SSL_CTX_set_timeout(GM_SSL_CTX *ctx, long timeout_seconds);
int GM_SSL_CTX_set_cipher_list(GM_SSL_CTX *ctx, const char *str);


// GmSSL OCL does not support options, only some GM_SSL_OP_ options are listed here to make compile success
#define GM_SSL_OP_NO_COMPRESSION	1
#define GM_SSL_OP_NO_RENEGOTIATION	1

#define GM_SSL_OP_SINGLE_GM_DH_USE	1
#define GM_SSL_OP_SINGLE_ECGM_DH_USE	1

#define GM_SSL_OP_NO_SSLv2		1
#define GM_SSL_OP_NO_SSLv3		1
#define GM_SSL_OP_NO_TLSv1		1
#define GM_SSL_OP_NO_SSLv2		1
#define GM_SSL_OP_NO_SSLv3		1
#define GM_SSL_OP_NO_TLSv1		1

#define GM_SSL_OP_CIPHER_SERVER_PREFERENCE 1


uint64_t GM_SSL_CTX_set_options(GM_SSL_CTX *ctx, uint64_t options);
uint64_t GM_SSL_CTX_clear_options(GM_SSL_CTX *ctx, uint64_t options);
uint64_t GM_SSL_set_options(SSL *ssl, uint64_t options);
uint64_t GM_SSL_clear_options(SSL *ssl, uint64_t options);

long GM_SSL_CTX_set_mode(GM_SSL_CTX *ctx, long mode);
int GM_SSL_CTX_set_min_proto_version(GM_SSL_CTX *ctx, int version);
int GM_SSL_CTX_set_max_proto_version(GM_SSL_CTX *ctx, int version);
void GM_SSL_CTX_set_cert_cb(GM_SSL_CTX *c, int (*cert_cb)(SSL *ssl, void *arg), void *arg);

long GM_SSL_CTX_set_read_ahead(GM_SSL_CTX *ctx, int yes);


// client verify CA
void GM_SSL_CTX_set_verify_depth(GM_SSL_CTX *ctx, int depth);
int GM_SSL_CTX_load_verify_locations(GM_SSL_CTX *ctx, const char *CAfile, const char *CApath);
STACK_OF(GM_X509_NAME) *GM_SSL_load_client_CA_file(const char *file);
void GM_SSL_CTX_set_client_CA_list(GM_SSL_CTX *ctx, STACK_OF(GM_X509_NAME) *list);


GM_X509 *GM_SSL_get1_peer_certificate(const SSL *ssl);
#define GM_SSL_get_peer_certificate(ssl) GM_SSL_get1_peer_certificate(ssl)


long GM_SSL_get_verify_result(const SSL *ssl);



# define GM_SSL_VERIFY_NONE                 0x00
# define GM_SSL_VERIFY_PEER                 0x01
# define GM_SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
# define GM_SSL_VERIFY_CLIENT_ONCE          0x04
# define GM_SSL_VERIFY_POST_HANDSHAKE       0x08

int GM_SSL_get_ex_data_GM_X509_STORE_CTX_idx(void);



typedef int (*GM_SSL_verify_cb)(int preverify_ok, GM_X509_STORE_CTX *x509_ctx);

void GM_SSL_CTX_set_verify(GM_SSL_CTX *ctx, int mode, GM_SSL_verify_cb verify_callback);
int GM_SSL_CTX_get_verify_mode(const GM_SSL_CTX *ctx);

GM_X509_STORE *GM_SSL_CTX_get_cert_store(const GM_SSL_CTX *ctx);


#undef GM_SSL_R_CERT_CB_ERROR

int GM_SSL_use_certificate(SSL *ssl, GM_X509 *x509);
int GM_SSL_use_PrivateKey(SSL *ssl, GM_EVP_PKEY *pkey);
int GM_SSL_set0_chain(SSL *ssl, STACK_OF(GM_X509) *sk);


// from <openssl/sslerr.h>
# define GM_SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY        291
# define GM_SSL_R_APP_DATA_IN_HANDSHAKE                      100
# define GM_SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 272
# define GM_SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE     158
# define GM_SSL_R_BAD_CHANGE_CIPHER_SPEC                     103
# define GM_SSL_R_BAD_CIPHER                                 186
# define GM_SSL_R_BAD_DATA                                   390
# define GM_SSL_R_BAD_DATA_RETURNED_BY_CALLBACK              106
# define GM_SSL_R_BAD_DECOMPRESSION                          107
# define GM_SSL_R_BAD_GM_DH_VALUE                               102
# define GM_SSL_R_BAD_DIGEST_LENGTH                          111
# define GM_SSL_R_BAD_EARLY_DATA                             233
# define GM_SSL_R_BAD_ECC_CERT                               304
# define GM_SSL_R_BAD_ECPOINT                                306
# define GM_SSL_R_BAD_EXTENSION                              110
# define GM_SSL_R_BAD_HANDSHAKE_LENGTH                       332
# define GM_SSL_R_BAD_HANDSHAKE_STATE                        236
# define GM_SSL_R_BAD_HELLO_REQUEST                          105
# define GM_SSL_R_BAD_HRR_VERSION                            263
# define GM_SSL_R_BAD_KEY_SHARE                              108
# define GM_SSL_R_BAD_KEY_UPDATE                             122
# define GM_SSL_R_BAD_LEGACY_VERSION                         292
# define GM_SSL_R_BAD_LENGTH                                 271
# define GM_SSL_R_BAD_PACKET                                 240
# define GM_SSL_R_BAD_PACKET_LENGTH                          115
# define GM_SSL_R_BAD_PROTOCOL_VERSION_NUMBER                116
# define GM_SSL_R_BAD_PSK                                    219
# define GM_SSL_R_BAD_PSK_IDENTITY                           114
# define GM_SSL_R_BAD_RECORD_TYPE                            443
# define GM_SSL_R_BAD_RSA_ENCRYPT                            119
# define GM_SSL_R_BAD_SIGNATURE                              123
# define GM_SSL_R_BAD_SRP_A_LENGTH                           347
# define GM_SSL_R_BAD_SRP_PARAMETERS                         371
# define GM_SSL_R_BAD_SRTP_MKI_VALUE                         352
# define GM_SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST           353
# define GM_SSL_R_BAD_GM_SSL_FILETYPE                           124
# define GM_SSL_R_BAD_VALUE                                  384
# define GM_SSL_R_BAD_WRITE_RETRY                            127
# define GM_SSL_R_BINDER_DOES_NOT_VERIFY                     253
# define GM_SSL_R_GM_BIO_NOT_SET                                128
# define GM_SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  129
# define GM_SSL_R_BN_LIB                                     130
# define GM_SSL_R_CALLBACK_FAILED                            234
# define GM_SSL_R_CANNOT_CHANGE_CIPHER                       109
# define GM_SSL_R_CANNOT_GET_GROUP_NAME                      299
# define GM_SSL_R_CA_DN_LENGTH_MISMATCH                      131
# define GM_SSL_R_CA_KEY_TOO_SMALL                           397
# define GM_SSL_R_CA_MD_TOO_WEAK                             398
# define GM_SSL_R_CCS_RECEIVED_EARLY                         133
# define GM_SSL_R_CERTIFICATE_VERIFY_FAILED                  134
# define GM_SSL_R_CERT_CB_ERROR                              377
# define GM_SSL_R_CERT_LENGTH_MISMATCH                       135
# define GM_SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED             218
# define GM_SSL_R_CIPHER_CODE_WRONG_LENGTH                   137
# define GM_SSL_R_CLIENTHELLO_TLSEXT                         226
# define GM_SSL_R_COMPRESSED_LENGTH_TOO_LONG                 140
# define GM_SSL_R_COMPRESSION_DISABLED                       343
# define GM_SSL_R_COMPRESSION_FAILURE                        141
# define GM_SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE    307
# define GM_SSL_R_COMPRESSION_LIBRARY_ERROR                  142
# define GM_SSL_R_CONNECTION_TYPE_NOT_SET                    144
# define GM_SSL_R_CONTEXT_NOT_DANE_ENABLED                   167
# define GM_SSL_R_COOKIE_GEN_CALLBACK_FAILURE                400
# define GM_SSL_R_COOKIE_MISMATCH                            308
# define GM_SSL_R_COPY_PARAMETERS_FAILED                     296
# define GM_SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED       206
# define GM_SSL_R_DANE_ALREADY_ENABLED                       172
# define GM_SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL            173
# define GM_SSL_R_DANE_NOT_ENABLED                           175
# define GM_SSL_R_DANE_TLSA_BAD_CERTIFICATE                  180
# define GM_SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE            184
# define GM_SSL_R_DANE_TLSA_BAD_DATA_LENGTH                  189
# define GM_SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH                192
# define GM_SSL_R_DANE_TLSA_BAD_MATCHING_TYPE                200
# define GM_SSL_R_DANE_TLSA_BAD_PUBLIC_KEY                   201
# define GM_SSL_R_DANE_TLSA_BAD_SELECTOR                     202
# define GM_SSL_R_DANE_TLSA_NULL_DATA                        203
# define GM_SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              145
# define GM_SSL_R_DATA_LENGTH_TOO_LONG                       146
# define GM_SSL_R_DECRYPTION_FAILED                          147
# define GM_SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        281
# define GM_SSL_R_GM_DH_KEY_TOO_SMALL                           394
# define GM_SSL_R_GM_DH_PUBLIC_VALUE_LENGTH_IS_WRONG            148
# define GM_SSL_R_DIGEST_CHECK_FAILED                        149
# define GM_SSL_R_DTLS_MESSAGE_TOO_BIG                       334
# define GM_SSL_R_DUPLICATE_COMPRESSION_ID                   309
# define GM_SSL_R_ECC_CERT_NOT_FOR_SIGNING                   318
# define GM_SSL_R_ECGM_DH_REQUIRED_FOR_SUITEB_MODE              374
# define GM_SSL_R_EE_KEY_TOO_SMALL                           399
# define GM_SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST         354
# define GM_SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  150
# define GM_SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              151
# define GM_SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN             204
# define GM_SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE                  194
# define GM_SSL_R_EXCESSIVE_MESSAGE_SIZE                     152
# define GM_SSL_R_EXTENSION_NOT_RECEIVED                     279
# define GM_SSL_R_EXTRA_DATA_IN_MESSAGE                      153
# define GM_SSL_R_EXT_LENGTH_MISMATCH                        163
# define GM_SSL_R_FAILED_TO_INIT_ASYNC                       405
# define GM_SSL_R_FRAGMENTED_CLIENT_HELLO                    401
# define GM_SSL_R_GOT_A_FIN_BEFORE_A_CCS                     154
# define GM_SSL_R_HTTPS_PROXY_REQUEST                        155
# define GM_SSL_R_HTTP_REQUEST                               156
# define GM_SSL_R_ILLEGAL_POINT_COMPRESSION                  162
# define GM_SSL_R_ILLEGAL_SUITEB_DIGEST                      380
# define GM_SSL_R_INAPPROPRIATE_FALLBACK                     373
# define GM_SSL_R_INCONSISTENT_COMPRESSION                   340
# define GM_SSL_R_INCONSISTENT_EARLY_DATA_ALPN               222
# define GM_SSL_R_INCONSISTENT_EARLY_DATA_SNI                231
# define GM_SSL_R_INCONSISTENT_EXTMS                         104
# define GM_SSL_R_INSUFFICIENT_SECURITY                      241
# define GM_SSL_R_INVALID_ALERT                              205
# define GM_SSL_R_INVALID_CCS_MESSAGE                        260
# define GM_SSL_R_INVALID_CERTIFICATE_OR_ALG                 238
# define GM_SSL_R_INVALID_COMMAND                            280
# define GM_SSL_R_INVALID_COMPRESSION_ALGORITHM              341
# define GM_SSL_R_INVALID_CONFIG                             283
# define GM_SSL_R_INVALID_CONFIGURATION_NAME                 113
# define GM_SSL_R_INVALID_CONTEXT                            282
# define GM_SSL_R_INVALID_CT_VALIDATION_TYPE                 212
# define GM_SSL_R_INVALID_KEY_UPDATE_TYPE                    120
# define GM_SSL_R_INVALID_MAX_EARLY_DATA                     174
# define GM_SSL_R_INVALID_NULL_CMD_NAME                      385
# define GM_SSL_R_INVALID_SEQUENCE_NUMBER                    402
# define GM_SSL_R_INVALID_SERVERINFO_DATA                    388
# define GM_SSL_R_INVALID_SESSION_ID                         999
# define GM_SSL_R_INVALID_SRP_USERNAME                       357
# define GM_SSL_R_INVALID_STATUS_RESPONSE                    328
# define GM_SSL_R_INVALID_TICKET_KEYS_LENGTH                 325
# define GM_SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED    333
# define GM_SSL_R_LENGTH_MISMATCH                            159
# define GM_SSL_R_LENGTH_TOO_LONG                            404
# define GM_SSL_R_LENGTH_TOO_SHORT                           160
# define GM_SSL_R_LIBRARY_BUG                                274
# define GM_SSL_R_LIBRARY_HAS_NO_CIPHERS                     161
# define GM_SSL_R_MISSING_DSA_SIGNING_CERT                   165
# define GM_SSL_R_MISSING_ECDSA_SIGNING_CERT                 381
# define GM_SSL_R_MISSING_FATAL                              256
# define GM_SSL_R_MISSING_PARAMETERS                         290
# define GM_SSL_R_MISSING_PSK_KEX_MODES_EXTENSION            310
# define GM_SSL_R_MISSING_RSA_CERTIFICATE                    168
# define GM_SSL_R_MISSING_RSA_ENCRYPTING_CERT                169
# define GM_SSL_R_MISSING_RSA_SIGNING_CERT                   170
# define GM_SSL_R_MISSING_SIGALGS_EXTENSION                  112
# define GM_SSL_R_MISSING_SIGNING_CERT                       221
# define GM_SSL_R_MISSING_SRP_PARAM                          358
# define GM_SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION         209
# define GM_SSL_R_MISSING_TMP_GM_DH_KEY                         171
# define GM_SSL_R_MISSING_TMP_ECGM_DH_KEY                       311
# define GM_SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA     293
# define GM_SSL_R_NOT_ON_RECORD_BOUNDARY                     182
# define GM_SSL_R_NOT_REPLACING_CERTIFICATE                  289
# define GM_SSL_R_NOT_SERVER                                 284
# define GM_SSL_R_NO_APPLICATION_PROTOCOL                    235
# define GM_SSL_R_NO_CERTIFICATES_RETURNED                   176
# define GM_SSL_R_NO_CERTIFICATE_ASSIGNED                    177
# define GM_SSL_R_NO_CERTIFICATE_SET                         179
# define GM_SSL_R_NO_CHANGE_FOLLOWING_HRR                    214
# define GM_SSL_R_NO_CIPHERS_AVAILABLE                       181
# define GM_SSL_R_NO_CIPHERS_SPECIFIED                       183
# define GM_SSL_R_NO_CIPHER_MATCH                            185
# define GM_SSL_R_NO_CLIENT_CERT_METHOD                      331
# define GM_SSL_R_NO_COMPRESSION_SPECIFIED                   187
# define GM_SSL_R_NO_COOKIE_CALLBACK_SET                     287
# define GM_SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER           330
# define GM_SSL_R_NO_METHOD_SPECIFIED                        188
# define GM_SSL_R_NO_GM_PEM_EXTENSIONS                          389
# define GM_SSL_R_NO_PRIVATE_KEY_ASSIGNED                    190
# define GM_SSL_R_NO_PROTOCOLS_AVAILABLE                     191
# define GM_SSL_R_NO_RENEGOTIATION                           339
# define GM_SSL_R_NO_REQUIRED_DIGEST                         324
# define GM_SSL_R_NO_SHARED_CIPHER                           193
# define GM_SSL_R_NO_SHARED_GROUPS                           410
# define GM_SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             376
# define GM_SSL_R_NO_SRTP_PROFILES                           359
# define GM_SSL_R_NO_SUITABLE_DIGEST_ALGORITHM               297
# define GM_SSL_R_NO_SUITABLE_GROUPS                         295
# define GM_SSL_R_NO_SUITABLE_KEY_SHARE                      101
# define GM_SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            118
# define GM_SSL_R_NO_VALID_SCTS                              216
# define GM_SSL_R_NO_VERIFY_COOKIE_CALLBACK                  403
# define GM_SSL_R_NULL_GM_SSL_CTX                               195
# define GM_SSL_R_NULL_GM_SSL_METHOD_PASSED                     196
# define GM_SSL_R_OCSP_CALLBACK_FAILURE                      305
# define GM_SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED            197
# define GM_SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 344
# define GM_SSL_R_OVERFLOW_ERROR                             237
# define GM_SSL_R_PACKET_LENGTH_TOO_LONG                     198
# define GM_SSL_R_PARSE_TLSEXT                               227
# define GM_SSL_R_PATH_TOO_LONG                              270
# define GM_SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE          199
# define GM_SSL_R_GM_PEM_NAME_BAD_PREFIX                        391
# define GM_SSL_R_GM_PEM_NAME_TOO_SHORT                         392
# define GM_SSL_R_PIPELINE_FAILURE                           406
# define GM_SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR           278
# define GM_SSL_R_PRIVATE_KEY_MISMATCH                       288
# define GM_SSL_R_PROTOCOL_IS_SHUTDOWN                       207
# define GM_SSL_R_PSK_IDENTITY_NOT_FOUND                     223
# define GM_SSL_R_PSK_NO_CLIENT_CB                           224
# define GM_SSL_R_PSK_NO_SERVER_CB                           225
# define GM_SSL_R_READ_GM_BIO_NOT_SET                           211
# define GM_SSL_R_READ_TIMEOUT_EXPIRED                       312
# define GM_SSL_R_RECORD_LENGTH_MISMATCH                     213
# define GM_SSL_R_RECORD_TOO_SMALL                           298
# define GM_SSL_R_RENEGOTIATE_EXT_TOO_LONG                   335
# define GM_SSL_R_RENEGOTIATION_ENCODING_ERR                 336
# define GM_SSL_R_RENEGOTIATION_MISMATCH                     337
# define GM_SSL_R_REQUEST_PENDING                            285
# define GM_SSL_R_REQUEST_SENT                               286
# define GM_SSL_R_REQUIRED_CIPHER_MISSING                    215
# define GM_SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING     342
# define GM_SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           345
# define GM_SSL_R_SCT_VERIFICATION_FAILED                    208
# define GM_SSL_R_SERVERHELLO_TLSEXT                         275
# define GM_SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED           277
# define GM_SSL_R_SHUTDOWN_WHILE_IN_INIT                     407
# define GM_SSL_R_SIGNATURE_ALGORITHMS_ERROR                 360
# define GM_SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE      220
# define GM_SSL_R_SRP_A_CALC                                 361
# define GM_SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES           362
# define GM_SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG      363
# define GM_SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE            364
# define GM_SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH       232
# define GM_SSL_R_SSL3_EXT_INVALID_SERVERNAME                319
# define GM_SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE           320
# define GM_SSL_R_SSL3_SESSION_ID_TOO_LONG                   300
# define GM_SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                1042
# define GM_SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 1020
# define GM_SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            1045
# define GM_SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            1044
# define GM_SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            1046
# define GM_SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          1030
# define GM_SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              1040
# define GM_SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              1047
# define GM_SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 1041
# define GM_SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             1010
# define GM_SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        1043
# define GM_SSL_R_GM_SSL_COMMAND_SECTION_EMPTY                  117
# define GM_SSL_R_GM_SSL_COMMAND_SECTION_NOT_FOUND              125
# define GM_SSL_R_GM_SSL_CTX_HAS_NO_DEFAULT_GM_SSL_VERSION         228
# define GM_SSL_R_GM_SSL_HANDSHAKE_FAILURE                      229
# define GM_SSL_R_GM_SSL_LIBRARY_HAS_NO_CIPHERS                 230
# define GM_SSL_R_GM_SSL_NEGATIVE_LENGTH                        372
# define GM_SSL_R_GM_SSL_SECTION_EMPTY                          126
# define GM_SSL_R_GM_SSL_SECTION_NOT_FOUND                      136
# define GM_SSL_R_GM_SSL_SESSION_ID_CALLBACK_FAILED             301
# define GM_SSL_R_GM_SSL_SESSION_ID_CONFLICT                    302
# define GM_SSL_R_GM_SSL_SESSION_ID_CONTEXT_TOO_LONG            273
# define GM_SSL_R_GM_SSL_SESSION_ID_HAS_BAD_LENGTH              303
# define GM_SSL_R_GM_SSL_SESSION_ID_TOO_LONG                    408
# define GM_SSL_R_GM_SSL_SESSION_VERSION_MISMATCH               210
# define GM_SSL_R_STILL_IN_INIT                              121
# define GM_SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED          1116
# define GM_SSL_R_TLSV13_ALERT_MISSING_EXTENSION             1109
# define GM_SSL_R_TLSV1_ALERT_ACCESS_DENIED                  1049
# define GM_SSL_R_TLSV1_ALERT_DECODE_ERROR                   1050
# define GM_SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              1021
# define GM_SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  1051
# define GM_SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             1060
# define GM_SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK         1086
# define GM_SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          1071
# define GM_SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 1080
# define GM_SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               1100
# define GM_SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               1070
# define GM_SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                1022
# define GM_SSL_R_TLSV1_ALERT_UNKNOWN_CA                     1048
# define GM_SSL_R_TLSV1_ALERT_USER_CANCELLED                 1090
# define GM_SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE           1114
# define GM_SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE      1113
# define GM_SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE             1111
# define GM_SSL_R_TLSV1_UNRECOGNIZED_NAME                    1112
# define GM_SSL_R_TLSV1_UNSUPPORTED_EXTENSION                1110
# define GM_SSL_R_TLS_ILLEGAL_EXPORTER_LABEL                 367
# define GM_SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST             157
# define GM_SSL_R_TOO_MANY_KEY_UPDATES                       132
# define GM_SSL_R_TOO_MANY_WARN_ALERTS                       409
# define GM_SSL_R_TOO_MUCH_EARLY_DATA                        164
# define GM_SSL_R_UNABLE_TO_FIND_ECGM_DH_PARAMETERS             314
# define GM_SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS       239
# define GM_SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES           242
# define GM_SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES          243
# define GM_SSL_R_UNEXPECTED_CCS_MESSAGE                     262
# define GM_SSL_R_UNEXPECTED_END_OF_EARLY_DATA               178
# define GM_SSL_R_UNEXPECTED_EOF_WHILE_READING               294
# define GM_SSL_R_UNEXPECTED_MESSAGE                         244
# define GM_SSL_R_UNEXPECTED_RECORD                          245
# define GM_SSL_R_UNINITIALIZED                              276
# define GM_SSL_R_UNKNOWN_ALERT_TYPE                         246
# define GM_SSL_R_UNKNOWN_CERTIFICATE_TYPE                   247
# define GM_SSL_R_UNKNOWN_CIPHER_RETURNED                    248
# define GM_SSL_R_UNKNOWN_CIPHER_TYPE                        249
# define GM_SSL_R_UNKNOWN_CMD_NAME                           386
# define GM_SSL_R_UNKNOWN_COMMAND                            139
# define GM_SSL_R_UNKNOWN_DIGEST                             368
# define GM_SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE                  250
# define GM_SSL_R_UNKNOWN_PKEY_TYPE                          251
# define GM_SSL_R_UNKNOWN_PROTOCOL                           252
# define GM_SSL_R_UNKNOWN_GM_SSL_VERSION                        254
# define GM_SSL_R_UNKNOWN_STATE                              255
# define GM_SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       338
# define GM_SSL_R_UNSOLICITED_EXTENSION                      217
# define GM_SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM          257
# define GM_SSL_R_UNSUPPORTED_ELLIPTIC_CURVE                 315
# define GM_SSL_R_UNSUPPORTED_PROTOCOL                       258
# define GM_SSL_R_UNSUPPORTED_GM_SSL_VERSION                    259
# define GM_SSL_R_UNSUPPORTED_STATUS_TYPE                    329
# define GM_SSL_R_USE_SRTP_NOT_NEGOTIATED                    369
# define GM_SSL_R_VERSION_TOO_HIGH                           166
# define GM_SSL_R_VERSION_TOO_LOW                            396
# define GM_SSL_R_WRONG_CERTIFICATE_TYPE                     383
# define GM_SSL_R_WRONG_CIPHER_RETURNED                      261
# define GM_SSL_R_WRONG_CURVE                                378
# define GM_SSL_R_WRONG_SIGNATURE_LENGTH                     264
# define GM_SSL_R_WRONG_SIGNATURE_SIZE                       265
# define GM_SSL_R_WRONG_SIGNATURE_TYPE                       370
# define GM_SSL_R_WRONG_GM_SSL_VERSION                          266
# define GM_SSL_R_WRONG_VERSION_NUMBER                       267
# define GM_SSL_R_GM_X509_LIB                                   268
# define GM_SSL_R_GM_X509_VERIFICATION_SETUP_PROBLEMS           269




#ifdef __cplusplus
}
#endif
#endif
