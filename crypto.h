/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The OpenSSL wrappers for userspace
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

#define libcrypto_error() \
    do { \
        fprintf(stderr, "Libcrypto error %s at %s, line %d in function %s\n", \
                ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE); \
    } while (0)

#define checkCryptoAPICall(pred) \
    do { \
        if ((pred) != 1) { \
            libcrypto_error(); \
        } \
    } while (0)

#define nullCheckCryptoAPICall(pred) \
    do { \
        if ((pred) == NULL) { \
            libcrypto_error(); \
        } \
    } while (0)

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* aad, const size_t aad_len);
unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
        const unsigned char* aad, const size_t aad_len);

void init_openssl(void);
void cleanup_openssl(void);
SSL_CTX* create_context(void);
void configure_context(SSL_CTX* ctx);
