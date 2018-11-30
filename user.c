/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The OpenSSL wrappers for userspace
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "crypto.h"
#include "shared.h"

/*
 * function:
 *    init_openssl
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 */
void init_openssl(void) {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
}

/*
 * function:
 *    cleanup_openssl
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 */
void cleanup_openssl(void) {
    EVP_cleanup();
}

/*
 * function:
 *    create_context
 *
 * return:
 *    SSL_CTX *
 *
 * parameters:
 *    void
 *
 * notes:
 * Creates a generic TLS SSL context
 */
SSL_CTX* create_context(void) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/*
 * function:
 *    configure_context
 *
 * return:
 *    void
 *
 * parameters:
 *    SSL_CTX* ctx
 *
 * notes:
 * Tells the SSL context to use the testing cert and key
 */
void configure_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
