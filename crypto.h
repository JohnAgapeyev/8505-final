/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The OpenSSL wrappers for userspace
 */

#include <openssl/ssl.h>

#include "shared.h"

void init_openssl(void);
void cleanup_openssl(void);
SSL_CTX* create_context(void);
void configure_context(SSL_CTX* ctx);
